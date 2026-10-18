#!/usr/bin/env python3
"""Check public text, encoded payloads and Git blobs without printing matches.

An optional local-only denylist supplements generic checks. Never commit that
denylist: it contains original identifiers. Reports contain rule names and
relative paths only, never the matching source text.
"""
import argparse
import ast
import base64
import binascii
import ipaddress
import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_SUFFIXES = {".zip", ".gz", ".tar", ".7z", ".pdf", ".png", ".jpg", ".jpeg", ".onnx", ".pyc", ".db", ".sqlite", ".pfx", ".p12", ".key", ".pem"}
SKIP = {".git", "build", "__pycache__", ".venv", ".cache", "node_modules"}
RULES = {
    "private-key": re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "ssh-public-identity": re.compile(r"ssh-(?:ed25519|rsa)\s+[A-Za-z0-9+/]{60,}"),
    "registration-secret": re.compile(r"tskey-[a-z]+-[A-Za-z0-9]{12,}"),
    "github-token": re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})"),
    "aws-access-key": re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}(?![A-Z0-9])"),
    "service-token": re.compile(r"(?:AIza[A-Za-z0-9_-]{35}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,})"),
    "url-credentials": re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@'\"<>]+@[^\s'\"<>]+"),
    "windows-user-path": re.compile(r"[A-Za-z]:[\\/]Users[\\/](?!labuser(?:[\\/]|$)|Public(?:[\\/]|$)|\$|%)[A-Za-z0-9_.-]+", re.I),
    "linux-user-path": re.compile(r"/home/(?!labuser(?:/|$)|filebrowser(?:/|$)|\$|\{|<)[A-Za-z0-9_.-]+"),
    "machine-sid": re.compile(r"S-1-5-21-\d+-\d+-\d+(?:-\d+)?"),
    "credential-literal": re.compile(r'''(?im)(?:password|access_token|auth_token|private_key)\s*[:=]\s*["']([A-Za-z0-9+/=_-]{16,})["']'''),
}
CREDENTIAL = re.compile(r'''(?im)(?:^|[\{,;])[ \t]*(?:export[ \t]+|option[ \t]+)?["']?(?P<key>(?:[a-z0-9]+[_-])*(?:password|passwd|secret|secret_access_key|access_token|auth_token|api_token|api_key|private_key|privatekey))["']?[ \t]*(?:[:=]|(?<=key)[ \t])[ \t]*(?P<quote>["']?)(?P<value>[^\s"'`,;\]\)\(]+)''')
PLACEHOLDER = re.compile(r'(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$(?:env:)?[A-Za-z_][A-Za-z0-9_]*|\{\{[A-Z][A-Z0-9_]*\}\}|<[A-Z][A-Z0-9_]*>|%[A-Z][A-Z0-9_]*%)\Z')
HEX_PAYLOAD = re.compile(r"(?<![A-Za-z0-9])[0-9a-fA-F]{16,}(?![A-Za-z0-9])")
ESCAPE = re.compile(r'\\(?:x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|([0-7]{1,3}))')
STRING_LITERAL = r'''(?:"(?:[^"\\\r\n]|\\.)*"|'(?:[^'\\\r\n]|\\.)*')'''
STRING_CHAIN = re.compile(STRING_LITERAL + r'(?:\s*\+\s*' + STRING_LITERAL + r')+')
STRING_PART = re.compile(STRING_LITERAL)
MAX_PAYLOAD = 2_000_000
MAX_DEPTH = 6
MAX_CANDIDATES = 4096
MAX_DECODED_TOTAL = 16_000_000
# Exact non-secret negative-test values, restricted to their existing test paths.
CREDENTIAL_FIXTURES = {
    'infra/openwrt/wireguard/luci/backend/test_rpc.py': {'DO_NOT_EXPOSE'},
    'infra/pve/reference/router-ready/test_readiness.py': {'NEVER_REPORT_THIS'},
    'services/tests/test_service_contracts.py': {'synthetic-token-value', 'another-synthetic-token'},
}
URL_FIXTURES = {'tests/test_publication.py': {('https', 'user', 'hs.example.com')}}
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MAC = re.compile(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![0-9a-fA-F:])")
IPV6 = re.compile(r'(?<![A-Za-z0-9:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}(?![A-Za-z0-9:])')
ENCODED = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_-])")
SYNTHETIC_NETWORKS = tuple(map(ipaddress.ip_network, (
    "10.10.10.0/24", "10.10.20.0/24", "10.10.99.0/24", "10.200.0.0/30",
    "100.100.10.0/24", "172.28.40.0/28", "172.28.50.0/28", "172.28.60.0/28",
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8"
)))
# Protocol constants, public test resolvers and range endpoints, not site hosts.
PROTOCOL_IPS = {"0.0.0.0", "255.255.255.255", "100.64.0.0", "100.100.100.100",
                "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
                "255.255.255.0", "128.0.0.0", "224.0.0.1", "162.159.200.1",
                "10.0.0.0", "169.254.0.0", "172.16.0.0", "192.0.0.0",
                "192.168.0.0", "198.18.0.0", "224.0.0.0", "240.0.0.0"}
# Exact synthetic boundary fixtures; not allowed as arbitrary runtime endpoints.
FIXTURE_IPS = {
    'windows/review-coexist-offline.ps1': [(10,44,0,0), (10,45,0,0)],
    'windows/review-tablet-rdp-offline.ps1': [(100,100,11,n) for n in (41,42,43,44)] + [(100,127,255,255), (100,128,0,1), (100,63,255,254)],
    'infra/openwrt/wireguard/controller/test_controller.py': [(192,0,80,1)],
}
PROTOCOL_IPV6 = {'::', '::1', '8000::', 'ff00::', 'fe80::', 'fc00::', 'fd00::',
                 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
                 'fe80::1', 'fe80::2', 'fe80::99', 'fe80::100', 'fe80::200', 'fe80::300', 'fe80::1234', 'fe80::5678',
                 'ff02::1', 'ff02::2', '2001:4860:4860::8888', '2001:4860:4860::8844',
                 '2606:4700:4700::1111', '2606:4700:4700::1001'}
EXAMPLE_MACS = {'02:00:00:00:10:00', '02:00:00:00:10:01', '02:00:00:00:10:02',
                '02:00:00:00:00:01', '02:00:00:00:00:02', '02:00:00:00:00:09', '02:00:00:00:00:99',
                '02:00:00:00:10:03', '02:00:00:00:20:01', '02:00:00:00:30:01', '00:00:00:00:00:00'}


def numeric_payloads(text):
    """Decode byte/address literals without importing or executing source."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    values = []
    for node in ast.walk(tree):
        literal, explicit_bytes = None, False
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('bytes', 'bytearray') and len(node.args) == 1:
            try:
                candidate = ast.literal_eval(node.args[0])
                if isinstance(candidate, (list, tuple)) and len(candidate) in (4, 6, 16) and all(type(n) is int and 0 <= n <= 255 for n in candidate):
                    literal, explicit_bytes = bytes(candidate), True
            except (ValueError, TypeError, SyntaxError):
                pass
        elif isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            literal = node.value
            # Short text and file signatures are not addresses. Known original
            # identifiers are still checked below regardless of this heuristic.
            explicit_bytes = len(literal) == 4 and literal[0] in (10, 100, 172, 192)
        elif isinstance(node, (ast.List, ast.Tuple)):
            try:
                candidate = ast.literal_eval(node)
                if len(candidate) in (4, 6, 16) and all(type(n) is int and 0 <= n <= 255 for n in candidate):
                    literal = bytes(candidate)
            except (ValueError, TypeError, SyntaxError):
                pass
        elif isinstance(node, ast.Constant) and type(node.value) is int and 65536 <= node.value <= (2**32-1):
            literal = node.value.to_bytes(4, 'big')
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and re.fullmatch(r'(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{12}|[0-9a-fA-F]{32})', node.value):
            literal = bytes.fromhex(node.value)
        if literal is not None:
            if len(literal) == 4:
                values.append((str(ipaddress.IPv4Address(literal)), explicit_bytes))
            elif len(literal) == 6:
                values.append((':'.join(format(n, '02x') for n in literal), explicit_bytes))
            elif len(literal) == 16:
                values.append((str(ipaddress.IPv6Address(literal)), explicit_bytes))
    return values


def _check_plain(label, text, deny):
    issues = []
    lower = text.lower()
    if any(value.lower() in lower for value in deny if value):
        issues.append({"path": label, "rule": "private-denylist"})
    for name, pattern in RULES.items():
        if any(not (name == 'url-credentials' and _url_fixture(label, match[0])) for match in pattern.finditer(text)):
            issues.append({"path": label, "rule": name})
    for match in CREDENTIAL.finditer(text):
        value = match['value']
        if (len(value) >= 12 and value not in CREDENTIAL_FIXTURES.get(label.split(':', 1)[0], ())
                and not PLACEHOLDER.fullmatch(value)
                and value.lower() not in {'none', 'null', 'false', 'true', match['key'].lower()}
                and not (not match['quote'] and text[match.end():match.end()+1] == '(')):
            issues.append({'path': label, 'rule': 'credential-literal'})
    for match in IPV4.finditer(text):
        raw = match.group()
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue  # Four-part software versions are not network addresses.
        if re.search(r'(?:==|>=|<=|~=)\s*$', text[:match.start()]):
            continue  # Explicit package pin, not an address.
        fixture_values = {'.'.join(map(str, parts)) for parts in FIXTURE_IPS.get(label.split(':', 1)[0], ())}
        if raw not in PROTOCOL_IPS and raw not in fixture_values and not any(ip in network for network in SYNTHETIC_NETWORKS):
            issues.append({"path": label, "rule": "non-example-ipv4"})
            break
    for raw in IPV6.findall(text):
        try:
            ip = ipaddress.IPv6Address(raw)
        except ValueError:
            continue
        if str(ip) not in PROTOCOL_IPV6 and ip not in ipaddress.IPv6Network('2001:db8::/32'):
            issues.append({'path': label, 'rule': 'non-example-ipv6'})
            break
    if any(raw.lower() not in EXAMPLE_MACS for raw in MAC.findall(text)):
        issues.append({"path": label, "rule": "non-example-mac"})
    return issues


def _url_fixture(label, value):
    try:
        parsed = urllib.parse.urlsplit(value)
        return (parsed.password is None and parsed.port is None and not any((parsed.path, parsed.query, parsed.fragment))
                and (parsed.scheme, parsed.username, parsed.hostname) in URL_FIXTURES.get(label.split(':', 1)[0], ()))
    except ValueError:
        return False


def _unescape(text):
    def replace(match):
        value = next(value for value in match.groups() if value is not None)
        number = int(value, 8 if match[5] is not None else 16)
        return chr(number) if number <= 0x10ffff and not 0xd800 <= number <= 0xdfff else match[0]
    return ESCAPE.sub(replace, text)


def _literal(node, level=0):
    """Fold a small whitelist of syntax nodes. No source code is executed."""
    if level > 32:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return node.value if len(node.value) <= MAX_PAYLOAD else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal(node.left, level + 1), _literal(node.right, level + 1)
        if type(left) is type(right) and isinstance(left, (str, bytes)) and len(left) + len(right) <= MAX_PAYLOAD:
            return left + right
    if isinstance(node, ast.Call) and not node.keywords and len(node.args) == 1 and isinstance(node.func, ast.Attribute):
        value = _literal(node.args[0], level + 1)
        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'bytes' and node.func.attr == 'fromhex' and isinstance(value, str):
            try:
                return bytes.fromhex(value)
            except ValueError:
                pass
        if node.func.attr == 'join' and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str) and isinstance(node.args[0], (ast.List, ast.Tuple)):
            parts = [_literal(item, level + 1) for item in node.args[0].elts]
            separator = node.func.value.value
            if all(isinstance(item, str) for item in parts) and sum(map(len, parts)) + len(separator) * len(parts) <= MAX_PAYLOAD:
                return separator.join(parts)
    return None


def _text_bytes(raw):
    encodings = ['utf-8-sig']
    if b'\x00' in raw or raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        encodings += ['utf-16', 'utf-16-le', 'utf-16-be']
    for encoding in encodings:
        try:
            value = raw.decode(encoding)
        except UnicodeError:
            continue
        if value and '\x00' not in value and sum(c.isprintable() or c.isspace() for c in value) / len(value) > .95:
            yield value


def _derived(text, label, deny, issues):
    normalized = re.sub(r'\\([./:_-])', r'\1', text)
    if normalized != text:
        yield 'unescaped', normalized
    unescaped = _unescape(text)
    if unescaped != text:
        yield 'character-escape', unescaped
    if re.search(r'%[0-9a-fA-F]{2}', text):
        yield 'percent-encoded', urllib.parse.unquote(text, errors='replace')
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            value = _literal(node)
            if isinstance(value, str):
                yield 'literal', value
            elif isinstance(value, bytes):
                for decoded in _text_bytes(value):
                    yield 'literal-bytes', decoded
        for value, explicit in numeric_payloads(text):
            if explicit:
                yield 'numeric-bytes', value
            elif any(item.lower() in value.lower() for item in deny if item):
                issues.append({'path': label, 'rule': 'private-encoded-numeric-identifier'})
    for chain in STRING_CHAIN.finditer(text):
        parts = [part[0][1:-1] for part in STRING_PART.finditer(chain[0])]
        yield 'string-concatenation', ''.join(_unescape(part) for part in parts)
    raw_candidates = []
    for token in HEX_PAYLOAD.findall(text):
        if len(token) > MAX_PAYLOAD * 2:
            issues.append({'path': label, 'rule': 'oversized-encoded-payload'})
        elif len(token) % 2 == 0:
            raw_candidates.append(bytes.fromhex(token))
    for match in ENCODED.finditer(text):
        token = match[0]
        if len(token) > MAX_PAYLOAD:
            issues.append({'path': label, 'rule': 'oversized-encoded-payload'})
            continue
        try:
            raw = base64.b64decode(token + '=' * (-len(token) % 4), altchars=b'-_', validate=True)
        except (ValueError, binascii.Error):
            continue
        # Canonical 32-byte material is a usable WireGuard key or peer identity.
        bounded = (match.start() == 0 or text[match.start()-1] in ' \t\r\n\"\'=:([{') and (match.end() == len(text) or text[match.end()] in ' \t\r\n\"\',;)]}')
        if (len(raw) == 32 and len(token) in (43, 44) and bounded
                and base64.b64encode(raw).decode().rstrip('=') == token.replace('-', '+').replace('_', '/').rstrip('=')):
            if not (label.split(':', 1)[0] == 'infra/openwrt/wireguard/luci/backend/test_rpc.py' and raw == bytes(32)):
                issues.append({'path': label, 'rule': 'bare-wireguard-key'})
        raw_candidates.append(raw)
    for raw in raw_candidates:
        if raw.startswith((b'PK\x03\x04', b'\x1f\x8b')):
            issues.append({'path': label, 'rule': 'embedded-archive'})
            continue
        candidates = [raw]
        if raw[:1] == b'x':
            try:
                decoded = zlib.decompressobj().decompress(raw, MAX_PAYLOAD + 1)
                if len(decoded) <= MAX_PAYLOAD:
                    candidates.append(decoded)
                else:
                    issues.append({'path': label, 'rule': 'oversized-encoded-payload'})
            except zlib.error:
                pass
        for candidate in candidates:
            if candidate.startswith((b'PK\x03\x04', b'\x1f\x8b')):
                issues.append({'path': label, 'rule': 'embedded-archive'})
            else:
                for decoded in _text_bytes(candidate):
                    yield 'decoded', decoded


def check_text(label, text, deny=(), depth=0):
    """Inspect bounded static representations, without eval or source execution."""
    issues, pending = [], [(label, text, depth)]
    admitted = len(text)
    if admitted > MAX_PAYLOAD or admitted > MAX_DECODED_TOTAL:
        return [{'path': label, 'rule': 'encoded-inspection-limit'}]
    known = {hashlib.sha256(text.encode('utf-8', errors='surrogatepass')).digest()}
    while pending:
        current_label, current, level = pending.pop()
        issues.extend(_check_plain(current_label, current, deny))
        for kind, value in _derived(current, current_label, deny, issues):
            digest = hashlib.sha256(value.encode('utf-8', errors='surrogatepass')).digest()
            if digest in known:
                continue
            if level >= MAX_DEPTH:
                issues.append({'path': current_label, 'rule': 'unresolved-nested-encoding'})
            elif len(value) > MAX_PAYLOAD or admitted + len(value) > MAX_DECODED_TOTAL or len(known) >= MAX_CANDIDATES:
                issues.append({'path': current_label, 'rule': 'encoded-inspection-limit'})
                return issues
            else:
                known.add(digest)
                admitted += len(value)
                pending.append((current_label + ':' + kind, value, level + 1))
    return issues


def check_bytes(label, raw, deny=()):
    issues = check_text(label + ":filename", label, deny)
    if issues:
        label = '<redacted-path:' + hashlib.sha256(label.encode('utf-8')).hexdigest()[:12] + '>'
        issues = [{'path': label, 'rule': row['rule']} for row in issues]
    if Path(label).suffix.lower() in FORBIDDEN_SUFFIXES or raw.startswith((b"PK\x03\x04", b"\x1f\x8b", b"%PDF-", b"\x89PNG")):
        return issues + [{"path": label, "rule": "excluded-binary-or-archive"}]
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return issues + [{"path": label, "rule": "non-utf8-file"}]
    if "\x00" in text:
        return issues + [{"path": label, "rule": "binary-file"}]
    return issues + check_text(label, text, deny)


def inspect(root, deny=(), git_blobs=False):
    root = Path(root)
    issues, count = [], 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in SKIP for part in relative.parts):
            continue
        if path.is_symlink():
            label = relative.as_posix()
            if check_text(label, label, deny):
                label = '<redacted-path:' + hashlib.sha256(label.encode('utf-8')).hexdigest()[:12] + '>'
            issues.append({"path": label, "rule": "symlink"})
        elif path.is_file():
            count += 1
            issues.extend(check_bytes(relative.as_posix(), path.read_bytes(), deny))
    blobs = 0
    if git_blobs:
        def git(*args):
            return subprocess.check_output(["git", "-C", str(root), *args])
        objects = git("rev-list", "--objects", "--all").decode("utf-8").splitlines()
        seen = set()
        for line in objects:
            oid, _, label = line.partition(" ")
            if oid in seen or git("cat-file", "-t", oid).strip() != b"blob":
                continue
            seen.add(oid)
            blobs += 1
            issues.extend(check_bytes(label, git("cat-file", "blob", oid), deny))
        # Include staged content even before a new commit is reachable.
        for line in git("ls-files", "--stage", '-z').decode("utf-8").split('\x00'):
            if not line:
                continue
            metadata, label = line.split("\t", 1)
            oid = metadata.split()[1]
            if oid not in seen:
                blobs += 1
                seen.add(oid)
                issues.extend(check_bytes(label, git("cat-file", "blob", oid), deny))
        for line in objects:
            oid = line.split(' ', 1)[0]
            kind = git('cat-file', '-t', oid).strip()
            if kind in (b'commit', b'tag'):
                label = 'git:' + kind.decode() + ':' + oid
                issues.extend(check_text(label, git('cat-file', kind.decode(), oid).decode('utf-8'), deny))
            if kind == b'commit':
                for path in git('ls-tree', '-r', '-z', '--name-only', oid).decode('utf-8').split('\x00'):
                    if path:
                        issues.extend(check_bytes(path, b'', deny))
        for ref in git('for-each-ref', '--format=%(refname)').decode('utf-8').splitlines():
            issues.extend(check_text('git:ref-name', ref, deny))
        for line in git("log", "--all", "--format=%an <%ae>|%cn <%ce>").decode("utf-8").splitlines():
            expected = "Home Network Infra Contributors <contributors@example.invalid>"
            if line != expected + "|" + expected:
                issues.append({"path": "git:commit-metadata", "rule": "unexpected-commit-identity"})
    unique = {json.dumps(row, sort_keys=True): row for row in issues}
    return {"passed": not unique, "files_checked": count, "git_blobs_checked": blobs,
            "issues": list(unique.values()), "matched_values_disclosed": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--denylist", type=Path)
    parser.add_argument("--git-blobs", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    deny = json.loads(args.denylist.read_text(encoding="utf-8"))["deny_literals"] if args.denylist else []
    result = inspect(args.root, deny, args.git_blobs)
    if args.report:
        args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["passed"] else 1)
