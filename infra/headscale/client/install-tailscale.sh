#!/usr/bin/env bash
# Install only. This script never registers a node or calls `tailscale up`.
set -Eeuo pipefail
export LC_ALL=C
umask 077

readonly TASK_VERSION=1.104.1
FINGERPRINT=2596A99EAAB33821893C0A79458CA832957F5868
DEB_SHA256=509753a4ff223efc70234e7f539afc51f743b3af043d9e55313960bd7327700f
KEY=/usr/share/keyrings/tailscale-archive-keyring.gpg
SOURCE=/etc/apt/sources.list.d/tailscale.list
PIN=/etc/apt/preferences.d/headscale-tailscale-version
OPERATOR=''
RECORD_DIR=''

usage() {
    echo "Usage: sudo bash $0 [--operator USER] [--record-dir ABSOLUTE_NEW_DIRECTORY]"
    echo 'Installs Tailscale 1.104.1 on Ubuntu 26.04 amd64; does not connect/register.'
}
while (($#)); do
    case "$1" in
        --operator) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; OPERATOR=$2; shift 2 ;;
        --record-dir) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; RECORD_DIR=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
fail() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail 'Run through sudo; do not put a password in this script.'
for tool in curl gpg python3 dpkg-query apt-get apt-cache systemctl sha256sum; do
    command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool (install separately)."
done
TASK_OS_ID=$( . /etc/os-release; printf '%s' "$ID")
TASK_OS_CODENAME=$( . /etc/os-release; printf '%s' "${VERSION_CODENAME:-}")
TASK_OS_VERSION=$( . /etc/os-release; printf '%s' "${VERSION:-}")
[[ $TASK_OS_ID == ubuntu && $TASK_OS_CODENAME == resolute ]] || fail 'Expected Ubuntu resolute.'
[[ $(dpkg --print-architecture) == amd64 ]] || fail 'Only the verified amd64 package is supported.'
if [[ -n $OPERATOR ]]; then
    [[ $OPERATOR =~ ^[a-z_][a-z0-9_-]*\$?$ ]] || fail 'Invalid operator username.'
    getent passwd "$OPERATOR" >/dev/null || fail 'Operator user does not exist.'
fi
[[ $(dpkg-query -W -f='${Status}' iptables 2>/dev/null || true) == 'install ok installed' ]] || fail 'iptables must already be installed.'
INSTALLED=$(dpkg-query -W -f='${Version}' tailscale 2>/dev/null || true)
[[ -z $INSTALLED || $INSTALLED == "$TASK_VERSION" ]] || fail "Existing Tailscale version $INSTALLED; refusing to replace it."
[[ $(systemctl is-enabled tailscaled.service 2>/dev/null || true) != masked* ]] || fail 'tailscaled is masked; refusing to override it.'
if command -v tailscale >/dev/null; then
    [[ -n $INSTALLED ]] || fail 'An unmanaged tailscale binary exists; inspect it before installing.'
    if systemctl is-active --quiet tailscaled.service; then
        STATUS=$(tailscale status --json 2>/dev/null) || fail 'Cannot inspect existing tailscaled; refusing to overwrite an unknown setup.'
        printf '%s' "$STATUS" | python3 -c 'import json,sys; s=json.load(sys.stdin); me=s.get("Self") or {}; sys.exit(1 if s.get("CurrentTailnet") or me.get("ID") or s.get("TailscaleIPs") else 0)' \
            || fail 'An existing registered Tailscale node was found; no changes made.'
        unset STATUS
    elif [[ -s /var/lib/tailscale/tailscaled.state ]]; then
        fail 'Existing state with a stopped daemon; inspect it before installation. No state is removed.'
    fi
elif [[ -s /var/lib/tailscale/tailscaled.state ]]; then
    fail 'Existing Tailscale state without a managed client; no changes made.'
fi

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
mkdir -m 700 "$TMP/gnupg"
curl --fail --location --proto '=https' --tlsv1.2 --max-time 60 --silent --show-error \
    https://pkgs.tailscale.com/stable/ubuntu/resolute.noarmor.gpg -o "$TMP/key.gpg"
ACTUAL_FPR=$(gpg --batch --homedir "$TMP/gnupg" --show-keys --with-colons "$TMP/key.gpg" 2>/dev/null | awk -F: '$1=="fpr" {print $10; exit}')
[[ $ACTUAL_FPR == "$FINGERPRINT" ]] || fail "Official signing key fingerprint mismatch: $ACTUAL_FPR"
printf '%s\n' '# Tailscale packages for ubuntu resolute' \
    'deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu resolute main' > "$TMP/source.list"
printf '%s\n' 'Package: tailscale' "Pin: version $TASK_VERSION" 'Pin-Priority: 1001' > "$TMP/pin"
if [[ -f $PIN && ! -L $PIN ]] && ! cmp --silent "$PIN" "$TMP/pin"; then
    # Repair only this installer's proven, failed, pre-package VERSION collision.
    python3 - "$PIN" "$TMP/pin" "$INSTALLED" "$TASK_OS_VERSION" <<'PY'
import datetime, hashlib, json, os, pathlib, stat, sys
pin, replacement = map(pathlib.Path, sys.argv[1:3])
installed, old_version = sys.argv[3:5]
base = pathlib.Path('/var/lib/headscale-client-install')
def safe(p, directory=False):
    try:
        s = p.lstat()
        return s.st_uid == 0 and not s.st_mode & 0o022 and (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
    except OSError:
        return False
def reject():
    raise SystemExit('Existing different version pin has no matching failed-install ownership receipt; not changed.')
old_bytes = f'Package: tailscale\nPin: version {old_version}\nPin-Priority: 1001\n'.encode()
if installed or not old_version or not safe(base, True) or not safe(pin) or pin.read_bytes() != old_bytes:
    reject()
for receipt in sorted(base.iterdir(), reverse=True):
    if not safe(receipt, True):
        continue
    before, created, code = (receipt / n for n in ('before.json', 'created-files', 'exit-code'))
    if not all(safe(p) for p in (before, created, code)):
        continue
    try:
        record = json.loads(before.read_text())
        owned = record['files'][str(pin)]
        package = record['package']
        if (record['version'] != old_version or owned != {'existed': False, 'sha256': None}
                or str(pin) not in created.read_text().splitlines() or code.read_text() != '1\n'
                or package['exit'] != 1 or package['stdout']):
            continue
        new_bytes = replacement.read_bytes()
        recovery = {'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'reason': 'os-release VERSION collision before package installation', 'pin': str(pin),
                    'before_sha256': hashlib.sha256(old_bytes).hexdigest(),
                    'after_sha256': hashlib.sha256(new_bytes).hexdigest()}
        # All evidence and destinations are root owned; retain ownership proof.
        (receipt / 'pin-before-repair').write_bytes(old_bytes)
        (receipt / 'pin-repair.json').write_text(json.dumps(recovery, indent=2) + '\n')
        staged = pin.with_name(pin.name + f'.repair-{os.getpid()}')
        with staged.open('xb') as f:
            f.write(new_bytes)
        staged.chmod(0o644)
        os.replace(staged, pin)
        print(f'Repaired this installer\'s failed version pin; ownership receipt: {receipt}')
        break
    except (KeyError, ValueError, OSError):
        continue
else:
    reject()
PY
fi
for pair in "$KEY|$TMP/key.gpg" "$SOURCE|$TMP/source.list" "$PIN|$TMP/pin"; do
    TARGET=${pair%%|*}; EXPECTED=${pair#*|}
    [[ ! -L $TARGET ]] || fail "Refusing symlink: $TARGET"
    [[ ! -e $TARGET && ! -L $TARGET ]] || cmp --silent "$TARGET" "$EXPECTED" || fail "Existing file differs: $TARGET (not overwritten)."
done
if command -v rg >/dev/null; then
    OTHER_SOURCES=$(rg -l 'pkgs\.tailscale\.com' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true)
else
    OTHER_SOURCES=$(grep -rlE 'pkgs\.tailscale\.com' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true)
fi
if [[ -n $OTHER_SOURCES ]]; then
    while IFS= read -r path; do
        [[ $path == "$SOURCE" ]] || fail "Another Tailscale apt source exists: $path"
    done <<< "$OTHER_SOURCES"
fi
if [[ -z $RECORD_DIR ]]; then
    RECORD_DIR=/var/lib/headscale-client-install/$(date -u +%Y%m%dT%H%M%SZ)-$$
fi
[[ $RECORD_DIR == /* && ! -e $RECORD_DIR ]] || fail 'record-dir must be an absolute new directory.'
install -d -m 700 "$RECORD_DIR"
python3 - "$RECORD_DIR/before.json" "$TASK_VERSION" "$OPERATOR" "$KEY" "$SOURCE" "$PIN" <<'PY'
import datetime, hashlib, json, pathlib, subprocess, sys
out, version, operator, *paths = sys.argv[1:]
def run(*args):
    p = subprocess.run(args, text=True, capture_output=True)
    return {"exit": p.returncode, "stdout": p.stdout.strip()}
files = {}
for name in paths:
    p = pathlib.Path(name)
    files[name] = {"existed": p.exists(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None}
state = {"time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "version": version,
         "operator_requested": operator, "files": files,
         "package": run("dpkg-query", "-W", "-f=${Status}\n${Version}", "tailscale"),
         "service_active": run("systemctl", "is-active", "tailscaled.service"),
         "service_enabled": run("systemctl", "is-enabled", "tailscaled.service")}
try:
    prefs = json.loads(subprocess.run(["tailscale", "debug", "prefs"], text=True, capture_output=True, timeout=5).stdout)
    state["preferences_before"] = {k: prefs.get(k) for k in ("AutoUpdate", "OperatorUser")}
except (OSError, ValueError, subprocess.TimeoutExpired):
    state["preferences_before"] = None
pathlib.Path(out).write_text(json.dumps(state, indent=2) + "\n")
PY
trap 'RC=$?; printf "%s\n" "$RC" > "$RECORD_DIR/exit-code"; rm -rf -- "$TMP"; echo "Installation receipt: $RECORD_DIR" >&2' EXIT
for pair in "$KEY|$TMP/key.gpg" "$SOURCE|$TMP/source.list" "$PIN|$TMP/pin"; do
    TARGET=${pair%%|*}; EXPECTED=${pair#*|}
    if [[ ! -e $TARGET ]]; then
        install -D -m 644 "$EXPECTED" "$TARGET"
        printf '%s\n' "$TARGET" >> "$RECORD_DIR/created-files"
    fi
done
apt-get -o Dir::Etc::sourcelist="$SOURCE" -o Dir::Etc::sourceparts=- \
    -o APT::Get::List-Cleanup=false update
META_SHA=$(apt-cache show "tailscale:amd64=$TASK_VERSION" | awk '/^SHA256:/ {print $2; exit}')
[[ $META_SHA == "$DEB_SHA256" ]] || fail 'The fixed version package hash does not match the verified official metadata.'
apt-get --simulate --no-upgrade --no-remove --no-install-recommends install "tailscale=$TASK_VERSION" > "$RECORD_DIR/apt-simulation.txt"
if awk '$1=="Inst" && $2!="tailscale" {found=1} END {exit !found}' "$RECORD_DIR/apt-simulation.txt"; then
    fail 'APT would change another package; inspect the simulation receipt.'
fi
apt-get --yes --no-upgrade --no-remove --no-install-recommends install "tailscale=$TASK_VERSION"
[[ $(dpkg-query -W -f='${Version}' tailscale) == "$TASK_VERSION" ]] || fail 'Installed package version mismatch.'
systemctl enable --now tailscaled.service
READY=0
for ((attempt=0; attempt<20; attempt++)); do
    if tailscale status --json >/dev/null 2>&1; then READY=1; break; fi
    sleep 1
done
[[ $READY == 1 ]] || fail 'tailscaled did not become ready within 20 seconds.'
SET_ARGS=(--auto-update=false --update-check=false)
[[ -z $OPERATOR ]] || SET_ARGS+=("--operator=$OPERATOR")
if tailscale set "${SET_ARGS[@]}" > "$RECORD_DIR/set-result.txt" 2>&1; then
    printf '%s\n' applied > "$RECORD_DIR/preferences-result"
else
    printf '%s\n' 'Deferred: daemon is logged out; reapply set flags after registration.' > "$RECORD_DIR/preferences-result"
    echo 'WARNING: apply the recorded set flags after registration; install itself is complete.' >&2
fi
tailscale version | head -1 > "$RECORD_DIR/installed-version"
printf '%s\n' "$DEB_SHA256" > "$RECORD_DIR/official-amd64-deb-sha256"
printf '%s\n' "$ACTUAL_FPR" > "$RECORD_DIR/official-key-fingerprint"
sha256sum "$KEY" "$SOURCE" "$PIN" > "$RECORD_DIR/installed-files.sha256"
echo 'Installed and started; node remains unregistered. Registration is a separate step.'
