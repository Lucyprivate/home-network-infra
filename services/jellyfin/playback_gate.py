#!/usr/bin/env python3
"""Caddy forward_auth gate for one ordinary Jellyfin playback device.

Only Caddy (172.28.40.4) may call /authorize. No passwords, tokens, original
request URIs, or user/device identifiers are logged. Run a single gate instance.
The lease coordinates normal web/Android clients, not hostile token sharing or
multiple player windows deliberately using the same Jellyfin device identity.
Native live HLS cached fragments lack client authentication. They are admitted
only within an authenticated manifest's current item/client-IP lease scope;
they neither acquire nor renew a lease and retain native opaque-cache semantics.
"""
from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://172.28.40.3:8096"
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,256}\Z")
DEVICE_RE = re.compile(r"[^\x00-\x20\x7f]{1,256}\Z")
PAIR_RE = re.compile(r'(?:^|[,\s])([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"([^"\r\n]*)"|([^,\s]+))')
BUSY = "Only one playback device is allowed. Stop playback on the other device and try again."
UUID_PATH = r"(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
CACHE_FRAGMENT_RE = re.compile(r"^/videos/(?P<item>" + UUID_PATH + r")/hls/(?P<cache>[0-9a-f]{32})/(?P=cache)(?:(?:0|[1-9][0-9]*)\.(?:ts|m4s|mp4)|-1\.mp4)$", re.I)
MANIFEST_RE = re.compile(r"^/videos/(?P<item>" + UUID_PATH + r")/(?:[a-z0-9_-]+/)*[a-z0-9_-]+\.m3u8$", re.I)


class GateError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)


def unique(values, label):
    values = set(value for value in values if value)
    if len(values) > 1:
        raise GateError(400, "Conflicting " + label + " values.")
    return next(iter(values), None)


def request_identity(headers, query):
    """Parse established Jellyfin header/query auth without logging raw values."""
    tokens, devices = [], []
    for key, value in headers.items():
        key = key.lower()
        if len(value) > 8192 or "\r" in value or "\n" in value:
            raise GateError(400, "Invalid request headers.")
        if key in ("authorization", "x-emby-authorization"):
            if value.lower().startswith("bearer "):
                tokens.append(value[7:].strip())
            for match in PAIR_RE.finditer(value):
                name, quoted, unquoted = match.groups()
                val = quoted if quoted is not None else unquoted
                if name.lower() == "token":
                    tokens.append(val)
                elif name.lower() == "deviceid":
                    devices.append(val)
        elif key in ("x-emby-token", "x-mediabrowser-token"):
            tokens.append(value)
        elif key in ("x-emby-device-id", "x-device-id"):
            devices.append(value)
    for key, values in query.items():
        if key.lower() in ("api_key", "apikey", "access_token"):
            tokens.extend(values)
        elif key.lower() == "deviceid":
            devices.extend(values)
    token = unique(tokens, "authentication")
    device = unique(devices, "device identity")
    if not token or not TOKEN_RE.fullmatch(token):
        raise GateError(401, "Jellyfin authentication is required.")
    if device is not None and not DEVICE_RE.fullmatch(device):
        raise GateError(400, "Unsupported Jellyfin device identity.")
    return token, device


def classify(uri):
    parsed = urllib.parse.urlsplit(uri)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/") or len(uri) > 16384:
        raise GateError(400, "Invalid forwarded request.")
    path = parsed.path.lower()
    if path.startswith("/emby/"):
        path = path[5:]
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, max_num_fields=100)
    negotiation = re.fullmatch(r"/items/[^/]+/playbackinfo/?", path) or path in ("/livestreams/open", "/livestreams/open/")
    if negotiation:
        # Caddy sets canonical false values before proxying negotiations. Do
        # not allow a differently cased/duplicate parameter to restore static
        # playback through ASP.NET's case-insensitive query binding.
        protected = {"enabledirectplay", "enabledirectstream", "forcedirectplay", "forcedirectstream"}
        for key, values in query.items():
            if key.lower() in protected and any(value.lower() != "false" for value in values):
                raise GateError(400, "Direct playback query options must be false for playback negotiation.")
    manifest_path = urllib.parse.unquote(path).lower().rstrip("/")
    if manifest_path.startswith("/emby/"):
        manifest_path = manifest_path[5:]
    if re.fullmatch(r"/videos/[^/]+/stream\.(?:hls|m3u8|m3u)", manifest_path):
        if any(value.strip().lower() == "true" for key, values in query.items() if key.lower() == "static" for value in values):
            raise GateError(403, "Static remote playlists are disabled; use Jellyfin's server playback stream.")
    if path == "/sessions/playing/stopped":
        return "stop", query
    if path in ("/sessions/playing", "/sessions/playing/progress"):
        return "progress", query
    if re.fullmatch(r"/items/[^/]+/playbackinfo/?", path):
        is_playback = next((values for key, values in query.items() if key.lower() == "isplayback"), [])
        return ("metadata" if is_playback == ["false"] else "play"), query
    if path in ("/livestreams/open", "/livestreams/open/"):
        return "play", query
    if path.startswith("/livetv/livestreamfiles/"):
        return "media", query
    if CACHE_FRAGMENT_RE.fullmatch(path):
        return "cached-fragment", query
    if re.match(r"/videos/[^/]+/", path):
        if "/subtitles/" in path or "/attachments/" in path:
            return "metadata", query
        return "media", query
    return "metadata", query


def normalized_video_path(uri):
    path = urllib.parse.urlsplit(uri).path.lower()
    return path[5:] if path.startswith("/emby/") else path


def trusted_client_ip(headers):
    """Caddy overwrites this header; Handler admits only the fixed Caddy peer."""
    values = [value for key, value in headers.items() if key.lower() == "x-jf-live-client"]
    if len(values) != 1 or not isinstance(values[0], str):
        return None
    try:
        return ipaddress.ip_address(values[0]).compressed
    except ValueError:
        return None


def has_auth_material(headers, query):
    names = {"authorization", "x-emby-authorization", "x-emby-token", "x-mediabrowser-token"}
    return (any(key.lower() in names and isinstance(value, str) and value.strip() for key, value in headers.items())
            or any(key.lower() in ("api_key", "apikey", "access_token") and any(value.strip() for value in values)
                   for key, values in query.items()))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GateError(503, "Playback authentication service is unavailable.")


class Jellyfin:
    def __init__(self, control_token=None):
        self.control_token = control_token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def get(self, path, token):
        headers = {"Accept": 'application/json; profile="PascalCase"',
                   "Authorization": 'MediaBrowser Client="ServiceHostPlaybackGate", Device="ServiceHost", '
                                    'DeviceId="service-host-playback-gate", Version="1", Token="' + token + '"'}
        request = urllib.request.Request(BASE + path, headers=headers)
        try:
            with self.opener.open(request, timeout=5) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise GateError(503, "Playback authentication service returned an invalid response.")
            return json.loads(raw)
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            if status in (401, 403):
                raise GateError(401, "Jellyfin authentication is required.") from None
            raise GateError(503, "Playback authentication service is unavailable.") from None
        except (OSError, ValueError):
            raise GateError(503, "Playback authentication service is unavailable.") from None

    def authenticate(self, token):
        user = self.get("/Users/Me", token)
        if (not isinstance(user, dict) or not re.fullmatch(r"[0-9a-fA-F-]{32,36}", user.get("Id", ""))
                or user.get("Policy", {}).get("IsDisabled") is True):
            raise GateError(401, "A valid Jellyfin user session is required.")
        return user["Id"]

    def sessions(self, token):
        sessions = self.get("/Sessions", self.control_token or token)
        if not isinstance(sessions, list):
            raise GateError(503, "Playback session service returned an invalid response.")
        return sessions


def active_owner(session, wall_time):
    """Use reported playback, including paused live playback, to protect long GETs."""
    if not isinstance(session, dict) or not session.get("NowPlayingItem"):
        return None
    uid, device = session.get("UserId"), session.get("DeviceId")
    if not uid or not device:
        return None
    stamp = session.get("LastPlaybackCheckIn") or session.get("LastActivityDate")
    if stamp:
        try:
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if wall_time - when.timestamp() > 90:
                return None
        except (ValueError, TypeError):
            # Unknown timestamps are conservatively treated as active.
            pass
    return str(uid), str(device)


class LeaseGate:
    def __init__(self, jellyfin, clock=time.monotonic, wall_clock=time.time, ttl=45, auth_ttl=15):
        self.api, self.clock, self.wall_clock = jellyfin, clock, wall_clock
        self.ttl, self.auth_ttl = ttl, auth_ttl
        self.lock = threading.Lock()
        self.owner, self.touched, self.release_at = None, 0, None
        self.media_scope = None
        self.auth_cache, self.context = OrderedDict(), OrderedDict()

    def authenticate(self, token):
        digest = hashlib.sha256(token.encode()).hexdigest()
        now = self.clock()
        with self.lock:
            cached = self.auth_cache.get(digest)
            if cached and now - cached[1] < self.auth_ttl:
                return digest, cached[0]
        uid = self.api.authenticate(token)
        with self.lock:
            self.auth_cache[digest] = (uid, now)
            self.auth_cache.move_to_end(digest)
            while len(self.auth_cache) > 128:
                evicted, _ = self.auth_cache.popitem(last=False)
                self.context.pop(evicted, None)
        return digest, uid

    def authorize(self, headers, uri):
        action, query = classify(uri)
        if action == "metadata":
            return 204
        if action == "cached-fragment" and not has_auth_material(headers, query):
            # Native live HLS intentionally omits auth query/headers on cached
            # file segments (Chrome behavior documented by HlsSegmentController).
            # Such reads cannot create a stream or acquire/renew our lease.
            # Scope is established only by an authenticated same-item manifest.
            item = CACHE_FRAGMENT_RE.fullmatch(normalized_video_path(uri))["item"].replace("-", "")
            client_ip = trusted_client_ip(headers)
            with self.lock:
                active = (self.owner is not None and self.clock() - self.touched < self.ttl
                          and self.release_at is None)
                if not client_ip or not active or self.media_scope != (self.owner, item, client_ip):
                    raise GateError(401, "An active authenticated playback manifest is required for this cached segment.")
            return 204
        token, device = request_identity(headers, query)
        digest, uid = self.authenticate(token)
        with self.lock:
            known = self.context.get(digest)
            if known and known[0] == uid:
                if device is None and action in ("media", "progress", "stop"):
                    device = known[1]
                elif device is not None and device != known[1]:
                    raise GateError(403, "This Jellyfin session has another device identity.")
            if device is None:
                raise GateError(400, "A Jellyfin device identity is required for playback.")
            owner = (uid, device)
            now = self.clock()
            if action == "stop":
                if self.owner == owner:
                    self.media_scope = None
                    # forward_auth runs before Jellyfin consumes the stopped
                    # report. Allow two seconds for native session state to
                    # settle, preventing another device stealing a cutover.
                    self.release_at = now + 2
                return 204
            held = (self.owner is not None and now - self.touched < self.ttl
                    and (self.release_at is None or now < self.release_at))
            if self.owner == owner and held:
                self.touched = now
                self.release_at = None
                self.context[digest] = owner
                self.remember_manifest(headers, uri, owner)
                return 204
            if held:
                raise GateError(423, BUSY)
            # Empty/expired leases and process restarts consult native sessions.
            # The lock makes cross-device acquisition atomic during this read.
            sessions = self.api.sessions(token)
            active = [active_owner(session, self.wall_clock()) for session in sessions]
            if any(existing is not None and existing != owner for existing in active):
                raise GateError(423, BUSY)
            self.owner, self.touched, self.release_at = owner, now, None
            self.media_scope = None
            self.context[digest] = owner
            self.context.move_to_end(digest)
            while len(self.context) > 128:
                self.context.popitem(last=False)
            self.remember_manifest(headers, uri, owner)
            return 204

    def remember_manifest(self, headers, uri, owner):
        """Called under lease lock only after normal authenticated admission."""
        manifest = MANIFEST_RE.fullmatch(normalized_video_path(uri))
        if not manifest:
            return
        client_ip = trusted_client_ip(headers)
        self.media_scope = (owner, manifest["item"].replace("-", ""), client_ip) if client_ip else None


def load_control_token():
    filename = os.environ.get("GATE_CONTROL_KEY_FILE")
    if not filename:
        return None
    try:
        value = json.loads(Path(filename).read_text())
        token = value["api_token"]
        if not TOKEN_RE.fullmatch(token):
            raise ValueError()
        return token
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit("Protected playback gate control credential is unavailable.") from None


class Handler(BaseHTTPRequestHandler):
    server_version = "ServiceHostPlaybackGate/1"
    sys_version = ""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        # Caddy forward_auth's URI rewrite retains the original query string.
        # The original media URI is independently supplied in X-Forwarded-Uri.
        endpoint = urllib.parse.urlsplit(self.path).path
        if endpoint == "/healthz":
            self.reply(200, "ready")
            return
        if endpoint != "/authorize":
            self.reply(404, "Unknown gate endpoint.")
            return
        if self.client_address[0] != "172.28.40.4":
            self.reply(403, "Only the configured local gateway may authorize playback.")
            return
        uri = self.headers.get("X-Forwarded-Uri", "")
        try:
            result = self.server.gate.authorize(dict(self.headers.items()), uri)
            self.reply(result)
        except GateError as error:
            self.reply(error.status, error.message)
        except Exception:
            self.reply(503, "Playback gate is temporarily unavailable.")

    def reply(self, status, message=None):
        payload = json.dumps({"Message": message}).encode() if message else b""
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if status == 423:
            self.send_header("Retry-After", "5")
        self.end_headers()
        if payload:
            self.wfile.write(payload)


def main():
    token = load_control_token()
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.daemon_threads = True
    server.gate = LeaseGate(Jellyfin(token))
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
