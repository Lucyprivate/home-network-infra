#!/usr/bin/env python3
"""Bounded IPTV/EPG publisher. Python 3.13 stdlib only; no media relay.

Exit 0: published a valid generation (warnings are in status.json).
Exit 1: update failed; current and last-good are untouched.
Exit 2: command/configuration error. Exit 75: another update holds the lock.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import ctypes
import datetime as dt
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC = dt.timezone.utc
HK = dt.timezone(dt.timedelta(hours=8))
MIB = 1024 * 1024
API = "https://iptv-org.github.io/api/{}.json"
USER_AGENT = "ServiceHost-JellyfinLive/1.0"
MAX_PROBE_BYTES = 16 * MIB
MAX_ATTEMPT_BYTES = 256 * 1024
MAX_CHANNELS = 60
TIMEOUT = 10
PLAYLIST_CAP = 48 * 1024
LIVENESS_READ_RESERVE = 1.0
ATTEMPT_SECONDS = 30
PROBE_WORKERS = 3
MAX_REDIRECTS = 5
JOB_SECONDS = 900
PROCESS_CLEANUP_RESERVE = 0.25
SUPPORTED_EPG_REGIONS = frozenset(('AU BR CA CN DE FR GB HK ID IN JP MY NZ PH RU SG TW US VN ZA').split())
RUN_DEADLINE = float("inf")


class UpdateError(Exception):
    pass


class BudgetExhausted(UpdateError):
    pass


class ProbeDeferred(UpdateError):
    """The bounded attempt cannot establish whether the source is live."""


class ProbeBudget:
    """A round-wide allowance including reads already reserved by workers."""
    def __init__(self, limit=MAX_PROBE_BYTES):
        self.limit = limit
        self.bytes = self.requests = self.reserved = 0
        self.conservative_bytes = self.unreported_attempts = 0
        self.phase_limit = limit
        self.lock = threading.Lock()

    def set_phase_limit(self, ceiling):
        with self.lock:
            if self.reserved:
                raise UpdateError("probe phase changed while reads are in flight")
            self.phase_limit = min(self.limit, ceiling)

    def reserve(self, wanted, count_request=True):
        with self.lock:
            available = min(wanted, self.limit - self.bytes - self.reserved,
                            self.phase_limit - self.bytes - self.reserved)
            if available <= 0:
                raise BudgetExhausted("media probe shared or phase budget exhausted")
            self.reserved += available
            if count_request:
                self.requests += 1
            return available

    def add_requests(self, count=1):
        with self.lock:
            self.requests += count

    def settle_attempt(self, grant, actual=None, requests=None):
        with self.lock:
            self.reserved -= grant
            self.bytes += grant if actual is None else actual
            if requests is not None:
                self.requests += requests
            if actual is None:
                self.conservative_bytes += grant
                self.unreported_attempts += 1

    def received(self, count):
        with self.lock:
            self.reserved -= count
            self.bytes += count

    def release(self, count):
        with self.lock:
            self.reserved -= count


def iso_now():
    return dt.datetime.now(UTC).isoformat(timespec="seconds")


def normalize(value):
    """Only normalize typography; never transliterate or fuzzy-match names."""
    return "".join(c for c in unicodedata.normalize("NFKC", value).casefold()
                   if c.isalnum())


def safe_url(url):
    if not isinstance(url, str) or any(c in url for c in "\r\n\x00"):
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname) and not parsed.username and not parsed.password
    except ValueError:
        return False


class NoAutomaticRedirect(urllib.request.HTTPRedirectHandler):
    """urllib's default redirect handler drains fp.read() without a limit."""
    def http_error_302(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def request(url, timeout=TIMEOUT, headers=None, deadline=float("inf"), on_redirect=None):
    end = min(RUN_DEADLINE, deadline, time.monotonic() + timeout)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoAutomaticRedirect())
    for hop in range(MAX_REDIRECTS + 1):
        if not safe_url(url):
            raise UpdateError("unsupported or credential-bearing URL")
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise ProbeDeferred("request chain deadline exhausted")
        if hop and on_redirect:
            on_redirect()
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
        try:
            return opener.open(req, timeout=remaining)
        except urllib.error.HTTPError as exc:
            try:
                if exc.code not in (301, 302, 303, 307, 308):
                    raise
                location = exc.headers.get("Location")
                if not location or hop >= MAX_REDIRECTS:
                    raise UpdateError("missing redirect location or redirect limit exceeded")
                try:
                    target = urllib.parse.urljoin(url, location)
                except ValueError:
                    raise UpdateError("malformed redirect URL") from None
                if not safe_url(target):
                    raise UpdateError("unsupported or credential-bearing redirect URL")
                url = target
            finally:
                # Never read redirect/error bodies, including invalid targets.
                exc.close()
    raise UpdateError("redirect limit exceeded")


def fetch_json(url, limit=24 * MIB):
    with request(url, timeout=30) as response:
        blob = response.read(limit + 1)
    if len(blob) > limit:
        raise UpdateError("metadata size limit exceeded")
    result = json.loads(blob)
    if not isinstance(result, list):
        raise UpdateError("metadata must be an array")
    return result


def redacted_error(exc):
    # Do not expose tokenized upstream URLs in logs or status.
    if isinstance(exc, urllib.error.HTTPError):
        return "HTTP {}".format(exc.code)
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, urllib.error.URLError):
        return "network error: " + type(exc.reason).__name__
    if isinstance(exc, UpdateError):
        return str(exc)
    return type(exc).__name__


class Probe:
    def __init__(self, limit=MAX_PROBE_BYTES, opener=None, global_deadline=float("inf"),
                 clock=None, sleeper=None, budget=None, isolate=False):
        self.budget = budget if budget is not None else ProbeBudget(limit)
        self.attempt_bytes = 0
        self.opener = opener or request
        self.deadline = 0
        self.global_deadline = global_deadline
        self.clock = clock or time.monotonic
        self.sleeper = sleeper or time.sleep
        self.isolate = isolate

    @property
    def bytes(self):
        return self.budget.bytes

    @property
    def requests(self):
        return self.budget.requests

    @property
    def limit(self):
        return self.budget.limit

    def fork(self, deadline):
        return Probe(opener=self.opener, global_deadline=min(deadline, self.global_deadline),
                     clock=self.clock, sleeper=self.sleeper, budget=self.budget, isolate=self.isolate)

    def read(self, url, cap, ranged=False, refresh=False):
        if self.clock() >= self.global_deadline:
            raise BudgetExhausted("media probe wall-clock budget exhausted")
        wanted = min(cap, MAX_ATTEMPT_BYTES - self.attempt_bytes)
        if wanted <= 0:
            raise BudgetExhausted("media probe budget exhausted")
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise UpdateError("probe time limit exceeded")
        available = self.budget.reserve(wanted)
        headers = {"Range": "bytes=0-{}".format(available - 1)} if ranged else {}
        if refresh:
            # Revalidate the exact resolved URL; changing a signed query could
            # invalidate it. Never follow segment URLs during this reread.
            headers.update({"Cache-Control": "no-cache", "Pragma": "no-cache"})
        data, consumed = bytearray(), 0
        try:
            with self.opener(url, timeout=min(TIMEOUT, remaining), headers=headers,
                             deadline=min(self.deadline, self.global_deadline),
                             on_redirect=self.budget.add_requests) as response:
                # Fixed-size reads also bound servers that ignore Range.
                while len(data) < available:
                    if self.clock() >= self.global_deadline:
                        raise BudgetExhausted("media probe wall-clock budget exhausted")
                    if self.clock() >= self.deadline:
                        raise UpdateError("probe time limit exceeded")
                    sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
                    if sock is not None:
                        sock.settimeout(max(0.1, min(TIMEOUT, self.deadline - self.clock())))
                    reader = getattr(response, "read1", response.read)
                    part = reader(min(16 * 1024, available - len(data)))
                    if not part:
                        break
                    self.budget.received(len(part))
                    consumed += len(part)
                    self.attempt_bytes += len(part)
                    data.extend(part)
                return bytes(data), response.geturl()
        finally:
            self.budget.release(available - consumed)

    @staticmethod
    def variants(text, base):
        lines = [line.strip() for line in text.splitlines()]
        variants = []
        for i, line in enumerate(lines):
            if not line.startswith("#EXT-X-STREAM-INF:"):
                continue
            attrs = dict(re.findall(r'([A-Z0-9-]+)=("[^"]*"|[^,]*)', line))
            match = re.search(r"\d+x(\d+)", attrs.get("RESOLUTION", ""))
            height = int(match.group(1)) if match else 0
            if height > 1080:
                continue
            codecs = attrs.get("CODECS", "").lower()
            compatible = ("avc1" in codecs or "avc3" in codecs) and "mp4a" in codecs
            for target in lines[i + 1:]:
                if target and not target.startswith("#"):
                    variants.append(((not compatible, not bool(height), abs(height - 720)), urllib.parse.urljoin(base, target)))
                    break
        return [url for _, url in sorted(variants)]

    @staticmethod
    def media_segments(text, base):
        lines = [line.strip() for line in text.splitlines()]
        if not lines or lines[0] != "#EXTM3U" or any(line.startswith("#EXT-X-STREAM-INF:") for line in lines):
            raise UpdateError("not an HLS media playlist")
        if "#EXT-X-ENDLIST" in lines:
            raise UpdateError("playlist is no longer live")
        segments = tuple(urllib.parse.urljoin(base, line) for line in lines if line and not line.startswith("#"))
        if not segments or not any(line.startswith("#EXTINF:") for line in lines):
            raise UpdateError("playlist has no live segments")
        return segments

    @staticmethod
    def liveness_parameters(text):
        lines = [line.strip() for line in text.splitlines()]
        values = []
        for tag in ("#EXT-X-TARGETDURATION:", "#EXT-X-MEDIA-SEQUENCE:"):
            entries = [line[len(tag):] for line in lines if line.startswith(tag)]
            if len(entries) != 1 or not re.fullmatch(r"[0-9]{1,20}", entries[0]):
                raise ProbeDeferred("HLS liveness deferred: target duration or media sequence unavailable")
            values.append(int(entries[0]))
        target, sequence = values
        if not 1 <= target <= 3600 or sequence >= 2 ** 64:
            raise ProbeDeferred("HLS liveness deferred: target duration or media sequence out of range")
        return target, sequence

    def live_playlist(self, text, resolved, observed):
        """Observe advancement, then return the fresh playlist for one sample.

        RFC 8216 section 6.2.1 permits the next update as late as 1.5 target
        durations. A full permitted interval plus a small scheduling margin
        prevents a healthy six-second source failing at its update boundary.
        Targets whose observation interval cannot fit the 30s cap are deferred.
        """
        segments = self.media_segments(text, resolved)
        target, sequence = self.liveness_parameters(text)
        due = observed + 1.5 * target + 0.25
        if due + LIVENESS_READ_RESERVE > self.deadline:
            raise ProbeDeferred("HLS liveness deferred: target interval exceeds remaining probe time")
        delay = due - self.clock()
        if delay > 0:
            self.sleeper(delay)
        if self.clock() + LIVENESS_READ_RESERVE > self.deadline:
            raise ProbeDeferred("HLS liveness deferred: insufficient time to reread playlist")
        try:
            blob, fresh_resolved = self.read(resolved, PLAYLIST_CAP, refresh=True)
        except BudgetExhausted:
            raise
        except (TimeoutError, socket.timeout):
            raise ProbeDeferred("HLS liveness deferred: playlist reread timed out") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise ProbeDeferred("HLS liveness deferred: playlist reread timed out") from None
            raise
        except UpdateError as exc:
            if str(exc) == "probe time limit exceeded":
                raise ProbeDeferred("HLS liveness deferred: playlist reread exceeded probe time") from None
            raise
        if self.bytes >= self.limit or self.attempt_bytes >= MAX_ATTEMPT_BYTES:
            raise BudgetExhausted("media probe budget exhausted")
        if len(blob) >= PLAYLIST_CAP:
            raise ProbeDeferred("HLS liveness deferred: playlist exceeds bounded observation size")
        fresh = blob.decode("utf-8-sig", errors="replace")
        fresh_segments = self.media_segments(fresh, fresh_resolved)
        fresh_target, fresh_sequence = self.liveness_parameters(fresh)
        if fresh_sequence < sequence:
            raise ProbeDeferred("HLS liveness deferred: media sequence reset during observation")
        if fresh_sequence > sequence or frozenset(fresh_segments) != frozenset(segments):
            return fresh, fresh_resolved, fresh_segments
        if fresh_target != target or fresh_sequence != sequence:
            raise ProbeDeferred("HLS liveness deferred: playlist timing changed during observation")
        raise UpdateError("HLS live playlist did not advance within its target update interval")

    def check(self, url):
        if self.isolate:
            return isolated_probe_check(self, url)
        self.attempt_bytes = 0
        self.deadline = min(self.clock() + ATTEMPT_SECONDS, self.global_deadline)
        observed_live = False
        try:
            current = url
            for depth in range(4):
                blob, resolved = self.read(current, PLAYLIST_CAP)
                if self.bytes >= self.limit or self.attempt_bytes >= MAX_ATTEMPT_BYTES:
                    raise BudgetExhausted("media probe budget exhausted")
                text = blob.decode("utf-8-sig", errors="replace")
                if not text.lstrip().startswith("#EXTM3U"):
                    raise UpdateError("not an HLS playlist")
                if "#EXT-X-STREAM-INF:" in text:
                    choices = self.variants(text, resolved)
                    if not choices:
                        raise UpdateError("no variant at or below 1080p")
                    current = choices[0]
                    continue
                if len(blob) >= PLAYLIST_CAP:
                    raise ProbeDeferred("HLS liveness deferred: playlist exceeds bounded observation size")
                text, resolved, segments = self.live_playlist(text, resolved, self.clock())
                observed_live = True
                for line in text.splitlines():
                    if not line.startswith("#EXT-X-KEY:") or "METHOD=NONE" in line:
                        continue
                    # Plain HLS AES-128 is supported by Jellyfin; DRM is not.
                    match = re.search(r'URI="([^"]+)"', line)
                    if "METHOD=AES-128" not in line or ("KEYFORMAT=" in line and 'KEYFORMAT="identity"' not in line) or not match:
                        raise UpdateError("DRM or unsupported encryption")
                    key, _ = self.read(urllib.parse.urljoin(resolved, match.group(1)), 32)
                    if len(key) != 16:
                        raise UpdateError("HLS AES key unavailable")
                data, _ = self.read(segments[-1], 64 * 1024, ranged=True)
                if len(data) < 1024 or data.lstrip().lower().startswith((b"<html", b"<!doctype", b"{\"error")):
                    raise UpdateError("media sample missing or invalid")
                # Preserve the catalog URL; signed variant/segment URLs may expire.
                return {"ok": True, "bytes": self.attempt_bytes, "error": None}
            raise UpdateError("too many nested playlists")
        except BudgetExhausted:
            raise
        except ProbeDeferred as exc:
            return {"ok": False, "deferred": True, "bytes": self.attempt_bytes, "error": redacted_error(exc)}
        except Exception as exc:
            timeout = isinstance(exc, (TimeoutError, socket.timeout)) or (
                isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, (TimeoutError, socket.timeout)))
            if observed_live and (timeout or self.clock() >= self.deadline):
                return {"ok": False, "deferred": True, "bytes": self.attempt_bytes,
                        "error": "HLS liveness deferred: insufficient time for the bounded media sample"}
            return {"ok": False, "bytes": self.attempt_bytes, "error": redacted_error(exc)}


def stop_process(process):
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            pass


def isolated_probe_check(probe, url, command=None, hard_seconds=ATTEMPT_SECONDS):
    """An attempt cannot pin a worker thread in DNS, headers or TLS.

    Reserve the whole child allowance before it starts. Only a validated,
    successful worker report refunds unused bytes. Killed/invalid workers are
    conservatively charged the full grant, including bytes not reported yet.
    """
    remaining = min(hard_seconds, probe.global_deadline - probe.clock())
    if remaining <= 0:
        raise BudgetExhausted("media probe wall-clock budget exhausted")
    grant = probe.budget.reserve(MAX_ATTEMPT_BYTES, count_request=False)
    actual = requests = None
    process = None
    result = {"ok": False, "deferred": True,
              "error": "isolated probe hard deadline or invalid worker report; full allowance charged"}
    started = time.monotonic()
    payload = {"url": url, "limit": grant, "deadline": started + remaining}
    env = dict(os.environ, JF_LIVE_EXPECTED_PARENT=str(os.getpid()))
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(command or [sys.executable, "-B", str(Path(__file__).resolve()), "--probe-worker"],
                                       stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL,
                                       env=env, close_fds=True)
            try:
                process.communicate(json.dumps(payload).encode(),
                    timeout=max(0, remaining - (time.monotonic() - started) - PROCESS_CLEANUP_RESERVE))
            except subprocess.TimeoutExpired:
                stop_process(process)
            else:
                if process.returncode == 0:
                    output.seek(0)
                    body = output.read(8193)
                    if len(body) <= 8192:
                        value = json.loads(body)
                        candidate = value.get("result")
                        count, number = value.get("actual_bytes"), value.get("requests")
                        if (isinstance(candidate, dict) and type(candidate.get("ok")) is bool and
                            type(count) is int and 0 <= count <= grant and
                            type(number) is int and 0 <= number <= 4096 and
                            type(candidate.get("bytes")) is int and candidate["bytes"] == count and
                            ("deferred" not in candidate or type(candidate["deferred"]) is bool) and
                            (candidate.get("error") is None or isinstance(candidate.get("error"), str) and
                             len(candidate["error"]) <= 300 and "http://" not in candidate["error"] and
                             "https://" not in candidate["error"])):
                            actual, requests, result = count, number, candidate
    except Exception:
        # Never log child stdout, stdin, upstream URLs or environment values.
        if process is not None:
            stop_process(process)
    finally:
        if process is not None:
            stop_process(process)
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
        probe.budget.settle_attempt(grant, actual, requests)
    probe.attempt_bytes = grant if actual is None else actual
    return {**result, "bytes": probe.attempt_bytes}


def arm_parent_death_signal():
    """Linux child guard, installed after exec instead of unsafe preexec_fn."""
    expected = os.environ.get("JF_LIVE_EXPECTED_PARENT")
    if not expected or not expected.isdigit():
        raise UpdateError("isolated worker parent identity missing")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise UpdateError("isolated worker parent-death guard unavailable")
    if os.getppid() != int(expected):
        os._exit(124)


def probe_worker():
    arm_parent_death_signal()
    blob = sys.stdin.buffer.read(32769)
    if len(blob) > 32768:
        return 2
    payload = json.loads(blob)
    limit = payload.get("limit")
    if type(limit) is not int or not 0 < limit <= MAX_ATTEMPT_BYTES or not safe_url(payload.get("url", "")):
        return 2
    probe = Probe(limit=limit, global_deadline=min(float(payload["deadline"]), time.monotonic() + ATTEMPT_SECONDS))
    try:
        result = probe.check(payload["url"])
    except BudgetExhausted as exc:
        result = {"ok": False, "deferred": True, "error": redacted_error(exc)}
    result["bytes"] = probe.bytes
    print(json.dumps({"result": result, "actual_bytes": probe.bytes, "requests": probe.requests}))
    return 0


def kill_job_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    stop_process(process)


def supervise_job(command, root, mode, hard_seconds=JOB_SECONDS):
    """No worker threads in this parent: its deadline never waits for join."""
    started = time.monotonic()
    process = subprocess.Popen(command, start_new_session=True, close_fds=True,
                               env=dict(os.environ, JF_LIVE_EXPECTED_PARENT=str(os.getpid())))
    prior_terminate = signal.getsignal(signal.SIGTERM)
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    try:
        return process.wait(timeout=max(0, hard_seconds - (time.monotonic() - started) - PROCESS_CLEANUP_RESERVE))
    except subprocess.TimeoutExpired:
        kill_job_group(process)
        # The worker group is dead. Do not delete staging or modify current:
        # it may already reference a valid generation at the commit boundary.
        error = {"at": iso_now(), "mode": mode, "error": "job hard deadline reached; worker group killed; current generation retained",
                 "hard_deadline_seconds": hard_seconds, "current_symlink_untouched": True}
        try:
            atomic_json(root / "last-error.json", error)
            atomic_json(root / "progress.json", {**error, "phase": "failed"})
        except OSError:
            pass
        return 124
    except BaseException:
        kill_job_group(process)
        raise
    finally:
        signal.signal(signal.SIGTERM, prior_terminate)


def quality_height(quality):
    match = re.search(r"(\d+)[pi]", quality or "")
    return int(match.group(1)) if match else 0


def stream_rank(stream, spec, official_hosts):
    parsed = urllib.parse.urlsplit(stream["url"])
    host = (parsed.hostname or "").lower()
    official = any(host == h or host.endswith("." + h) for h in official_hosts)
    height = quality_height(stream.get("quality"))
    labels = " ".join(stream.get("labels") or []).lower()
    preferred = spec.get("preferred_height", 720 if spec.get("discovery_bucket") == "INTL" else 1080)
    return (not official, parsed.scheme != "https", "hevc" in labels or "h265" in labels,
            not bool(height), abs(height - preferred), stream["url"])


def parse_playlist_metadata(text):
    """Read catalogue text only. No URL in the playlist is opened here."""
    if not text.lstrip().startswith("#EXTM3U"):
        raise UpdateError("English catalogue is not an M3U playlist")
    attributes, title = {}, ""
    for line in text.splitlines():
        if line.startswith("#EXTINF:"):
            attributes = dict(re.findall(r'([\w-]+)="([^"]*)"', line))
            title = line.rsplit(",", 1)[-1].strip()
        elif line and not line.startswith("#"):
            identifier = attributes.get("tvg-id", "")
            channel, separator, feed = identifier.partition("@")
            quality = re.search(r"\b(\d{3,4}[pi])\b", title, re.I)
            if channel and safe_url(line):
                yield {"channel": channel, "feed": feed if separator else None, "url": line,
                       "quality": quality.group(1).lower() if quality else None,
                       "labels": [x for x in ("Geo-blocked", "Not 24/7") if x in title],
                       "_catalogue_language": "eng", "_catalogue": "iptv-org-English",
                       "_logo": attributes.get("tvg-logo", "")}
            attributes, title = {}, ""


def fetch_playlist_metadata(url, limit=MIB):
    with request(url, timeout=30, headers={"Accept-Encoding": "identity"}) as response:
        length = getattr(response, "headers", {}).get("Content-Length")
        if length and int(length) > limit:
            raise UpdateError("English catalogue declared size exceeds limit")
        blob = response.read(limit)
    if len(blob) >= limit:
        raise UpdateError("English catalogue size limit reached")
    return list(parse_playlist_metadata(blob.decode("utf-8-sig")))


def held_source_hashes(spec):
    """Operator-reviewed decoder failures block only exact catalogue URLs."""
    entries = spec.get("validation_holds", [])
    if not isinstance(entries, list):
        raise UpdateError("validation_holds must be a list")
    held = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"source_sha256", "reason", "checked_on"}:
            raise UpdateError("validation hold requires exactly source_sha256, reason and checked_on")
        digest, reason, checked = entry["source_sha256"], entry["reason"], entry["checked_on"]
        if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise UpdateError("validation hold source_sha256 must contain 64 hexadecimal characters")
        if not isinstance(reason, str) or not reason.strip():
            raise UpdateError("validation hold reason must be nonempty text")
        if not isinstance(checked, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", checked):
            raise UpdateError("validation hold checked_on must be an ISO date")
        try:
            dt.date.fromisoformat(checked)
        except ValueError:
            raise UpdateError("validation hold checked_on must be a valid ISO date") from None
        digest = digest.lower()
        if digest in held:
            raise UpdateError("validation hold contains a duplicate source_sha256")
        held.add(digest)
    return held


def load_candidates(specs, english_playlist_url=None):
    # Reject a malformed hold before downloading any catalogue metadata.
    holds = [held_source_hashes(spec) for spec in specs]
    wanted = {spec["channel"] for spec in specs}
    metadata_errors = []
    def fetch(kind):
        try:
            return fetch_json(API.format(kind))
        except Exception as exc:
            metadata_errors.append(kind + ": " + redacted_error(exc))
            return []
    channels = {c["id"]: c for c in fetch("channels") if c["id"] in wanted}
    feeds = collections.defaultdict(dict)
    for f in fetch("feeds"):
        if f.get("channel") in wanted:
            feeds[f["channel"]][f["id"]] = f
    logos = {}
    for logo in fetch("logos"):
        if logo.get("channel") in wanted and safe_url(logo.get("url", "")):
            key = (logo["channel"], logo.get("feed"))
            if key not in logos or logo.get("in_use"):
                logos[key] = logo["url"]
    streams = collections.defaultdict(list)
    for s in fetch("streams"):
        if s.get("channel") in wanted:
            streams[s["channel"]].append(s)
    if english_playlist_url:
        try:
            for stream in fetch_playlist_metadata(english_playlist_url):
                if stream["channel"] in wanted:
                    duplicate = next((row for row in streams[stream["channel"]]
                                      if (row.get("feed"), row.get("url")) == (stream.get("feed"), stream["url"])), None)
                    if duplicate is None:
                        streams[stream["channel"]].append(stream)
                    else:
                        # Keep API header requirements while enriching language
                        # and logo evidence from the English catalogue.
                        for key in ("_catalogue_language", "_catalogue", "_logo"):
                            if stream.get(key):
                                duplicate[key] = stream[key]
        except Exception as exc:
            metadata_errors.append("English playlist: " + redacted_error(exc))
    result = []
    for spec, held in zip(specs, holds):
        channel = spec["channel"]
        meta = channels.get(channel)
        problems = list(metadata_errors)
        blocked = bool(meta and (meta.get("is_nsfw") or meta.get("closed")))
        if not meta:
            problems.append("channel metadata ID unavailable")
        if blocked:
            problems.append("channel is closed or excluded by catalogue policy")
        preferred_language = spec.get("language")
        options = []
        seen = set()
        for s in streams[channel]:
            if blocked:
                continue
            url = s.get("url", "")
            if not safe_url(url):
                problems.append("source URL or required per-stream headers unsupported")
                continue
            if hashlib.sha256(url.encode()).hexdigest() in held:
                problems.append("held after bounded decoder failure; awaiting replacement or manual revalidation")
                continue
            if s.get("referrer") or s.get("user_agent"):
                problems.append("source URL or required per-stream headers unsupported")
                continue
            key = (s.get("feed"), url)
            if key in seen:
                continue
            if quality_height(s.get("quality")) > 1080:
                problems.append("source catalogue quality exceeds 1080p")
                continue
            f = feeds[channel].get(s.get("feed"), {})
            if preferred_language and preferred_language not in f.get("languages", []) and s.get("_catalogue_language") != preferred_language:
                problems.append("feed language unavailable or does not match preference")
                continue
            if spec.get("feeds") and s.get("feed") not in spec["feeds"]:
                problems.append("source feed does not match pinned feed")
                continue
            if not meta and not (spec.get("allow_playlist_metadata") and s.get("_catalogue_language") == preferred_language):
                continue
            seen.add(key)
            s = dict(s)
            s["_feed_rank"] = (not f.get("is_main", False), s.get("feed") or "")
            options.append(s)
        # New channels may try another compatible feed if the preferred feed
        # fails. Publication still contains one feed, with its full suffix.
        options.sort(key=lambda s: (stream_rank(s, spec, spec.get("official_hosts", []))[:2], s["_feed_rank"],
                                    stream_rank(s, spec, spec.get("official_hosts", []))[2:]))
        if options:
            selected_feed = options[0].get("feed")
        elif (held and isinstance(spec.get("feeds"), list) and len(spec["feeds"]) == 1 and
              isinstance(spec["feeds"][0], str) and spec["feeds"][0]):
            selected_feed = spec["feeds"][0]
        else:
            selected_feed = None
        result.append({"channel_id": channel, "feed": selected_feed,
                       "id": channel + ("@" + selected_feed if selected_feed else ""),
                       "name": spec.get("name", (meta or {}).get("name", channel)), "region": spec["region"],
                       "epg_region": spec.get("epg_region", spec["region"]),
                       "discovery_bucket": spec.get("discovery_bucket", spec["region"]),
                       "provenance_status": spec.get("provenance_status", "existing-catalogue"),
                       "group": spec.get("group", spec["region"]),
                       "logo": logos.get((channel, selected_feed), logos.get((channel, None), "")) or
                               next((s.get("_logo", "") for s in options if s.get("_logo")), ""),
                       "aliases": spec.get("aliases", []), "epg_ids": spec.get("epg_ids", []),
                       "epg_by_feed": spec.get("epg_by_feed", {}),
                       "catalogue_diagnostics": sorted(set(problems)),
                       "candidates": options})
    return result


def select_channels(candidates, previous, probe, now, progress=None, source_cursors=None):
    day = now.astimezone(UTC).date().isoformat()
    old = {c["channel_id"]: c for c in previous}
    selected, failures = [], []
    for processed, candidate in enumerate(candidates, 1):
        if len(selected) >= MAX_CHANNELS:
            break
        prior = old.get(candidate["channel_id"])
        options = list(candidate["candidates"])
        cursor = (source_cursors or {}).get(candidate["channel_id"], 0)
        if prior:
            # Retain the prior identity and feed; never map a different regional
            # feed onto its guide after an API feed-list change.
            candidate = {**candidate, **{k: prior[k] for k in ("id", "feed")}}
            options = [s for s in options if s.get("feed") == prior.get("feed")]
            options = [s for s in options if s["url"] != prior["url"]]
        if options:
            offset = cursor % len(options)
            options = options[offset:] + options[:offset]
        if prior:
            options.insert(0, {"url": prior["url"], "feed": prior.get("feed"), "quality": prior.get("quality")})
        seen, success, errors, deferred = set(), None, [], False
        attempted = 0
        for s in options:
            if s["url"] in seen:
                continue
            if attempted >= 2:
                break
            seen.add(s["url"])
            attempted += 1
            try:
                check = probe.check(s["url"])
            except BudgetExhausted:
                deferred = True
                break
            if check["ok"]:
                success = s
                break
            errors.append(check["error"])
            if check.get("deferred"):
                deferred = True
                if prior and s["url"] == prior["url"]:
                    # A bounded observation is not evidence the established
                    # source failed. Keep it rather than replacing it with a
                    # shorter-target source that merely fits this probe.
                    break
        if source_cursors is not None:
            if success:
                source_cursors[candidate["channel_id"]] = 0
            elif attempted and (not prior or attempted > 1):
                source_cursors[candidate["channel_id"]] = cursor + 1
        if not options:
            errors = candidate.get("catalogue_diagnostics") or ["no eligible catalogue sources for this channel/feed"]
        if deferred and not errors:
            errors = ["probe shared budget or phase deadline exhausted; verification deferred"]
        clean = {k: v for k, v in candidate.items() if k != "candidates"}
        if prior and not clean.get("logo"):
            clean["logo"] = prior.get("logo", "")
        if success:
            if not prior:
                clean["feed"] = success.get("feed")
                clean["id"] = clean["channel_id"] + ("@" + clean["feed"] if clean["feed"] else "")
            clean.update(clean.get("epg_by_feed", {}).get(clean.get("feed"), {}))
            clean.update(url=success["url"], quality=success.get("quality"), failure_streak=0,
                         last_check_day=day, last_success=now.isoformat(), health="pass",
                         last_probe_attempts=attempted)
            selected.append(clean)
        elif prior:
            streak = prior.get("failure_streak", 0)
            if not deferred and prior.get("last_check_day") != day:
                streak += 1
            clean = dict(prior)
            clean.update(failure_streak=streak, health="deferred" if deferred else "failed-kept")
            if not deferred:
                clean["last_check_day"] = day
            if streak < 3:
                selected.append(clean)
            failures.append({"id": clean["id"], "errors": errors, "failure_streak": streak,
                             "attempted_sources": attempted,
                             "action": "deferred" if deferred else "removed" if streak >= 3 else "retained"})
        else:
            failures.append({"id": clean["id"], "errors": errors,
                             "attempted_sources": attempted,
                             "action": "deferred" if deferred else "not-added"})
        if progress:
            progress({"phase": "probe", "processed": processed, "total": len(candidates),
                      "last_channel": clean["id"], "selected": len(selected),
                      "verified": sum(c.get("health") == "pass" for c in selected),
                      "media_probe_bytes": probe.bytes})
    # An API omission is not evidence that an existing stream failed: check it.
    represented = {c["channel_id"] for c in candidates}
    for prior in previous:
        if prior["channel_id"] in represented or len(selected) >= MAX_CHANNELS:
            continue
        extra, extra_failures = select_channels([{**prior, "candidates": []}], [prior], probe, now,
                                                source_cursors=source_cursors)
        selected.extend(extra)
        failures.extend(extra_failures)
    return selected, failures


def assign_channel_numbers(channels, previous, next_number=1):
    """Migrate legacy state in snapshot order; never renumber surviving IDs."""
    old_numbers, used = {}, set()
    for index, channel in enumerate(previous, 1):
        number = channel.get("number", index)
        if not isinstance(number, int) or number <= 0 or number in used:
            number = max(used, default=0) + 1
        old_numbers[channel["channel_id"]] = number
        used.add(number)
    next_number = max(next_number, max(used, default=0) + 1)
    result = []
    for channel in channels:
        row = dict(channel)
        number = old_numbers.get(row["channel_id"])
        if number is None:
            number, next_number = next_number, next_number + 1
        row["number"] = number
        result.append(row)
    return sorted(result, key=lambda row: row["number"]), next_number


def schedule_channels(candidates, previous, probe, now, progress=None, state=None, workers=PROBE_WORKERS):
    """Reserve old slots, then fairly discover new feeds under one hard budget.

    Each worker owns its Probe/attempt counters. Only this coordinator writes
    progress, selected channels and the state committed with the generation.
    """
    workers = min(PROBE_WORKERS, max(1, workers))
    state = state if state is not None else {}
    cursors = state.setdefault("source_cursors", {})
    by_id = {row["channel_id"]: row for row in candidates}
    old_ids = {row["channel_id"] for row in previous}
    old_jobs = [by_id.get(row["channel_id"], {**row, "candidates": []}) for row in previous]
    new_jobs = [row for row in candidates if row["channel_id"] not in old_ids]
    old_cursor = state.get("health_cursor", 0)
    if old_jobs:
        offset = old_cursor % len(old_jobs)
        old_jobs = old_jobs[offset:] + old_jobs[:offset]
    buckets = collections.defaultdict(list)
    for row in new_jobs:
        buckets[row.get("discovery_bucket", row["region"])].append(row)
    new_jobs = []
    for bucket in sorted(buckets, key=lambda key: (key != "INTL", key)):
        rows = buckets[bucket]
        cursor = state.setdefault("discovery_cursors", {}).get(bucket, 0) % len(rows)
        new_jobs.extend(rows[cursor:] + rows[:cursor])
    old_results, new_results, failures, unstarted_old = {}, [], [], []
    processed = 0
    total = len(old_jobs) + len(new_jobs)
    old_by_id = {row["channel_id"]: row for row in previous}

    def one(candidate, deadline, is_old):
        child = probe.fork(deadline)
        local_cursor = {candidate["channel_id"]: cursors.get(candidate["channel_id"], 0)}
        rows, errors = select_channels([candidate], [old_by_id[candidate["channel_id"]]] if is_old else [],
                                      child, now, source_cursors=local_cursor)
        return rows, errors, local_cursor

    def phase(jobs, deadline, is_old, capacity=MAX_CHANNELS):
        nonlocal processed
        pending, index, accepted = {}, 0, 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="jf-live-probe") as pool:
            while pending or index < len(jobs):
                while (index < len(jobs) and len(pending) < workers and
                       probe.clock() < deadline and accepted + len(pending) < capacity and
                       probe.bytes < min(probe.limit, probe.budget.phase_limit)):
                    candidate = jobs[index]
                    index += 1
                    pending[pool.submit(one, candidate, deadline, is_old)] = candidate
                if not pending:
                    break
                done, _ = concurrent.futures.wait(pending, timeout=0.25,
                                                  return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    candidate = pending.pop(future)
                    rows, errors, source_cursor = future.result()
                    cursors.update(source_cursor)
                    failures.extend(errors)
                    if is_old:
                        old_results[candidate["channel_id"]] = rows[0] if rows else None
                        state["health_cursor"] = state.get("health_cursor", old_cursor) + 1
                    else:
                        new_results.extend(rows)
                        accepted += len(rows)
                        bucket = candidate.get("discovery_bucket", candidate["region"])
                        state["discovery_cursors"][bucket] = state["discovery_cursors"].get(bucket, 0) + 1
                    processed += 1
                    if progress:
                        progress({"phase": "probe", "probe_pool": "health" if is_old else "discovery",
                                  "processed": processed, "total": total, "last_channel": candidate["id"],
                                  "selected": sum(row is not None for row in old_results.values()) + len(new_results),
                                  "media_probe_bytes": probe.bytes})
        return jobs[index:]

    # Six minutes / 8MiB protects a four-minute discovery opportunity. Early
    # completion donates unused time and bytes to discovery automatically.
    probe.budget.set_phase_limit(min(probe.limit, 8 * MIB))
    health_deadline = min(probe.global_deadline - 4 * 60, probe.clock() + 6 * 60)
    unstarted_old = phase(old_jobs, health_deadline, True)
    retained = [old_results.get(row["channel_id"], {**row, "health": "deferred"})
                for row in previous]
    retained = [row for row in retained if row is not None]
    probe.budget.set_phase_limit(probe.limit)
    unstarted_new = phase(new_jobs, probe.global_deadline, False, max(0, MAX_CHANNELS - len(retained)))
    # If discovery ends early, unused soft allocation may finish old jobs that
    # were never started. An already-attempted source is never probed twice.
    if unstarted_old and probe.clock() < probe.global_deadline and probe.bytes < probe.limit:
        remaining_old = phase(unstarted_old, probe.global_deadline, True)
        unstarted_old = remaining_old
        retained = [old_results.get(row["channel_id"], {**row, "health": "deferred"}) for row in previous]
        retained = [row for row in retained if row is not None]
    for candidate in unstarted_old + unstarted_new:
        failures.append({"id": candidate["id"], "errors": ["scheduler capacity, shared budget or deadline; not verified this round"],
                         "action": "deferred", "attempted_sources": 0})
    new_order = {row["channel_id"]: index for index, row in enumerate(new_jobs)}
    new_results.sort(key=lambda row: new_order[row["channel_id"]])
    selected, next_number = assign_channel_numbers(retained + new_results, previous,
                                                  state.get("next_channel_number", 1))
    state["next_channel_number"] = next_number
    return selected[:MAX_CHANNELS], failures


def interleave_candidates(candidates):
    """Give each region a first chance before trying many failed channels."""
    buckets = collections.defaultdict(collections.deque)
    priority = {"RTHKTV31.hk": 0, "CGTN.cn": 1, "NHKWorldJapan.jp": 2,
                "France24.fr": 3, "RTHKTV32.hk": 4}
    for candidate in sorted(enumerate(candidates), key=lambda pair: (
            pair[1]["region"], priority.get(pair[1]["channel_id"], 100 + pair[0]))):
        buckets[candidate[1]["region"]].append(candidate[1])
    ordered = []
    while any(buckets.values()):
        for region in ("CN", "HK", "TW"):
            if buckets[region]:
                ordered.append(buckets[region].popleft())
        for region in sorted(set(buckets) - {"CN", "HK", "TW"}):
            if buckets[region]:
                ordered.append(buckets[region].popleft())
    return ordered


def apply_mapping_config(channels, specs):
    """Apply corrected mapping data during EPG-only runs too, without probing."""
    configured = {spec["channel"]: spec for spec in specs}
    result = []
    for channel in channels:
        copy = dict(channel)
        spec = configured.get(channel["channel_id"])
        if spec:
            for key in ("region", "epg_region", "discovery_bucket", "group", "aliases", "epg_ids", "epg_by_feed", "provenance_status"):
                if key in spec:
                    copy[key] = spec[key]
            copy.update(copy.get("epg_by_feed", {}).get(copy.get("feed"), {}))
        result.append(copy)
    return result


def parse_xmltv_time(value):
    if not value:
        return None
    match = re.fullmatch(r"(\d{14})\s*([+-]\d{4}|Z)", value)
    if not match:
        return None
    try:
        return dt.datetime.strptime(match.group(1) + ("+0000" if match.group(2) == "Z" else match.group(2)), "%Y%m%d%H%M%S%z")
    except ValueError:
        return None


def verified_xmltv_time(value, rule):
    """Apply only an audited, source-ID-scoped clock policy.

    Some epg.pw entries serialize local HK/CN clock readings with +0000.
    A +0800 entry is already correct and must never be shifted twice.
    Unverified source clocks intentionally produce no programmes.
    """
    parsed = parse_xmltv_time(value)
    if parsed is None or not rule:
        return None
    policy = rule.get("policy")
    if policy == "local_utc_plus_8_mislabeled_as_utc":
        offset = parsed.utcoffset()
        if offset == dt.timedelta(0):
            return parsed.replace(tzinfo=HK).astimezone(UTC)
        if offset == dt.timedelta(hours=8):
            return parsed.astimezone(UTC)
        return None
    if policy == "declared_offset_verified":
        return parsed.astimezone(UTC)
    if policy == "local_timezone_mislabeled_as_utc":
        # Only explicitly audited source rules may use this policy. Reject
        # ambiguous/nonexistent DST clock readings rather than guessing fold.
        try:
            zone = ZoneInfo(rule["timezone"])
        except (KeyError, ZoneInfoNotFoundError):
            return None
        if parsed.utcoffset() != dt.timedelta(0):
            return parsed.astimezone(UTC) if parsed.astimezone(zone).utcoffset() == parsed.utcoffset() else None
        wall = parsed.replace(tzinfo=None)
        first, second = wall.replace(tzinfo=zone, fold=0), wall.replace(tzinfo=zone, fold=1)
        if first.utcoffset() != second.utcoffset():
            return None
        absolute = first.astimezone(UTC)
        return absolute if absolute.astimezone(zone).replace(tzinfo=None) == wall else None
    return None


def resolve_mapping(channels, catalogue):
    """Exact, region-scoped aliases. Ambiguous aliases never produce a match."""
    by_name = collections.defaultdict(set)
    for source_id, names in catalogue.items():
        for name in names:
            by_name[normalize(name)].add(source_id)
    mapping = {}
    for channel in channels:
        aliases = {normalize(alias) for alias in channel.get("aliases", [])}
        explicit = {str(v) for v in channel.get("epg_ids", []) if str(v) in catalogue
                    and aliases.intersection(normalize(n) for n in catalogue[str(v)])}
        matches = explicit or set().union(*(by_name.get(normalize(alias), set()) for alias in channel.get("aliases", [])))
        if len(matches) == 1:
            source_id = next(iter(matches))
            mapping.setdefault(source_id, []).append(channel["id"])
    return mapping


class CountedReader:
    def __init__(self, source, limit):
        self.source = source
        self.limit = limit
        self.bytes = 0

    def read(self, size=-1):
        if time.monotonic() >= RUN_DEADLINE:
            raise UpdateError("update wall-clock limit exceeded")
        allowed = min(size if size >= 0 else 64 * 1024, self.limit - self.bytes + 1)
        chunk = self.source.read(allowed)
        self.bytes += len(chunk)
        if self.bytes > self.limit:
            raise UpdateError("XMLTV input size limit exceeded")
        return chunk


def filter_epg(source, channels, programmes, now, time_rules=None, region=None):
    """Stream a regional XMLTV, keep only reliable maps and 72h programmes."""
    root = None
    catalogue, mapping = {}, {}
    counts = collections.Counter()
    horizon = now + dt.timedelta(hours=72)
    time_rules = time_rules or {}
    region = region or (channels[0]["region"] if channels else "")
    for event, elem in ET.iterparse(CountedReader(source, 256 * MIB), events=("start", "end")):
        if root is None and event == "start":
            root = elem
            if root.tag != "tv":
                raise UpdateError("XMLTV root is not tv")
        if event != "end":
            continue
        if elem.tag == "channel":
            catalogue[elem.attrib.get("id", "")] = [e.text or "" for e in elem.findall("display-name")]
            elem.clear()
            root.clear()
        elif elem.tag == "programme":
            if not mapping:
                mapping = resolve_mapping(channels, catalogue)
            source_id = elem.attrib.get("channel")
            targets = mapping.get(source_id, [])
            rule = time_rules.get(region + ":" + (source_id or ""))
            start, stop = verified_xmltv_time(elem.get("start"), rule), verified_xmltv_time(elem.get("stop"), rule)
            if targets and start and stop and stop > start and stop > now and start < horizon and elem.find("title") is not None:
                elem.set("start", start.strftime("%Y%m%d%H%M%S +0000"))
                elem.set("stop", stop.strftime("%Y%m%d%H%M%S +0000"))
                for target in targets:
                    elem.set("channel", target)
                    programmes.write(ET.tostring(elem, encoding="utf-8") + b"\n")
                    counts[target] += 1
            elem.clear()
            root.clear()
    if root is None:
        raise UpdateError("empty XMLTV")
    return counts, mapping or resolve_mapping(channels, catalogue)


def build_guide(channels, destination, now, opener=request, progress=None, time_rules=None):
    regions = collections.defaultdict(list)
    for channel in channels:
        region = channel.get("epg_region", channel["region"])
        if region in SUPPORTED_EPG_REGIONS and (channel.get("aliases") or channel.get("epg_ids")):
            regions[region].append(channel)
    counts, mappings, errors = collections.Counter(), {}, []
    spool_path = destination.with_suffix(".programmes")
    with spool_path.open("wb") as spool:
        for region, regional in regions.items():
            if progress:
                progress({"phase": "epg", "region": region, "selected": len(channels)})
            # Each region is fetched exactly once per run. A failed partial XML
            # document must not leak its programmes into the published guide.
            region_path = destination.with_suffix("." + region + ".tmp")
            try:
                url = "https://epg.pw/xmltv/epg_{}.xml.gz".format(region)
                with opener(url, timeout=45) as response, gzip.GzipFile(fileobj=CountedReader(response, 64 * MIB)) as source, region_path.open("wb") as region_spool:
                    regional_counts, regional_mapping = filter_epg(source, regional, region_spool, now, time_rules, region)
                counts.update(regional_counts)
                for source_id, targets in regional_mapping.items():
                    for target in targets:
                        mappings[target] = {"region": region, "source_id": source_id}
                with region_path.open("rb") as part:
                    shutil.copyfileobj(part, spool)
            except Exception as exc:
                errors.append({"region": region, "error": redacted_error(exc)})
            finally:
                region_path.unlink(missing_ok=True)
    if errors:
        spool_path.unlink(missing_ok=True)
        raise UpdateError("regional XMLTV fetch failed: " + ",".join(e["region"] + "=" + e["error"] for e in errors))
    if not counts and mappings and any(time_rules and time_rules.get(m["region"] + ":" + m["source_id"])
                                      for m in mappings.values()):
        spool_path.unlink(missing_ok=True)
        raise UpdateError("no reliable future programmes; retaining last good generation")
    with destination.open("wb") as output:
        output.write(b'<?xml version="1.0" encoding="utf-8"?>\n<tv generator-info-name="ServiceHost Jellyfin Live">\n')
        for channel in channels:
            elem = ET.Element("channel", {"id": channel["id"]})
            ET.SubElement(elem, "display-name").text = channel["name"]
            if channel.get("logo"):
                ET.SubElement(elem, "icon", {"src": channel["logo"]})
            output.write(ET.tostring(elem, encoding="utf-8") + b"\n")
        with spool_path.open("rb") as source:
            shutil.copyfileobj(source, output)
        output.write(b"</tv>\n")
    spool_path.unlink()
    return counts, mappings, errors


def current_programme_channels(path, now):
    active = set()
    root = None
    for event, elem in ET.iterparse(path, events=("start", "end")):
        if root is None:
            root = elem
        if event == "end" and elem.tag == "programme":
            start, stop = parse_xmltv_time(elem.get("start")), parse_xmltv_time(elem.get("stop"))
            if start and stop and start <= now < stop:
                active.add(elem.get("channel"))
            elem.clear()
            root.clear()
    return active


def m3u_attribute(value):
    return str(value).replace('"', "'").replace("\r", " ").replace("\n", " ")


def write_m3u(channels, path):
    with path.open("w", encoding="utf-8") as output:
        output.write('#EXTM3U x-tvg-url="/livetv/current/guide.xml"\n')
        for fallback_number, channel in enumerate(channels, 1):
            number = channel.get("number", fallback_number)
            attrs = {"tvg-id": channel["id"], "tvg-name": channel["name"], "tvg-chno": number,
                     "tvg-logo": channel.get("logo", ""), "group-title": channel["group"]}
            output.write("#EXTINF:-1 " + " ".join('{}="{}"'.format(k, m3u_attribute(v)) for k, v in attrs.items()) + "," + m3u_attribute(channel["name"]) + "\n")
            output.write(channel["url"] + "\n")


def atomic_json(path, value):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)


def publish(root, staging):
    relative = str(staging.relative_to(root))
    prior = os.readlink(root / "current") if (root / "current").is_symlink() else None
    if prior:
        temp = root / ".last-good.tmp"
        temp.unlink(missing_ok=True)
        temp.symlink_to(prior)
        os.replace(temp, root / "last-good")
    temp = root / ".current.tmp"
    temp.unlink(missing_ok=True)
    temp.symlink_to(relative)
    os.replace(temp, root / "current")
    # Retain published generations for diagnosis and rollback; never delete
    # current or last-good, even if generation naming/order differs.
    protected = {(root / "current").resolve(), (root / "last-good").resolve()}
    old = sorted((root / "generations").iterdir(), reverse=True)
    for path in old[4:]:
        if path.resolve() not in protected and path.is_dir():
            shutil.rmtree(path)


def update(root, config, mode):
    global RUN_DEADLINE
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".update.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 75
        started = time.monotonic()
        RUN_DEADLINE = started + 15 * 60
        now = dt.datetime.now(UTC)
        previous = []
        scheduler_state = {}
        if (root / "current" / "state.json").is_file():
            prior_state = json.loads((root / "current" / "state.json").read_text())
            previous = prior_state["channels"]
            scheduler_state = prior_state.get("scheduler", {})
        generation = now.strftime("%Y%m%dT%H%M%SZ") + "-" + str(os.getpid())
        staging = root / "generations" / generation
        staging.mkdir(parents=True)
        probe = Probe(global_deadline=started + 10 * 60, isolate=True)
        def progress(value):
            atomic_json(root / "progress.json", {"at": iso_now(), "mode": mode,
                        "elapsed_seconds": round(time.monotonic() - started, 1),
                        "media_probe_bytes": probe.bytes, **value})
        def timeout_handler(signum, frame):
            raise UpdateError("update wall-clock limit exceeded")
        prior_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(15 * 60)
        try:
            progress({"phase": "metadata" if mode == "full" else "starting"})
            configuration = json.loads(config.read_text(encoding="utf-8"))
            specs = configuration["channels"]
            if not isinstance(specs, list) or not specs:
                raise UpdateError("empty channel configuration")
            if mode == "full":
                candidates = load_candidates(specs, configuration.get("sources", {}).get("english_playlist"))
                selected, failures = schedule_channels(candidates, previous, probe, now, progress, scheduler_state)
            else:
                if not previous:
                    raise UpdateError("EPG-only run requires a successful full update")
                selected, failures = previous, []
                selected, scheduler_state["next_channel_number"] = assign_channel_numbers(
                    selected, previous, scheduler_state.get("next_channel_number", 1))
            if not selected:
                raise UpdateError("no verified channels; retaining last good generation")
            selected = apply_mapping_config(selected, specs)
            time_rules = configuration.get("epg_time_rules", {})
            counts, mappings, epg_errors = build_guide(selected, staging / "guide.xml", now, progress=progress,
                                                       time_rules=time_rules)
            active_programmes = current_programme_channels(staging / "guide.xml", now)
            def time_rule_for(channel_id):
                mapping = mappings.get(channel_id)
                return time_rules.get(mapping["region"] + ":" + mapping["source_id"]) if mapping else None
            write_m3u(selected, staging / "channels.m3u")
            # URLs stay in private state/M3U only. Public status has no tokens.
            atomic_json(staging / "state.json", {"channels": selected, "scheduler": scheduler_state})
            status = {"updated_at": now.isoformat(), "timezone": "Etc/UTC", "mode": mode,
                      "generation": generation, "channel_count": len(selected),
                      "playable_verified_this_run": sum(c.get("health") == "pass" for c in selected) if mode == "full" else None,
                      "epg_channel_count": sum(bool(counts[c["id"]]) for c in selected),
                      "epg_mapped_channel_count": len(mappings),
                      "epg_time_verified_channel_count": sum(bool(time_rule_for(c["id"])) for c in selected),
                      "current_programme_channel_count": len(active_programmes),
                      "epg_coverage_percent": round(100 * sum(bool(counts[c["id"]]) for c in selected) / len(selected), 1),
                      "programme_count": sum(counts.values()), "epg_window_hours": 72,
                      "media_probe_bytes": probe.bytes, "media_probe_limit_bytes": probe.limit,
                      "media_probe_requests": probe.requests, "failures": failures, "epg_errors": epg_errors,
                      "media_probe_conservative_charged_bytes": probe.budget.conservative_bytes,
                      "media_probe_unreported_attempts": probe.budget.unreported_attempts,
                      "media_probe_requests_are_lower_bound": bool(probe.budget.unreported_attempts),
                      "media_probe_accounting": "bounded response-body bytes; unreported child attempts charged their entire reserved allowance",
                      "probe_workers": PROBE_WORKERS, "probe_attempt_seconds": ATTEMPT_SECONDS,
                      "new_channel_count": sum(c["channel_id"] not in {p["channel_id"] for p in previous} for c in selected),
                      "deferred_channel_count": sum(f["action"] == "deferred" for f in failures),
                      "duration_seconds": round(time.monotonic() - started, 1),
                      "channels": [{"id": c["id"], "name": c["name"], "health": c.get("health"),
                                    "number": c.get("number"), "region": c["region"],
                                    "epg_region": c.get("epg_region", c["region"]),
                                    "group": c.get("group"), "provenance_status": c.get("provenance_status", "existing-catalogue"),
                                    "quality": c.get("quality"),
                                    "source_url_sha256": hashlib.sha256(c["url"].encode()).hexdigest(),
                                    "failure_streak": c.get("failure_streak", 0), "programme_count": counts[c["id"]],
                                    "epg_mapping": mappings.get(c["id"]),
                                    "current_programme_available": c["id"] in active_programmes,
                                    "epg_time_policy": (time_rule_for(c["id"]) or {}).get("policy", "unverified-withheld"),
                                    "epg_status": "mapped-time-verified" if counts[c["id"]] else
                                    "time-unverified-programmes-withheld" if c["id"] in mappings and not time_rule_for(c["id"]) else
                                    "no-reliable-mapping-configured" if c.get("epg_region", c["region"]) not in SUPPORTED_EPG_REGIONS else
                                    "missing-programme-data"} for c in selected]}
            atomic_json(staging / "status.json", status)
            publish(root, staging)
            progress({"phase": "complete", "generation": generation, "selected": len(selected),
                      "epg_channels": sum(bool(counts[c["id"]]) for c in selected)})
            (root / "last-error.json").unlink(missing_ok=True)
            print(json.dumps({k: status[k] for k in ("generation", "channel_count", "epg_channel_count", "media_probe_bytes")}, ensure_ascii=False))
            return 0
        except Exception as exc:
            # A diagnostic/logging failure after the atomic commit must never
            # remove the generation now referenced by current.
            if (root / "current").is_symlink() and (root / "current").resolve() == staging.resolve():
                return 0
            atomic_json(root / "last-error.json", {"at": iso_now(), "mode": mode,
                        "error": redacted_error(exc), "media_probe_bytes": probe.bytes,
                        "duration_seconds": round(time.monotonic() - started, 1)})
            shutil.rmtree(staging, ignore_errors=True)
            print("update failed: " + redacted_error(exc), file=sys.stderr)
            progress({"phase": "failed", "error": redacted_error(exc)})
            return 1
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, prior_handler)
            RUN_DEADLINE = float("inf")


def main():
    if sys.argv[1:] == ["--probe-worker"]:
        return probe_worker()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("full", "epg"), required=True)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("channels.json"))
    parser.add_argument("--job-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.job_worker:
        arm_parent_death_signal()
        return update(args.root, args.config, args.mode)
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--root", str(args.root),
               "--mode", args.mode, "--config", str(args.config), "--job-worker"]
    return supervise_job(command, args.root, args.mode)


if __name__ == "__main__":
    sys.exit(main())
