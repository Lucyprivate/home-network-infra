#!/usr/bin/env python3
"""Pull the newest completed VM100 backup over pinned SSH; never prune PVE.

Only manifest-owned local copies are eligible for local retention. Configuration,
credentials, backup payloads and SSH diagnostics are never printed to the log.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid

TOOL = "openwrt-vm100-backup-pull"
MANIFEST = ".vm100-backup-pull.json"
LOCK = ".vm100-backup-pull.lock"
MAX_BYTES = 6 * 1024**3
MIN_FREE_BYTES = 1024**3
KEEP = 14
REMOTE_TIMEOUT = 900
NAME_RE = re.compile(r"vzdump-qemu-100-(\d{4}_\d{2}_\d{2}-\d{2}_\d{2}_\d{2})\.vma\.zst\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")


class PullError(RuntimeError):
    pass


class PullInterrupted(PullError):
    def __init__(self, signum):
        super().__init__("Backup pull interrupted")
        self.signum = signum


def valid_name(name):
    match = NAME_RE.fullmatch(name) if isinstance(name, str) else None
    if not match:
        return False
    try:
        dt.datetime.strptime(match.group(1), "%Y_%m_%d-%H_%M_%S")
    except ValueError:
        return False
    return True


def integer(value, minimum=0, maximum=None):
    return type(value) is int and value >= minimum and (maximum is None or value <= maximum)


def validate_metadata(meta):
    if not isinstance(meta, dict) or set(meta) != {"name", "bytes", "sha256", "stamp", "log_stamp"}:
        raise PullError("Remote backup metadata is invalid")
    if not valid_name(meta["name"]) or not integer(meta["bytes"], 1, MAX_BYTES):
        raise PullError("Remote backup name or size is unsupported")
    if not isinstance(meta["sha256"], str) or not SHA_RE.fullmatch(meta["sha256"]):
        raise PullError("Remote backup checksum is invalid")
    for field in ("stamp", "log_stamp"):
        value = meta[field]
        if not isinstance(value, list) or len(value) != 5 or not all(integer(x) for x in value):
            raise PullError("Remote backup identity is invalid")
    if meta["stamp"][2] != meta["bytes"]:
        raise PullError("Remote backup metadata size differs")
    return meta


# The remote program has fixed storage paths and no write operations. The only
# variable passed to copy is metadata already checked against the strict schema.
# Functions remain separately callable by local fixture tests.
REMOTE_PROGRAM = r'''
import datetime as dt
import hashlib, json, os, re, stat, sys
MAX_BYTES = 6 * 1024**3
ROOT = "/var/lib/vz/dump"
NAME_RE = re.compile(r"vzdump-qemu-100-(\d{4}_\d{2}_\d{2}-\d{2}_\d{2}_\d{2})\.vma\.zst\Z")
def valid_name(name):
    m = NAME_RE.fullmatch(name)
    if not m: return False
    try: dt.datetime.strptime(m.group(1), "%Y_%m_%d-%H_%M_%S")
    except ValueError: return False
    return True
def stamp(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
def complete_log(text):
    started = re.search(r"\bStarting Backup of VM 100(?:\s|\()", text)
    finished = re.search(r"\bFinished Backup of VM 100(?:\s|\()", text)
    failed = re.search(r"(?:\bERROR\b|\bABORTED\b|\bfailed\b|\bfailure\b)", text, re.I)
    return bool(started and finished and finished.start() > started.start() and not failed)
def read_log(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024**2:
            raise ValueError("Invalid backup log")
        raw = f.read(1024**2 + 1)
        after = os.fstat(f.fileno())
        if len(raw) != before.st_size or stamp(before) != stamp(after):
            raise ValueError("Backup log changed")
        if not complete_log(raw.decode("utf-8", "strict")):
            raise ValueError("Backup is not complete")
        return stamp(after)
def being_written(s):
    # Refuse a backup held by any currently visible writable file descriptor.
    # Inaccessible /proc evidence fails closed instead of assuming it is idle.
    for pid in os.listdir("/proc"):
        if not pid.isdigit(): continue
        folder = "/proc/" + pid + "/fd"
        try: descriptors = os.listdir(folder)
        except FileNotFoundError: continue
        for number in descriptors:
            try:
                fs = os.stat(folder + "/" + number)
                if (fs.st_dev, fs.st_ino) != (s.st_dev, s.st_ino): continue
                with open("/proc/" + pid + "/fdinfo/" + number) as info:
                    line = next(x for x in info if x.startswith("flags:"))
                flags = int(line.split()[1], 8)
                if (flags & os.O_ACCMODE) in (os.O_WRONLY, os.O_RDWR): return True
            except (FileNotFoundError, ProcessLookupError): continue
    return False
def checked_open(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    s = os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or not 0 < s.st_size <= MAX_BYTES:
        os.close(fd); raise ValueError("Invalid backup file")
    return fd, s
def discover(root=ROOT):
    rs = os.lstat(root)
    if not stat.S_ISDIR(rs.st_mode): raise ValueError("Invalid storage directory")
    for name in sorted((x for x in os.listdir(root) if valid_name(x)), reverse=True):
        path = root + "/" + name
        log_path = path[:-8] + ".log"
        try:
            ls = read_log(log_path)
            fd, before = checked_open(path)
        except (OSError, UnicodeError, ValueError): continue
        with os.fdopen(fd, "rb") as f:
            if being_written(before): continue
            digest = hashlib.sha256()
            size = 0
            for block in iter(lambda: f.read(131072), b""):
                size += len(block)
                if size > MAX_BYTES: raise ValueError("Backup grew beyond limit")
                digest.update(block)
            after = os.fstat(f.fileno())
            if stamp(before) != stamp(after) or size != before.st_size: continue
            if stamp(os.stat(path, follow_symlinks=False)) != stamp(after): continue
            if being_written(after) or read_log(log_path) != ls: continue
            return {"name":name, "bytes":size, "sha256":digest.hexdigest(),
                    "stamp":stamp(after), "log_stamp":ls}
    raise ValueError("No completed VM100 backup is available")
def copy(meta, root=ROOT):
    if not valid_name(meta["name"]): raise ValueError("Invalid backup name")
    path = root + "/" + meta["name"]
    log_path = path[:-8] + ".log"
    if read_log(log_path) != meta["log_stamp"]: raise ValueError("Backup log changed")
    fd, before = checked_open(path)
    with os.fdopen(fd, "rb") as f:
        if stamp(before) != meta["stamp"] or being_written(before):
            raise ValueError("Backup identity changed or is active")
        total = 0
        for block in iter(lambda: f.read(131072), b""):
            total += len(block)
            if total > meta["bytes"]: raise ValueError("Backup grew")
            sys.stdout.buffer.write(block)
        sys.stdout.buffer.flush()
        after = os.fstat(f.fileno())
        if total != meta["bytes"] or stamp(after) != meta["stamp"]:
            raise ValueError("Backup changed during transfer")
        if stamp(os.stat(path, follow_symlinks=False)) != stamp(after):
            raise ValueError("Backup path changed during transfer")
        if being_written(after) or read_log(log_path) != meta["log_stamp"]:
            raise ValueError("Backup activity changed during transfer")
def main(mode, meta):
    try:
        if mode == "discover": print(json.dumps(discover(), separators=(",", ":")))
        elif mode == "copy": copy(meta)
        else: raise ValueError("Invalid operation")
    except Exception:
        print("Completed VM100 backup is unavailable or changed", file=sys.stderr)
        sys.exit(1)
'''


def check_absolute_regular(path):
    path = Path(path)
    if not path.is_absolute() or path != path.resolve():
        raise PullError("SSH configuration must be an absolute path without symlinks")
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid not in (0, os.geteuid()) or s.st_mode & 0o022:
        raise PullError("SSH configuration ownership or permissions are unsafe")
    return str(path)


class SSHRunner:
    def __init__(self, config, host):
        if host != "pve-uplink":
            raise PullError("Only the approved pve-uplink alias is supported")
        self.command = ["ssh", "-F", check_absolute_regular(config),
                        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                        "-o", "ControlMaster=no", "-o", "ControlPath=none",
                        "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=8",
                        "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
                        host, "python3", "-"]

    @staticmethod
    def source(mode, metadata=None):
        return (REMOTE_PROGRAM + "\nmain(" + repr(mode) + ", json.loads(" +
                repr(json.dumps(metadata)) + "))\n").encode()

    def discover(self):
        try:
            result = subprocess.run(self.command, input=self.source("discover"),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=REMOTE_TIMEOUT, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise PullError("SSH discovery failed or timed out") from None
        if result.returncode or len(result.stdout) > 16384:
            raise PullError("SSH discovery found no stable completed VM100 backup")
        try:
            return validate_metadata(json.loads(result.stdout))
        except (ValueError, UnicodeError):
            raise PullError("SSH discovery returned invalid metadata") from None

    def transfer(self, metadata, destination):
        process = None
        thread = None
        selector = None
        try:
            process = subprocess.Popen(self.command, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Drain diagnostics without displaying or retaining potentially
            # sensitive SSH banners or blocking the backup stream.
            def drain():
                try:
                    while process.stderr.read(65536):
                        pass
                except (OSError, ValueError):
                    pass
            thread = threading.Thread(target=drain, daemon=True)
            thread.start()
            deadline = time.monotonic() + REMOTE_TIMEOUT
            selector = selectors.DefaultSelector()
            total = 0
            process.stdin.write(self.source("copy", metadata))
            process.stdin.close()
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                if time.monotonic() >= deadline:
                    raise PullError("SSH backup transfer timed out")
                if not selector.select(min(1, max(0, deadline - time.monotonic()))):
                    continue
                block = os.read(process.stdout.fileno(), 131072)
                if not block:
                    break
                total += len(block)
                if total > metadata["bytes"] or total > MAX_BYTES:
                    raise PullError("SSH backup stream exceeds declared size")
                destination.write(block)
            if process.wait(timeout=max(0.1, deadline - time.monotonic())):
                raise PullError("SSH backup changed or transfer failed")
        except (OSError, subprocess.TimeoutExpired):
            raise PullError("SSH backup transfer failed") from None
        finally:
            if selector is not None:
                selector.close()
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream and not stream.closed:
                        stream.close()
            if thread is not None:
                thread.join(timeout=1)


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest_file(handle):
    digest = hashlib.sha256()
    total = 0
    handle.seek(0)
    for block in iter(lambda: handle.read(131072), b""):
        total += len(block)
        if total > MAX_BYTES:
            raise PullError("Local backup exceeds size limit")
        digest.update(block)
    return total, digest.hexdigest()


class Store:
    def __init__(self, destination):
        path = Path(destination)
        if not path.is_absolute() or path != path.resolve():
            raise PullError("Destination must be an absolute path without symlinks")
        self.path = path
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.lock_fd = None
        self.manifest = None
        self.old_manifest_stamp = None
        try:
            s = os.fstat(self.fd)
            if s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o700:
                raise PullError("Destination must be caller-owned and mode 0700")
            try:
                self.lock_fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                       0o600, dir_fd=self.fd)
                os.write(self.lock_fd, (TOOL + "\n").encode())
                os.fsync(self.lock_fd)
            except FileExistsError:
                self.lock_fd = self.open_private(LOCK)
            os.lseek(self.lock_fd, 0, os.SEEK_SET)
            if os.read(self.lock_fd, 128) != (TOOL + "\n").encode():
                raise PullError("Existing lock file is not owned by this tool")
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PullError("Another backup pull is already running") from None
            self.manifest = self.load_manifest()
        except Exception:
            self.close()
            raise

    def close(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def open_private(self, name, create=False):
        flags = os.O_RDWR if create else os.O_RDONLY
        if create:
            try:
                fd = os.open(name, flags | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=self.fd)
            except FileExistsError:
                fd = os.open(name, flags | os.O_NOFOLLOW, dir_fd=self.fd)
        else:
            fd = os.open(name, flags | os.O_NOFOLLOW, dir_fd=self.fd)
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) != 0o600:
            os.close(fd)
            raise PullError("Local owned file permissions or type are unsafe")
        return fd

    def stat_name(self, name):
        return os.stat(name, dir_fd=self.fd, follow_symlinks=False)

    @staticmethod
    def file_stamp(s):
        return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

    def load_manifest(self):
        try:
            fd = self.open_private(MANIFEST)
        except FileNotFoundError:
            return {"schema": 1, "tool": TOOL, "entries": [], "updated_at": utc_now()}
        with os.fdopen(fd, "rb") as f:
            s = os.fstat(f.fileno())
            self.old_manifest_stamp = self.file_stamp(s)
            if s.st_size > 1024**2:
                raise PullError("Local manifest is too large")
            try:
                data = json.load(f)
            except (ValueError, UnicodeError):
                raise PullError("Local manifest is damaged; existing copies were preserved") from None
        if (not isinstance(data, dict) or set(data) != {"schema", "tool", "entries", "updated_at"}
                or data.get("schema") != 1 or data.get("tool") != TOOL
                or not isinstance(data.get("entries"), list) or len(data["entries"]) > 1024
                or not isinstance(data.get("updated_at"), str)):
            raise PullError("Local manifest is not owned by this tool")
        seen = set()
        for entry in data["entries"]:
            if (not isinstance(entry, dict) or set(entry) != {"name", "bytes", "sha256", "copied_at", "dev", "ino"}
                    or not valid_name(entry.get("name")) or entry["name"] in seen
                    or not integer(entry.get("bytes"), 1, MAX_BYTES)
                    or not isinstance(entry.get("sha256"), str) or not SHA_RE.fullmatch(entry["sha256"])
                    or not isinstance(entry.get("copied_at"), str)
                    or not integer(entry.get("dev")) or not integer(entry.get("ino"), 1)):
                raise PullError("Local manifest entry is invalid")
            seen.add(entry["name"])
        return data

    def check_entry(self, entry):
        fd = self.open_private(entry["name"])
        with os.fdopen(fd, "rb") as f:
            s = os.fstat(f.fileno())
            if (s.st_dev, s.st_ino, s.st_size) != (entry["dev"], entry["ino"], entry["bytes"]) or s.st_nlink != 1:
                raise PullError("Managed backup identity changed; file was preserved")
            size, checksum = digest_file(f)
            if size != entry["bytes"] or checksum != entry["sha256"] or self.file_stamp(os.fstat(f.fileno())) != self.file_stamp(s):
                raise PullError("Managed backup checksum changed; file was preserved")
            if self.file_stamp(self.stat_name(entry["name"])) != self.file_stamp(s):
                raise PullError("Managed backup path changed; file was preserved")
            return s

    def reconcile(self):
        # A crash after an owned unlink but before manifest replacement is safe:
        # absent records may be dropped; a replaced or edited file is never owned.
        existing = []
        for entry in self.manifest["entries"]:
            try:
                self.check_entry(entry)
            except FileNotFoundError:
                continue
            existing.append(entry)
        self.manifest["entries"] = existing

    def available(self):
        info = os.fstatvfs(self.fd)
        return info.f_bavail * info.f_frsize

    def unlink_created(self, name, identity):
        try:
            s = self.stat_name(name)
            if stat.S_ISREG(s.st_mode) and (s.st_dev, s.st_ino) == identity:
                os.unlink(name, dir_fd=self.fd)
        except FileNotFoundError:
            pass

    def save_manifest(self):
        if self.old_manifest_stamp is None:
            try:
                self.stat_name(MANIFEST)
            except FileNotFoundError:
                pass
            else:
                raise PullError("A foreign manifest appeared; local copies were preserved")
        elif self.file_stamp(self.stat_name(MANIFEST)) != self.old_manifest_stamp:
            raise PullError("Local manifest changed during pull")
        self.manifest["updated_at"] = utc_now()
        raw = (json.dumps(self.manifest, indent=2, sort_keys=True) + "\n").encode()
        temp = ".vm100-manifest-" + uuid.uuid4().hex + ".part"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        s = os.fstat(fd)
        identity = (s.st_dev, s.st_ino)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, MANIFEST, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
            self.old_manifest_stamp = self.file_stamp(self.stat_name(MANIFEST))
        finally:
            self.unlink_created(temp, identity)

    def prune(self):
        ordered = sorted(self.manifest["entries"], key=lambda x: x["name"], reverse=True)
        old = ordered[KEEP:]
        # Validate every deletion before deleting any member. A foreign file,
        # changed identity, hard link or checksum mismatch prevents all pruning.
        checked = [(entry, self.check_entry(entry)) for entry in old]
        for entry, s in checked:
            if s.st_nlink != 1:
                raise PullError("Managed backup has extra links; retention was refused")
        for entry, s in checked:
            if self.file_stamp(self.stat_name(entry["name"])) != self.file_stamp(s):
                raise PullError("Managed backup changed before retention")
            os.unlink(entry["name"], dir_fd=self.fd)
        if old:
            os.fsync(self.fd)
        self.manifest["entries"] = ordered[:KEEP]
        self.save_manifest()


def pull(runner, destination):
    store = Store(destination)
    temp = None
    identity = None
    try:
        metadata = validate_metadata(runner.discover())
        if store.available() < MIN_FREE_BYTES:
            raise PullError("Destination has less than the required 1GiB free reserve")
        store.reconcile()
        name = metadata["name"]
        entry = next((x for x in store.manifest["entries"] if x["name"] == name), None)
        if entry is not None:
            if (entry["bytes"], entry["sha256"]) != (metadata["bytes"], metadata["sha256"]):
                raise PullError("Completed remote backup changed; existing local copy was preserved")
            # reconcile already checked the full local hash and private metadata.
            store.prune()
            return {"event": "unchanged", "file": name, "bytes": entry["bytes"], "sha256": entry["sha256"]}
        try:
            store.stat_name(name)
        except FileNotFoundError:
            pass
        else:
            raise PullError("An unowned destination backup exists; it was preserved")
        if store.available() < metadata["bytes"] + MIN_FREE_BYTES:
            raise PullError("Insufficient space for backup plus the required 1GiB reserve")
        temp = ".vm100-pull-" + uuid.uuid4().hex + ".part"
        fd = os.open(temp, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=store.fd)
        s = os.fstat(fd)
        identity = (s.st_dev, s.st_ino)
        with os.fdopen(fd, "w+b") as handle:
            runner.transfer(metadata, handle)
            handle.flush()
            size, checksum = digest_file(handle)
            if size != metadata["bytes"] or checksum != metadata["sha256"]:
                raise PullError("Transferred backup length or checksum differs")
            os.fsync(handle.fileno())
        try:
            store.stat_name(name)
        except FileNotFoundError:
            pass
        else:
            raise PullError("Destination backup appeared during copy; it was preserved")
        os.replace(temp, name, src_dir_fd=store.fd, dst_dir_fd=store.fd)
        temp = None
        os.fsync(store.fd)
        final = store.stat_name(name)
        store.manifest["entries"].append({"name": name, "bytes": size, "sha256": checksum,
                                          "copied_at": utc_now(), "dev": final.st_dev, "ino": final.st_ino})
        # Publish ownership before retention. If save fails, the completed new
        # copy remains untouched and requires explicit inspection on the next run.
        store.save_manifest()
        store.prune()
        return {"event": "copied", "file": name, "bytes": size, "sha256": checksum}
    finally:
        if temp is not None and identity is not None:
            store.unlink_created(temp, identity)
        store.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-config", required=True, help="Absolute trusted SSH config path")
    parser.add_argument("--host", default="pve-uplink", choices=["pve-uplink"])
    parser.add_argument("--destination", required=True, help="Existing caller-owned private 0700 directory")
    args = parser.parse_args(argv)
    interrupted = None

    def interrupt(signum, _frame):
        nonlocal interrupted
        # A second signal must not interrupt cleanup of the child or temp file.
        if interrupted is None:
            interrupted = signum
            raise PullInterrupted(signum)

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for sig in previous:
            signal.signal(sig, interrupt)
        result = pull(SSHRunner(args.ssh_config, args.host), args.destination)
        print(json.dumps(result, sort_keys=True))
        return 0
    except PullInterrupted as exc:
        print("ERROR: Backup pull interrupted; existing copies were preserved.", file=sys.stderr)
        return 128 + exc.signum
    except KeyboardInterrupt:
        print("ERROR: Backup pull interrupted; existing copies were preserved.", file=sys.stderr)
        return 130
    except (PullError, OSError):
        # Detailed SSH stderr and unexpected OS paths are intentionally private.
        print("ERROR: Backup pull refused or failed; existing copies were preserved. "
              "Check private directory permissions, free space and completed PVE backup availability.", file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
