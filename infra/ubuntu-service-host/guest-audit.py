#!/usr/bin/env python3
"""Collect a root-private, read-only Ubuntu guest audit. No secret files are read.

Only new audit output is written. This does not trim, install, update, reset,
restart, contact remote hosts, read passwords, or read SSH private keys.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time


SSH_DIRECTIVES = {
    "port", "listenaddress", "addressfamily", "pubkeyauthentication",
    "passwordauthentication", "kbdinteractiveauthentication", "permitrootlogin",
    "usepam", "authorizedkeysfile", "allowusers", "allowgroups", "denyusers",
    "denygroups", "authenticationmethods", "usedns", "loglevel", "maxauthtries",
    "maxsessions", "clientaliveinterval", "clientalivecountmax", "permittty",
    "allowtcpforwarding", "x11forwarding", "permitemptypasswords", "include",
}
CMDLINE_PREFIXES = {
    "BOOT_IMAGE", "root", "rootfstype", "rootflags", "ro", "rw", "quiet",
    "splash", "console", "nomodeset", "mem", "memmap", "iommu", "intel_iommu",
    "mitigations", "video", "initrd", "panic", "crashkernel", "clocksource",
}
GPU_CONTEXT = re.compile(r"i915|\bdrm\b|\bGuC\b|\bHuC\b|graphics|\bGPU\b", re.I)
INIT_ERROR = re.compile(r"fail|error|fatal|panic|\bBUG:|Oops:|out of memory|oom[-_]kill|wedg|hang|timed?\s*out", re.I)
MEMORY_CONTEXT = re.compile(r"\bMemory:|\be820:|\bBIOS.*(?:RAM|reserved)|\bRAMDISK:|\bmemblock", re.I)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_text(path):
    try:
        return {"available": True, "text": Path(path).read_text(encoding="utf-8", errors="replace")}
    except OSError as error:
        return {"available": False, "error": str(error)}


def command(arguments):
    tool = shutil.which(arguments[0])
    timeout = shutil.which("timeout")
    if not tool or not timeout:
        return {"available": False, "missing": arguments[0] if not tool else "timeout"}
    started = time.monotonic()
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C"})
    try:
        # Regular private captures avoid waiting forever for pipe EOF if a
        # kernel-blocked child survives the independent 30-second timeout.
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            process = subprocess.Popen(
                [timeout, "--signal=KILL", "30s", tool, *arguments[1:]],
                stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env,
                start_new_session=True,
            )
            overdue = False
            try:
                returncode = process.wait(timeout=32)
            except subprocess.TimeoutExpired:
                overdue = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    returncode = process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    returncode = None
            out.seek(0)
            err.seek(0)
            stdout = out.read().decode("utf-8", errors="replace")
            stderr = err.read().decode("utf-8", errors="replace")
        return {
            "available": True, "returncode": returncode,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "stdout": stdout, "stderr": stderr,
            "timed_out": overdue or returncode in (124, 137, -9),
            "wrapper_remains": process.poll() is None,
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"available": False, "error": str(error), "elapsed_seconds": round(time.monotonic() - started, 3)}


def fields_command(arguments):
    result = command(arguments)
    if result.get("returncode") == 0:
        try:
            result["data"] = json.loads(result.pop("stdout"))
        except json.JSONDecodeError:
            result["parse_error"] = "Command did not return valid JSON."
    return result


def cmdline_audit():
    source = read_text("/proc/cmdline")
    if not source.get("available"):
        return source
    tokens = source["text"].split()
    selected = [token for token in tokens if token.split("=", 1)[0] in CMDLINE_PREFIXES
                or token.split("=", 1)[0].startswith(("i915.", "xe.", "drm.", "vfio-pci."))]
    return {"available": True, "relevant_tokens": selected, "other_argument_count": len(tokens) - len(selected)}


def memory_audit():
    source = read_text("/proc/meminfo")
    iomem = read_text("/proc/iomem")
    data = {"meminfo": source, "iomem_available": iomem.get("available", False)}
    if not iomem.get("available"):
        data["iomem_error"] = iomem.get("error")
        return data
    retained = []
    ranges = []
    parsed_addresses = []
    for line in iomem["text"].splitlines():
        match = re.match(r"^(\s*)([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.*)$", line)
        if not match:
            continue
        indent, begin, end, label = match.groups()
        begin, end = int(begin, 16), int(end, 16)
        parsed_addresses.extend((begin, end))
        if re.search(r"System RAM|reserved|PCI Bus|PCI MMCONFIG|Graphics|Video ROM|Kernel|ACPI", label, re.I):
            retained.append(line)
        if label == "System RAM":
            ranges.append((begin, end))
    data["iomem_relevant_lines"] = retained
    masked = bool(parsed_addresses) and not any(parsed_addresses)
    data["iomem_addresses_masked"] = masked
    if not masked:
        # Union only System RAM spans; reserved/child ranges may overlap.
        merged = []
        for begin, end in sorted(ranges):
            if merged and begin <= merged[-1][1] + 1:
                merged[-1][1] = max(end, merged[-1][1])
            else:
                merged.append([begin, end])
        data["system_ram_address_span_bytes"] = sum(end - begin + 1 for begin, end in merged)
    data["interpretation"] = "Address spans and MemTotal are observations; no attribution to GPU reservation is made."
    return data


def gpu_sysfs_audit():
    devices = []
    for device in sorted(Path("/sys/bus/pci/devices").glob("*")):
        try:
            ids = (int((device / "vendor").read_text().strip(), 16), int((device / "device").read_text().strip(), 16))
        except (OSError, ValueError):
            continue
        if ids != (0x8086, 0x46B3):
            continue
        driver = device / "driver"
        item = {"pci_address": device.name, "pci_id": "8086:46b3", "driver": driver.resolve().name if driver.exists() else None}
        item["power"] = {key: read_text(device / "power" / key) for key in ("control", "runtime_status")}
        devices.append(item)
    renders = []
    for render in sorted(Path("/sys/class/drm").glob("renderD*")):
        device = render / "device"
        renders.append({
            "render_node": "/dev/dri/" + render.name,
            "pci_path": str(device.resolve()),
            "vendor": read_text(device / "vendor"),
            "device": read_text(device / "device"),
            "driver": (device / "driver").resolve().name if (device / "driver").exists() else None,
        })
    params = {name: read_text(Path("/sys/module/i915/parameters") / name)
              for name in ("enable_guc", "enable_fbc", "enable_psr")}
    return {"intel_devices": devices, "render_nodes": renders, "i915_parameter_observations": params}


def kernel_audit():
    result = command(["dmesg", "--color=never"])
    if result.get("returncode") != 0:
        return result
    lines = result.pop("stdout").splitlines()
    groups = {
        "gpu_initialization": [line for line in lines if GPU_CONTEXT.search(line)],
        "initialization_errors": [line for line in lines if INIT_ERROR.search(line)],
        "memory_initialization": [line for line in lines if MEMORY_CONTEXT.search(line)],
    }
    result["groups"] = {name: {"total_lines": len(selected), "last_500_lines": selected[-500:], "truncated": len(selected) > 500}
                        for name, selected in groups.items()}
    return result


def ssh_configuration_audit():
    observations = []
    skipped = []
    paths = [Path("/etc/ssh/sshd_config"), *sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf"))]
    for path in paths:
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file():
            skipped.append({"path": str(path), "reason": "Symlink/nonregular configuration not followed."})
            continue
        source = read_text(path)
        if not source.get("available"):
            skipped.append({"path": str(path), "reason": source.get("error")})
            continue
        scope = "global"
        for number, line in enumerate(source["text"].splitlines(), 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts[0].lower(), parts[1]
            if key == "match":
                scope = "Match " + value
            elif key in SSH_DIRECTIVES:
                observations.append({"path": str(path), "line": number, "scope": scope, "directive": key, "value": value})
    fingerprints = []
    for path in sorted(Path("/etc/ssh").glob("ssh_host_*_key.pub")):
        if path.is_file() and not path.is_symlink():
            fingerprints.append({"public_key_file": str(path), "fingerprint": command(["ssh-keygen", "-lf", str(path)])})
    return {
        "declared_configuration": observations, "skipped_files": skipped,
        "host_public_key_fingerprints": fingerprints,
        "interpretation": "Declared settings only; include precedence and Match evaluation are not claimed. No private key is opened.",
    }


def agent_channel_audit():
    channel = Path("/dev/virtio-ports/org.qemu.guest_agent.0")
    try:
        info = channel.stat()
        return {"exists": True, "is_character_device": stat.S_ISCHR(info.st_mode), "mode": oct(stat.S_IMODE(info.st_mode))}
    except OSError as error:
        return {"exists": False, "error": str(error)}


def collect():
    units = ["systemctl", "show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,Result"]
    packages = ["qemu-guest-agent", "openssh-server", "pciutils", "vainfo", "ffmpeg", "linux-firmware",
                "intel-media-va-driver", "intel-media-va-driver-non-free", "systemd-timesyncd", "chrony",
                "docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"]
    return {
        "os_release": read_text("/etc/os-release"),
        "uname": command(["uname", "-srm"]),
        "boot_id": read_text("/proc/sys/kernel/random/boot_id"),
        "uptime": read_text("/proc/uptime"),
        "kernel_command_line": cmdline_audit(),
        "memory": memory_audit(),
        "disk_usage": command(["df", "--block-size=1", "--output=source,fstype,size,used,avail,pcent,target"]),
        "block_devices": fields_command(["lsblk", "--json", "--bytes", "--output", "NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,ROTA,DISC-GRAN,DISC-MAX"]),
        "mounts": fields_command(["findmnt", "--json", "--output", "TARGET,SOURCE,FSTYPE"]),
        "clock": command(["timedatectl", "show", "--no-pager", "-p", "Timezone", "-p", "NTP", "-p", "NTPSynchronized", "-p", "TimeUSec", "-p", "RTCTimeUSec", "-p", "LocalRTC"]),
        "ntp_services": command([*units, "systemd-timesyncd.service", "chrony.service"]),
        "chrony_tracking": command(["chronyc", "-n", "tracking"]),
        "fstrim_timer": command(["systemctl", "show", "fstrim.timer", "--no-pager", "--property=LoadState,ActiveState,SubState,UnitFileState,LastTriggerUSec,NextElapseUSecRealtime,TimersCalendar"]),
        "fstrim_last_result": command(["systemctl", "show", "fstrim.service", "--no-pager", "--property=Result,ExecMainStatus,ExecMainCode,ExecMainStartTimestamp,ExecMainExitTimestamp"]),
        "fstrim_recent_log": command(["journalctl", "-u", "fstrim.service", "--no-pager", "-n", "20", "-o", "short-iso"]),
        "failed_services": command(["systemctl", "--failed", "--no-pager", "--no-legend"]),
        "system_running_state": command(["systemctl", "is-system-running"]),
        "packages": command(["dpkg-query", "-W", "-f", "${binary:Package}\t${Version}\t${db:Status-Abbrev}\n", *packages]),
        "package_consistency": command(["dpkg", "--audit"]),
        "agent_service": command([*units, "qemu-guest-agent.service"]),
        "agent_channel": agent_channel_audit(),
        "ssh_services": command([*units, "ssh.service", "ssh.socket"]),
        "ssh_configuration": ssh_configuration_audit(),
        "listening_tcp": command(["ss", "-lntp"]),
        "ipv4_addresses": fields_command(["ip", "-j", "-4", "address", "show"]),
        "ipv4_routes": fields_command(["ip", "-j", "-4", "route", "show", "table", "main"]),
        "resolver_state": command(["resolvectl", "status", "--no-pager"]),
        "resolver_file": read_text("/etc/resolv.conf"),
        "gpu_sysfs": gpu_sysfs_audit(),
        "gpu_pci": command(["lspci", "-Dnnk", "-d", "8086:46b3"]),
        "kernel_initialization": kernel_audit(),
        "reboot_required": Path("/run/reboot-required").exists(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-parent", type=Path, default=Path("/root/servicehost-audit"))
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        print(json.dumps({"status": "refused", "reason": "Run as root for a complete private guest audit."}))
        return 1
    os.umask(0o077)
    parent = arguments.output_parent.expanduser().absolute()
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or parent.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        print(json.dumps({"status": "refused", "reason": "Output parent must be a root-owned real directory with mode 0700."}))
        return 1
    run_dir = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=parent))
    result = {"schema": 1, "capture_mode": "read_only", "started_utc": utc_now(), "data": collect(), "completed_utc": utc_now()}
    output = run_dir / "audit.json"
    with output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=True, indent=2)
        handle.write("\n")
    print(json.dumps({"status": "completed", "audit_file": str(output), "checks": len(result["data"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
