#!/usr/bin/env python3
"""Bounded, local-only Intel 46b3 VAAPI acceptance; never changes GPU settings.

Run as root for complete kernel auditing, or as a user with render access.
Each run creates a new owner-private directory. Root runs default to /root.
No downloads, hardware resets, module reloads, or global configuration writes.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


TIMEOUT_SECONDS = 30
GPU_SUBJECT = re.compile(r"\b(?:i915|drm|guc|huc|gpu|gt\d*)\b", re.I)
GPU_ERROR = re.compile(
    r"fail|error|hang|wedg|reset|fault|timed?\s*out|timeout|"
    r"not\s+(?:loaded|authenticated|found)|missing", re.I
)
OOM_ERROR = re.compile(
    r"out of memory|oom[-_]kill|oom_reaper|invoked oom-killer|"
    r"killed process .*total-vm", re.I
)


class ValidationError(Exception):
    pass


def private_write(path, value):
    with open(path, "x", encoding="utf-8") as handle:
        handle.write(value)


def private_run_directory(parent):
    os.umask(0o077)
    parent = parent.expanduser().absolute()
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or parent.is_symlink():
        raise ValidationError("Output parent must be a real directory.")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValidationError("Output parent must belong to this user with mode 0700.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
    return Path(tempfile.mkdtemp(prefix=stamp, dir=parent))


class Commands:
    def __init__(self, directory, summary):
        self.directory = directory
        self.summary = summary
        self.sequence = 0

    def run(self, name, arguments, check=True, ihd=False):
        self.sequence += 1
        prefix = f"{self.sequence:02d}-{name}"
        outpath = self.directory / f"{prefix}.stdout.log"
        errpath = self.directory / f"{prefix}.stderr.log"
        env = os.environ.copy()
        env.update({"LC_ALL": "C", "LANG": "C"})
        if ihd:
            env["LIBVA_DRIVER_NAME"] = "iHD"
            # Use the installed distribution driver; ignore inherited overrides.
            env.pop("LIBVA_DRIVERS_PATH", None)
        started = time.monotonic()
        timed_out = False
        still_running = False
        interrupted = False
        timeout_tool = shutil.which("timeout")
        if not timeout_tool:
            raise ValidationError("Installed timeout command is required for independent process protection.")
        with open(outpath, "xb") as stdout, open(errpath, "xb") as stderr:
            try:
                process = subprocess.Popen(
                    [timeout_tool, "--signal=KILL", f"{TIMEOUT_SECONDS}s", *arguments],
                    stdin=subprocess.DEVNULL, stdout=stdout,
                    stderr=stderr, env=env, start_new_session=True,
                )
            except OSError as error:
                raise ValidationError(f"Cannot start {name}: {error}") from error
            try:
                returncode = process.wait(timeout=TIMEOUT_SECONDS + 1)
                timed_out = returncode in (124, 137, -signal.SIGKILL)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    returncode = process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    still_running = True
                    returncode = None
            except KeyboardInterrupt:
                interrupted = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    returncode = process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    still_running = True
                    returncode = None
        if timed_out or interrupted:
            # timeout can reap its wrapper while a driver-blocked child remains.
            # Check this run's process group, without touching any other group.
            for _ in range(10):
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    still_running = False
                    break
                still_running = True
                time.sleep(0.1)
        result = {
            "returncode": returncode,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "timeout_seconds": TIMEOUT_SECONDS,
            "timed_out": timed_out,
            "interrupted": interrupted,
            "process_remains": still_running,
            "stdout_log": outpath.name,
            "stderr_log": errpath.name,
        }
        if still_running:
            result["remaining_process_group"] = process.pid
        self.summary["commands"][name] = result
        if interrupted:
            raise KeyboardInterrupt
        stdout_text = outpath.read_text(encoding="utf-8", errors="replace")
        stderr_text = errpath.read_text(encoding="utf-8", errors="replace")
        if check and (timed_out or returncode != 0):
            reason = "timed out" if timed_out else f"exited {returncode}"
            if still_running:
                reason += "; process did not terminate after SIGKILL"
            raise ValidationError(f"{name} {reason}; inspect its private logs.")
        return result, stdout_text, stderr_text


def identify_render():
    matches = []
    for render in sorted(Path("/sys/class/drm").glob("renderD*")):
        device = render / "device"
        try:
            vendor = int((device / "vendor").read_text().strip(), 16)
            devid = int((device / "device").read_text().strip(), 16)
        except (OSError, ValueError):
            continue
        if (vendor, devid) == (0x8086, 0x46B3):
            matches.append((render, device))
    if len(matches) != 1:
        raise ValidationError(f"Expected one Intel 8086:46b3 render node; found {len(matches)}.")
    render, device = matches[0]
    driver_link = device / "driver"
    driver = driver_link.resolve(strict=True).name
    if driver != "i915":
        raise ValidationError(f"Intel render device uses {driver}, expected i915.")
    node = Path("/dev/dri") / render.name
    info = node.stat()
    if not stat.S_ISCHR(info.st_mode):
        raise ValidationError("Matched render path is not a character device.")
    if not os.access(node, os.R_OK | os.W_OK):
        raise ValidationError("Current user lacks read/write access to the Intel render node.")
    return {
        "pci_id": "8086:46b3",
        "guest_pci_address": device.resolve(strict=True).name,
        "render_node": str(node),
        "kernel_driver": driver,
    }


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def kernel_capture(commands, name):
    if not shutil.which("dmesg"):
        return {"available": False, "reason": "dmesg is unavailable"}
    result, text, _ = commands.run(name, ["dmesg", "--color=never"], check=False)
    if result["returncode"] != 0 or result["timed_out"]:
        return {"available": False, "reason": "Kernel log access failed or timed out"}
    lines = text.splitlines()
    timestamps = []
    for line in lines:
        match = re.match(r"^\[\s*(\d+(?:\.\d+)?)\]", line)
        if match:
            timestamps.append(float(match.group(1)))
    return {
        "available": True,
        "boot_id": boot_id(),
        "lines": lines,
        "first_timestamp": min(timestamps) if timestamps else None,
        "last_timestamp": max(timestamps) if timestamps else None,
    }


def error_lines(lines):
    gpu = [line for line in lines if GPU_SUBJECT.search(line) and GPU_ERROR.search(line)]
    oom = [line for line in lines if OOM_ERROR.search(line)]
    return gpu, oom


def audit_kernel(before, after, directory):
    if not before.get("available") or not after.get("available"):
        return {"status": "unavailable", "reason": "Kernel auditing requires readable kernel logs."}
    if before["boot_id"] != after["boot_id"]:
        return {"status": "incomplete", "reason": "Boot changed during validation."}
    latest = before["last_timestamp"]
    first = after["first_timestamp"]
    if latest is None:
        return {"status": "incomplete", "reason": "Kernel log has no verifiable monotonic timestamps."}
    if latest is not None and (first is None or first > latest):
        return {"status": "incomplete", "reason": "Kernel log no longer covers the validation start."}
    old_counts = Counter(before["lines"])
    new_lines = []
    for line in after["lines"]:
        if old_counts[line]:
            old_counts[line] -= 1
        else:
            new_lines.append(line)
    old_gpu, old_oom = error_lines(before["lines"])
    new_gpu, new_oom = error_lines(new_lines)
    private_write(directory / "kernel-new-gpu-errors.log", "\n".join(new_gpu) + ("\n" if new_gpu else ""))
    private_write(directory / "kernel-new-oom-errors.log", "\n".join(new_oom) + ("\n" if new_oom else ""))
    return {
        "status": "failed" if new_gpu or new_oom else "passed",
        "prior_gpu_error_lines": len(old_gpu),
        "prior_oom_error_lines": len(old_oom),
        "new_gpu_error_lines": len(new_gpu),
        "new_oom_error_lines": len(new_oom),
    }


def final_progress(text):
    values = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def validate(commands, summary, directory):
    for tool in ("ffmpeg", "ffprobe", "vainfo"):
        if not shutil.which(tool):
            raise ValidationError(f"Required installed tool is unavailable: {tool}; nothing was downloaded.")
    summary["gpu"] = identify_render()
    node = summary["gpu"]["render_node"]
    _, version, _ = commands.run("ffmpeg-version", ["ffmpeg", "-version"])
    summary["ffmpeg_version"] = version.splitlines()[0] if version.splitlines() else "unknown"
    _, help_text, help_errors = commands.run("encoder-capabilities", ["ffmpeg", "-hide_banner", "-h", "encoder=h264_vaapi"])
    encoder_help = help_text + help_errors
    if "Encoder h264_vaapi" not in encoder_help:
        raise ValidationError("Installed FFmpeg does not expose h264_vaapi.")
    for option in ("-rc_mode", "-qp", "-low_power"):
        if option not in encoder_help:
            raise ValidationError(f"Installed h264_vaapi lacks the required {option} option.")
    _, va_stdout, va_stderr = commands.run(
        "vainfo", ["vainfo", "--display", "drm", "--device", node], ihd=True,
    )
    va_text = va_stdout + va_stderr
    if not re.search(r"Driver version:.*Intel.*iHD", va_text, re.I):
        raise ValidationError("vainfo did not confirm the Intel iHD media driver.")
    high_lines = [line for line in va_text.splitlines() if re.search(r"\bVAProfileH264High\b", line)]
    def entrypoint(name):
        return any(re.search(r"\b" + re.escape(name) + r"\b", line) for line in high_lines)
    if not entrypoint("VAEntrypointVLD"):
        raise ValidationError("iHD does not advertise H264High hardware decoding.")
    if entrypoint("VAEntrypointEncSlice"):
        low_power = 0
        encode_entry = "VAEntrypointEncSlice"
    elif entrypoint("VAEntrypointEncSliceLP"):
        low_power = 1
        encode_entry = "VAEntrypointEncSliceLP"
    else:
        raise ValidationError("iHD does not advertise an H264High hardware encoding entry point.")
    summary["capabilities"] = {"decode": "VAEntrypointVLD", "encode": encode_entry, "low_power": low_power}
    sample = directory / "h264-vaapi.mp4"
    _, encode_progress, _ = commands.run("encode", [
        "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "verbose", "-nostats", "-n",
        "-init_hw_device", f"vaapi=igpu:{node}", "-filter_hw_device", "igpu",
        "-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=30:duration=10",
        "-vf", "format=nv12,hwupload", "-frames:v", "300", "-an",
        "-c:v", "h264_vaapi", "-profile:v", "high", "-rc_mode", "CQP", "-qp", "24",
        "-bf", "0", "-low_power", str(low_power), "-progress", "pipe:1", str(sample),
    ], ihd=True)
    enc = final_progress(encode_progress)
    if enc.get("progress") != "end" or enc.get("frame") != "300":
        raise ValidationError("Hardware encoder did not finish exactly 300 frames.")
    summary["encoding"] = {"status": "passed", "encoder": "h264_vaapi", "rate_control": "CQP", "frames": 300}
    _, probe_text, _ = commands.run("ffprobe", [
        "ffprobe", "-v", "error", "-select_streams", "v:0", "-count_frames",
        "-show_entries", "stream=codec_name,profile,width,height,nb_read_frames,pix_fmt,avg_frame_rate:format=duration",
        "-of", "json", str(sample),
    ])
    metadata = json.loads(probe_text)
    streams = metadata.get("streams", [])
    if len(streams) != 1:
        raise ValidationError("Sample metadata does not contain exactly one selected video stream.")
    video = streams[0]
    duration = float(metadata.get("format", {}).get("duration", "nan"))
    if not (
        video.get("codec_name") == "h264" and video.get("profile") == "High"
        and video.get("width") == 1280 and video.get("height") == 720
        and int(video.get("nb_read_frames", -1)) == 300
        and video.get("avg_frame_rate") == "30/1" and abs(duration - 10.0) <= 0.05
    ):
        raise ValidationError("Sample failed the H264High/720p/30fps/300-frame/10-second metadata check.")
    summary["sample"] = {"status": "passed", "codec": "h264", "profile": "High", "width": 1280, "height": 720,
                         "frames": 300, "fps": 30, "duration_seconds": duration, "bytes": sample.stat().st_size}
    _, decode_progress, decode_log = commands.run("decode", [
        "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "debug", "-nostats",
        "-init_hw_device", f"vaapi=igpu:{node}", "-hwaccel", "vaapi", "-hwaccel_device", "igpu",
        "-hwaccel_output_format", "vaapi", "-c:v", "h264", "-i", str(sample),
        "-vf", "hwdownload,format=nv12", "-an", "-progress", "pipe:1", "-f", "null", "-",
    ], ihd=True)
    dec = final_progress(decode_progress)
    if dec.get("progress") != "end" or dec.get("frame") != "300":
        raise ValidationError("VAAPI hardware decode did not finish exactly 300 frames.")
    summary["decoding"] = {
        "status": "passed", "hwaccel": "vaapi", "hardware_frame_filter": "hwdownload",
        "frames": 300, "vaapi_format_log_seen": bool(re.search(r"Format vaapi chosen", decode_log, re.I)),
    }
    # Recheck the render identity after both calls, without changing driver state.
    if identify_render() != summary["gpu"]:
        raise ValidationError("Intel render identity changed during validation.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default_parent = Path("/root/servicehost-gpu-acceptance") if os.geteuid() == 0 else Path.home() / ".local/state/servicehost-gpu-acceptance"
    parser.add_argument("--output-parent", type=Path, default=default_parent)
    arguments = parser.parse_args()
    def interrupted_signal(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted_signal)
    signal.signal(signal.SIGHUP, interrupted_signal)
    try:
        directory = private_run_directory(arguments.output_parent)
    except (OSError, ValidationError) as error:
        print(json.dumps({"schema": 1, "status": "failed", "reason": str(error)}))
        return 1
    summary = {
        "schema": 1, "status": "failed", "started_utc": datetime.now(timezone.utc).isoformat(),
        "output_directory": str(directory), "commands": {},
        "scope": "Local H264 VAAPI acceptance; application/QSV/other codecs are not certified.",
    }
    commands = Commands(directory, summary)
    before = {"available": False}
    validation_passed = False
    try:
        before = kernel_capture(commands, "kernel-before")
        validate(commands, summary, directory)
        validation_passed = True
    except (ValidationError, OSError, ValueError, KeyError, TypeError) as error:
        summary["reason"] = str(error)[:500]
    except KeyboardInterrupt:
        summary["reason"] = "Interrupted; validation is not accepted."
    finally:
        try:
            after = kernel_capture(commands, "kernel-after")
            summary["kernel_audit"] = audit_kernel(before, after, directory)
        except (ValidationError, OSError, ValueError) as error:
            summary["kernel_audit"] = {"status": "incomplete", "reason": str(error)[:300]}
        except KeyboardInterrupt:
            summary["kernel_audit"] = {"status": "incomplete", "reason": "Kernel audit was interrupted."}
        audit_status = summary["kernel_audit"]["status"]
        if validation_passed and audit_status == "passed":
            summary["status"] = "passed"
        elif validation_passed and audit_status in ("unavailable", "incomplete"):
            summary["status"] = "incomplete"
            summary["reason"] = "VAAPI passed, but the mandatory kernel error audit was incomplete."
        elif validation_passed:
            summary["reason"] = "New GPU or OOM kernel errors appeared during validation."
        summary["completed_utc"] = datetime.now(timezone.utc).isoformat()
        private_write(directory / "result.json", json.dumps(summary, ensure_ascii=True, indent=2) + "\n")
    print(json.dumps(summary, ensure_ascii=True, separators=(",", ":")))
    return 0 if summary["status"] == "passed" else 2 if summary["status"] == "incomplete" else 1


if __name__ == "__main__":
    sys.exit(main())
