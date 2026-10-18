#!/usr/bin/env python3
"""Verify service host VM Docker without publishing ports or changing host networking.

Temporary containers/networks carry a unique Compose project or explicit label.
Cleanup removes only those objects and the exact image built by this run.
Official small test images remain cached; no global prune is performed.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
from types import SimpleNamespace
import uuid

_spec = importlib.util.spec_from_file_location("docker_install", Path(__file__).with_name("docker-install.py"))
helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(helpers)
Commands = helpers.Commands
Refused = helpers.Refused
save_json = helpers.save_json
MIN_FREE = helpers.MIN_FREE


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def root_free():
    fs = os.statvfs("/")
    return fs.f_bavail * fs.f_frsize


def verified_render(path, sysfs="/sys/class/drm"):
    path = Path(path)
    if path.parent != Path("/dev/dri") or not path.name.startswith("renderD") or not path.name[7:].isdigit():
        raise Refused("Render device must be an explicit /dev/dri/renderD<number> path.")
    if path.is_symlink() or not stat.S_ISCHR(path.stat().st_mode):
        raise Refused("Render device must be an existing character device.")
    device = Path(sysfs) / path.name / "device"
    if device.joinpath("vendor").read_text().strip().lower() != "0x8086":
        raise Refused("Requested render device is not Intel.")
    if device.joinpath("device").read_text().strip().lower() != "0x46b3":
        raise Refused("Requested render device does not belong to the service host VM 8086:46b3 GPU.")
    return path.stat()


def image_digest(commands, tag):
    commands.run(["docker", "pull", "--platform", "linux/amd64", tag], timeout=300)
    value = json.loads(commands.run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", tag]).stdout)
    if not value or not isinstance(value, list) or "@sha256:" not in value[0]:
        raise Refused("Pulled image has no recorded repository digest.")
    return value[0]


def routes(commands):
    values = json.loads(commands.run(["ip", "-j", "route", "show", "default"]).stdout)
    # Ignore volatile expiry counters, while retaining routing identity.
    keys = {"dst", "gateway", "dev", "table", "protocol", "prefsrc", "metric", "multipath"}
    normalized = [{key: value for key, value in row.items() if key in keys} for row in values]
    return sorted(json.dumps(row, sort_keys=True) for row in normalized)


def verify(args):
    helpers.require_root()
    helpers.read_os_release()
    if root_free() < MIN_FREE:
        raise Refused("Root filesystem has less than 5 GiB free; no test images were pulled.")
    state_root = helpers.allowed_state_directory(args.state_dir)
    install_receipt = json.loads((state_root / "latest-install.json").read_text())
    daemon = Path("/etc/docker/daemon.json")
    if install_receipt.get("stage") != "complete" or install_receipt.get("schema") != 1:
        raise Refused("No complete installation receipt is available.")
    if hashlib.sha256(daemon.read_bytes()).hexdigest() != install_receipt.get("daemon_sha256"):
        raise Refused("Docker daemon configuration changed after installation; inspect it first.")
    render_info = verified_render(args.render_device) if args.render_device else None
    token = uuid.uuid4().hex[:12]
    project = "u150verify" + token
    directory = helpers.private_directory(state_root / ("verify-" + token))
    commands = Commands(directory / "commands.log")
    result = {"schema": 1, "project": project, "started_at": stamp(),
              "status": "running", "checks": {}, "images": {},
              "root_free_before_bytes": root_free(), "gpu_scope": "device_visibility_only"}
    names = []
    compose_file = directory / "compose.test.json"
    build_tag = "servicehost-selftest:" + token
    built_image_id = None
    original_routes = routes(commands)
    cleanup_errors = []

    def cleanup_run(argv, timeout=30):
        try:
            return commands.run(argv, check=False, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            cleanup_errors.append("cleanup_command_unavailable:" + Path(argv[0]).name)
            return SimpleNamespace(returncode=125, stdout="", stderr="")

    def run_container(name_suffix, image, command, *, network=None, extras=None):
        name = project + "-" + name_suffix
        names.append(name)
        argv = ["docker", "run", "--rm", "--name", name,
                "--label", "servicehost.selftest=" + token,
                "--memory", "128m", "--cpus", "0.5", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"]
        if network:
            argv.extend(["--network", network])
        if extras:
            argv.extend(extras)
        argv.extend([image, *command])
        return commands.run(argv, timeout=60)

    def check_free():
        free = root_free()
        if free < MIN_FREE:
            raise Refused("Test image downloads left less than 5 GiB free; stopping tests.")
        return free

    try:
        commands.run(["systemctl", "is-enabled", "docker.service", "containerd.service"])
        commands.run(["systemctl", "is-active", "docker.service", "containerd.service"])
        info = json.loads(commands.run(["docker", "info", "--format", "{{json .}}"]).stdout)
        if info.get("LoggingDriver") != "local":
            raise Refused("Default Docker logging driver is not local.")
        result["versions"] = {
            "engine": info.get("ServerVersion"),
            "compose": commands.run(["docker", "compose", "version", "--short"]).stdout.strip(),
            "buildx": commands.run(["docker", "buildx", "version"]).stdout.strip(),
            "storage_driver": info.get("Driver"), "logging_driver": info.get("LoggingDriver")}
        commands.run(["docker", "buildx", "inspect"], timeout=30)
        for role, tag in (("hello", "hello-world:latest"), ("busybox", "busybox:stable"),
                          ("curl", "curlimages/curl:latest")):
            result["images"][role] = image_digest(commands, tag)
            check_free()
        hello = run_container("hello", result["images"]["hello"], [], extras=["--network", "none"])
        if "Hello from Docker!" not in hello.stdout:
            raise Refused("hello-world did not return its expected success marker.")
        result["checks"]["hello_world"] = True
        # Compose's default network is user-defined and IPv4-only. No host port
        # or external interface is attached to it; Docker chooses its subnet.
        compose = {"services": {"service": {
            "image": result["images"]["busybox"],
            "command": ["sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done"],
            "read_only": True, "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"], "mem_limit": "64m", "cpus": 0.5,
            "labels": {"servicehost.selftest": token}}},
            "networks": {"default": {"enable_ipv6": False,
                         "labels": {"servicehost.selftest": token}}}}
        save_json(compose_file, compose)
        compose_args = ["docker", "compose", "--project-name", project, "--file", str(compose_file)]
        commands.run([*compose_args, "config", "--quiet"])
        commands.run([*compose_args, "up", "--detach", "--wait", "--wait-timeout", "30"], timeout=60)
        service_id = commands.run([*compose_args, "ps", "--quiet", "service"]).stdout.strip()
        if not service_id:
            raise Refused("Compose service did not start.")
        log_config = json.loads(commands.run(["docker", "inspect", "--format", "{{json .HostConfig.LogConfig}}", service_id]).stdout)
        if log_config.get("Type") != "local" or log_config.get("Config", {}).get("max-size") != "10m" or log_config.get("Config", {}).get("max-file") != "3":
            raise Refused("New containers did not inherit the approved log rotation limits.")
        network = project + "_default"
        run_container("dns", result["images"]["busybox"],
                      ["sh", "-c", "nslookup service 127.0.0.11 && nslookup example.com 127.0.0.11"],
                      network=network)
        result["checks"]["compose_service_dns_and_external_dns"] = True
        response = run_container("https", result["images"]["curl"],
                                 ["--fail", "--silent", "--show-error", "--location",
                                  "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
                                  "--max-time", "20", "--max-filesize", "8192", "--output", "/dev/null",
                                  "--write-out", "%{http_code} %{size_download} %{ssl_verify_result}",
                                  "https://example.com"], network=network)
        fields = response.stdout.strip().split()
        if len(fields) != 3 or fields[0] != "200" or int(float(fields[1])) > 8192 or fields[2] != "0":
            raise Refused("TLS-verified small HTTPS request did not pass.")
        result["checks"]["https"] = {"passed": True, "bytes": int(float(fields[1])), "tls_verification": True}
        # An empty build tests Buildx without adding packages or large layers.
        context = helpers.private_directory(directory / "build-context")
        helpers.atomic_bytes(context / "Dockerfile", ("FROM " + result["images"]["busybox"] + "\nCMD [\"true\"]\n").encode())
        commands.run(["docker", "buildx", "build", "--load", "--provenance=false", "--tag", build_tag,
                      "--label", "servicehost.selftest=" + token, str(context)], timeout=120)
        built_image_id = commands.run(["docker", "image", "inspect", "--format", "{{.Id}}", build_tag]).stdout.strip()
        run_container("build", build_tag, [], extras=["--network", "none"])
        result["checks"]["buildx_local_build"] = True
        if args.render_device:
            device = str(Path(args.render_device))
            check = "test -c \"$1\" && test -r \"$1\" && test -w \"$1\""
            run_container("render", result["images"]["busybox"],
                          ["sh", "-c", check, "render-check", device],
                          extras=["--network", "none", "--device", device + ":" + device + ":rw",
                                  "--user", "65534:65534", "--group-add", str(render_info.st_gid)])
            result["checks"]["intel_render_device_mapping"] = {"passed": True, "device": device,
                "vendor_device": "8086:46b3", "nonroot_group_access": True,
                "hardware_transcoding_tested_in_container": False}
        else:
            result["checks"]["intel_render_device_mapping"] = {"tested": False}
        result["root_free_after_bytes"] = check_free()
        if routes(commands) != original_routes:
            raise Refused("Host default routes changed during testing; inspect before proceeding.")
        result["checks"]["host_default_route_preserved"] = True
        result["status"] = "passed"
    except BaseException as error:
        result["status"] = "failed"
        result["error_type"] = type(error).__name__
        raise
    finally:
        # Never use global prune, delete volumes, or target another project.
        if compose_file.exists():
            cleanup = cleanup_run(["docker", "compose", "--project-name", project, "--file", str(compose_file),
                                   "down", "--timeout", "10"], timeout=45)
            if cleanup.returncode:
                cleanup_errors.append("compose_down")
        for name in names:
            exists = cleanup_run(["docker", "container", "inspect", name], timeout=15)
            if exists.returncode == 0:
                label = cleanup_run(["docker", "inspect", "--format", "{{index .Config.Labels \"servicehost.selftest\"}}", name]).stdout.strip()
                if label == token:
                    deleted = cleanup_run(["docker", "rm", "--force", name], timeout=15)
                    if deleted.returncode:
                        cleanup_errors.append("container:" + name)
                else:
                    cleanup_errors.append("unexpected_container_identity")
        # Also inspect the unique tag when a build timed out after producing an
        # image, before the CLI returned its ID to this process.
        current_build = cleanup_run(["docker", "image", "inspect", "--format", "{{.Id}}", build_tag])
        if current_build.returncode == 0 and current_build.stdout.strip():
            current_image_id = current_build.stdout.strip()
            label = cleanup_run(["docker", "image", "inspect", "--format", "{{index .Config.Labels \"servicehost.selftest\"}}", current_image_id]).stdout.strip()
            if label == token:
                deleted = cleanup_run(["docker", "image", "rm", build_tag], timeout=30)
                if deleted.returncode:
                    cleanup_errors.append("build_image")
            else:
                cleanup_errors.append("unexpected_build_image_identity")
        remaining_command = cleanup_run(["docker", "ps", "-aq", "--filter", "label=servicehost.selftest=" + token])
        network_command = cleanup_run(["docker", "network", "ls", "--quiet", "--filter", "label=servicehost.selftest=" + token])
        remaining = remaining_command.stdout.strip()
        networks = network_command.stdout.strip()
        if remaining_command.returncode or network_command.returncode:
            cleanup_errors.append("cannot_verify_cleanup")
        if remaining or networks:
            cleanup_errors.append("remaining_test_objects")
        result.update({"finished_at": stamp(), "cleanup_errors": cleanup_errors,
                       "cleanup_passed": not cleanup_errors})
        if cleanup_errors:
            result["status"] = "failed"
        save_json(directory / "result.json", result)
        save_json(state_root / "latest-verify.json", result)
        print(json.dumps({"status": result["status"].upper(), "result": str(directory / "result.json"),
                          "cleanup_passed": not cleanup_errors,
                          "root_free_bytes": result.get("root_free_after_bytes")}))
    return result["status"] == "passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", default="/var/lib/servicehost-setup/docker")
    parser.add_argument("--render-device", help="Verified Intel /dev/dri/renderD<number> device; optional.")
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Interrupted; cleaning only this run's test objects.")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    try:
        return 0 if verify(args) else 1
    except (Refused, ValueError, OSError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
