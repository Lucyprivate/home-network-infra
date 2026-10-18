#!/bin/bash
# Read-only VPS checks. No private key, enrollment key, or database content is read.
set -euo pipefail
test "$(id -u)" -eq 0 || { printf 'Run as root to inspect listeners and service state.\n' >&2; exit 1; }
TASK_SHA=e979d27fe17d924d33bb6ab7504f6338d0635989a0cfdcfbc0ceb637dbcbe980
printf '%s  %s\n' "$TASK_SHA" /usr/local/bin/headscale | sha256sum --check --status
/usr/local/bin/headscale version
systemctl is-active --quiet headscale
systemctl is-enabled headscale
curl --fail --silent --show-error --noproxy '*' --max-time 10 http://127.0.0.1:18080/health >/dev/null
# Public checks enforce normal certificate trust and IP SAN validation.
curl --fail --silent --show-error --noproxy '*' --max-time 15 https://hs.example.com/health >/dev/null
# v=148 is Tailscale 1.104's capability version; unversioned /key is rejected.
curl --fail --silent --show-error --noproxy '*' --max-time 15 'https://hs.example.com/key?v=148' >/dev/null
TASK_SOCKETS=$(ss -H -lntu)
printf '%s\n' "$TASK_SOCKETS" | awk '$5 ~ /:(18080|9090|50443|3478)$/ {print}'
printf '%s\n' "$TASK_SOCKETS" | awk '
    $5 ~ /:(18080|9090|50443)$/ && $5 !~ /^127\.0\.0\.1:/ {bad=1}
    END {exit bad}
'
test -S /run/headscale/headscale.sock
# Admin access uses the private Unix socket, without exposing the gRPC API.
/usr/local/bin/headscale --config /etc/headscale/config.yaml --output json users list >/dev/null
printf 'PASS: artifact, configuration, systemd, health, TLS, loopback admin listeners, Unix CLI.\n'
printf 'STUN and relay client connectivity still require tailscale netcheck/debug derp from clients.\n'
