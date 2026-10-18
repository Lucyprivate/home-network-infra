#!/bin/bash
# Run on the VPS after taking the deployment backup.
# Installs files and validates configuration, but does not start/enable anything.
set -euo pipefail
umask 077
TASK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TASK_BINARY="$TASK_DIR/vendor/headscale_0.29.5_linux_amd64"
TASK_SHA=e979d27fe17d924d33bb6ab7504f6338d0635989a0cfdcfbc0ceb637dbcbe980
test "$(id -u)" -eq 0 || { printf 'Run as root.\n' >&2; exit 1; }
test "$(uname -m)" = x86_64 || { printf 'This artifact requires x86_64.\n' >&2; exit 1; }
printf '%s  %s\n' "$TASK_SHA" "$TASK_BINARY" | sha256sum --check --status
"$TASK_BINARY" version
# Never overwrite another installation or an already-personalized ACL.
for TASK_DEST in /usr/local/bin/headscale /etc/headscale/config.yaml /etc/headscale/policy.hujson /etc/headscale/derp-public.yaml /usr/local/libexec/headscale/refresh-derp-map.py /var/lib/home-network-derp-map/owner.json /etc/systemd/system/headscale.service; do
    if test -e "$TASK_DEST"; then
        printf 'Refusing existing destination: %s\n' "$TASK_DEST" >&2
        exit 1
    fi
done
if test -e /var/lib/headscale && test -n "$(find /var/lib/headscale -mindepth 1 -maxdepth 1 -print -quit)"; then
    printf 'Refusing an existing nonempty Headscale data directory.\n' >&2
    exit 1
fi
if ! getent group headscale >/dev/null; then
    groupadd --system headscale
fi
if ! getent passwd headscale >/dev/null; then
    useradd --system --gid headscale --home-dir /var/lib/headscale --shell /sbin/nologin headscale
fi
install -d -m 0750 -o root -g headscale /etc/headscale
install -d -m 0700 -o headscale -g headscale /var/lib/headscale
install -m 0755 -o root -g root "$TASK_BINARY" /usr/local/bin/headscale
install -m 0640 -o root -g headscale "$TASK_DIR/config.yaml" /etc/headscale/config.yaml
install -m 0640 -o root -g headscale "$TASK_DIR/policy.hujson" /etc/headscale/policy.hujson
install -m 0640 -o root -g headscale "$TASK_DIR/derp-public.yaml" /etc/headscale/derp-public.yaml
install -d -m 0700 -o root -g root /usr/local/libexec/headscale
install -m 0700 -o root -g root "$TASK_DIR/refresh-derp-map.py" /usr/local/libexec/headscale/refresh-derp-map.py
install -m 0644 -o root -g root "$TASK_DIR/headscale.service" /etc/systemd/system/headscale.service
# configtest creates keys/opens SQLite, so it must run as the service user.
runuser -u headscale -- /usr/local/bin/headscale --config /etc/headscale/config.yaml configtest
python /usr/local/libexec/headscale/refresh-derp-map.py init-receipt
systemctl daemon-reload
printf 'Installed and configuration validated. Service remains stopped and disabled.\n'
printf 'Merge/validate Caddy, add UDP 3478 in the existing firewall zone, then start and verify.\n'
