#!/usr/bin/env bash
# CentOS 7 static-client installation only. Registration and ACLs are separate.
set -Eeuo pipefail
export LC_ALL=C
umask 077

readonly TASK_VERSION=1.104.1
readonly ARCHIVE_SHA=108d1d96ecf410d305571e173516f27038f870919a9b89c914a167c6d33a4528
readonly ARCHIVE_URL=https://pkgs.tailscale.com/stable/tailscale_1.104.1_amd64.tgz
readonly RECORD_DIR=/var/lib/home-network-exit-install
readonly OWNER=$RECORD_DIR/installer-owner.tsv
readonly CLIENT=/usr/local/bin/tailscale
readonly DAEMON=/usr/local/sbin/tailscaled
readonly UNIT=/etc/systemd/system/tailscaled.service
readonly SYSCTL_FILE=/etc/sysctl.d/99-headscale-exit.conf
readonly ZONE=vps-secure
readonly PORT=41641/udp
MODE=install
CLIENTS_DISCONNECTED=0
TMP=''
MUTATING=0
CLIENT_SHA=''
DAEMON_SHA=''
UNIT_SHA=''
SYSCTL_SHA=''
IPV6_BEFORE=''
IPV6_CHANGED=0
RUNTIME_PORT_BEFORE=''
PERMANENT_PORT_BEFORE=''

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' "Usage: sudo bash $0 [--rollback --clients-disconnected]" \
        'Installs the fixed official static binaries and an unregistered daemon.' \
        "Rollback removes only this installer's files and additions; it preserves node state."
}
while (($#)); do
    case $1 in
        --rollback) MODE=rollback ;;
        --clients-disconnected) CLIENTS_DISCONNECTED=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done
[[ $EUID == 0 ]] || fail 'Run as root. Do not place passwords in this script.'
for tool in curl tar sha256sum stat install mktemp systemctl firewall-cmd sysctl awk uname pgrep ip; do
    command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool"
done
[[ $(uname -m) == x86_64 ]] || fail 'Only the verified amd64 archive is supported.'
[[ ! -L $RECORD_DIR ]] || fail 'Refusing a symlink record directory.'
if [[ -e $RECORD_DIR ]]; then
    [[ -d $RECORD_DIR && $(stat -c %u "$RECORD_DIR") == 0 && $(stat -c %a "$RECORD_DIR") == 700 ]] \
        || fail 'The shared record directory must be a root-owned directory with mode 0700.'
fi

write_receipt() {
    local status=$1 staged
    staged=$(mktemp "$RECORD_DIR/.installer-owner.XXXXXX")
    {
        printf 'schema\t%s\n' 1
        printf 'status\t%s\n' "$status"
        printf 'version\t%s\n' "$TASK_VERSION"
        printf 'archive_sha256\t%s\n' "$ARCHIVE_SHA"
        printf 'client_sha256\t%s\n' "$CLIENT_SHA"
        printf 'daemon_sha256\t%s\n' "$DAEMON_SHA"
        printf 'unit_sha256\t%s\n' "$UNIT_SHA"
        printf 'sysctl_sha256\t%s\n' "$SYSCTL_SHA"
        printf 'ipv6_before\t%s\n' "$IPV6_BEFORE"
        printf 'ipv6_changed\t%s\n' "$IPV6_CHANGED"
        printf 'runtime_port_before\t%s\n' "$RUNTIME_PORT_BEFORE"
        printf 'permanent_port_before\t%s\n' "$PERMANENT_PORT_BEFORE"
    } > "$staged"
    # The receipt contains no credentials, registration key, or node state.
    chmod 600 "$staged"
    mv -f -- "$staged" "$OWNER"
}
field() { awk -F '\t' -v key="$1" '$1 == key { print $2; found++ } END { if (found != 1) exit 1 }' "$OWNER"; }
same_file_or_absent() {
    local path=$1 hash=$2
    [[ ! -e $path && ! -L $path ]] && return 0
    [[ -f $path && ! -L $path && $(stat -c %u "$path") == 0 && $(sha256sum "$path" | awk '{print $1}') == "$hash" ]]
}
rollback_owned() {
    local bad=0 current query_exit
    # Check all owned file hashes before touching any service or firewall rule.
    same_file_or_absent "$CLIENT" "$CLIENT_SHA" || { printf '%s\n' 'Client ownership changed; rollback refused.' >&2; return 1; }
    same_file_or_absent "$DAEMON" "$DAEMON_SHA" || { printf '%s\n' 'Daemon ownership changed; rollback refused.' >&2; return 1; }
    same_file_or_absent "$UNIT" "$UNIT_SHA" || { printf '%s\n' 'Unit ownership changed; rollback refused.' >&2; return 1; }
    if [[ $IPV6_CHANGED == 1 ]]; then
        same_file_or_absent "$SYSCTL_FILE" "$SYSCTL_SHA" || { printf '%s\n' 'Sysctl ownership changed; rollback refused.' >&2; return 1; }
    fi
    if [[ -f $UNIT ]]; then
        systemctl stop tailscaled.service || return 1
        systemctl disable tailscaled.service || bad=1
    fi
    if [[ $RUNTIME_PORT_BEFORE == 0 ]]; then
        if firewall-cmd --zone="$ZONE" --query-port="$PORT" >/dev/null; then
            firewall-cmd --zone="$ZONE" --remove-port="$PORT" || bad=1
        else
            query_exit=$?; [[ $query_exit == 1 ]] || bad=1
        fi
    fi
    if [[ $PERMANENT_PORT_BEFORE == 0 ]]; then
        if firewall-cmd --permanent --zone="$ZONE" --query-port="$PORT" >/dev/null; then
            firewall-cmd --permanent --zone="$ZONE" --remove-port="$PORT" || bad=1
        else
            query_exit=$?; [[ $query_exit == 1 ]] || bad=1
        fi
    fi
    if [[ $IPV6_CHANGED == 1 ]]; then
        current=$(sysctl -n net.ipv6.conf.all.forwarding) || return 1
        [[ $current == 0 || $current == 1 ]] || return 1
        sysctl -w "net.ipv6.conf.all.forwarding=$IPV6_BEFORE" || bad=1
        [[ $bad == 0 ]] && rm -f -- "$SYSCTL_FILE"
    fi
    if [[ $bad == 0 ]]; then
        rm -f -- "$UNIT" "$CLIENT" "$DAEMON"
        systemctl daemon-reload || bad=1
    fi
    if [[ $bad == 0 ]]; then
        write_receipt rolled-back
        printf '%s\n' "Removed this installer's additions. /var/lib/tailscale is preserved."
    else
        write_receipt rollback-incomplete
        printf '%s\n' "Rollback incomplete; inspect $OWNER. State and keys have been preserved." >&2
    fi
    return "$bad"
}
cleanup() {
    local rc=$?
    trap - EXIT
    if [[ $rc != 0 && $MUTATING == 1 ]]; then
        printf '%s\n' "Installation failed; reverting only this installer's additions." >&2
        rollback_owned || true
    fi
    [[ -z $TMP ]] || rm -rf -- "$TMP"
    exit "$rc"
}
trap cleanup EXIT

if [[ $MODE == rollback ]]; then
    [[ $CLIENTS_DISCONNECTED == 1 ]] || fail 'First disconnect all clients from this exit node, then add --clients-disconnected.'
    [[ -f $OWNER && ! -L $OWNER && $(stat -c %u "$OWNER") == 0 && $(stat -c %a "$OWNER") == 600 ]] \
        || fail 'No protected installer ownership receipt; no changes made.'
    [[ $(field schema) == 1 && $(field version) == "$TASK_VERSION" && $(field archive_sha256) == "$ARCHIVE_SHA" ]] \
        || fail 'Installer receipt identity mismatch.'
    CLIENT_SHA=$(field client_sha256); DAEMON_SHA=$(field daemon_sha256); UNIT_SHA=$(field unit_sha256)
    SYSCTL_SHA=$(field sysctl_sha256); IPV6_BEFORE=$(field ipv6_before); IPV6_CHANGED=$(field ipv6_changed)
    RUNTIME_PORT_BEFORE=$(field runtime_port_before); PERMANENT_PORT_BEFORE=$(field permanent_port_before)
    for value in "$CLIENT_SHA" "$DAEMON_SHA" "$UNIT_SHA"; do
        [[ $value =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid receipt file hash.'
    done
    [[ $IPV6_BEFORE =~ ^[01]$ && $IPV6_CHANGED =~ ^[01]$ && $RUNTIME_PORT_BEFORE =~ ^[01]$ && $PERMANENT_PORT_BEFORE =~ ^[01]$ ]] \
        || fail 'Invalid receipt flags.'
    [[ $IPV6_CHANGED == 0 || $SYSCTL_SHA =~ ^[0-9a-f]{64}$ ]] || fail 'Invalid sysctl receipt hash.'
    rollback_owned
    exit 0
fi

[[ $CLIENTS_DISCONNECTED == 0 ]] || fail '--clients-disconnected is only valid with --rollback.'
TASK_OS_ID=$( . /etc/os-release; printf '%s' "$ID")
TASK_OS_VERSION=$( . /etc/os-release; printf '%s' "$VERSION_ID")
[[ $TASK_OS_ID == centos && $TASK_OS_VERSION == 7* ]] || fail 'This installer was prepared for the inspected CentOS 7 host.'
[[ -c /dev/net/tun ]] || fail '/dev/net/tun is unavailable.'
for tool in iptables ip6tables; do command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool"; done
systemctl is-active --quiet firewalld.service || fail 'The existing firewalld must be active.'
[[ $(firewall-cmd --get-zone-of-interface=eth0) == "$ZONE" ]] || fail 'eth0 is no longer in the inspected vps-secure zone.'
[[ $(sysctl -n net.ipv4.ip_forward) == 1 ]] || fail 'Existing IPv4 forwarding is no longer enabled; no changes made.'
[[ ! -e $OWNER && ! -L $OWNER ]] || fail 'An installer receipt already exists; inspect it rather than overwriting it.'
for path in "$CLIENT" "$DAEMON" "$UNIT" "$SYSCTL_FILE" /var/lib/tailscale /run/tailscale; do
    [[ ! -e $path && ! -L $path ]] || fail "Existing path is not replaced: $path"
done
! command -v tailscale >/dev/null || fail 'Another tailscale binary already exists.'
! command -v tailscaled >/dev/null || fail 'Another tailscaled binary already exists.'
! pgrep -x tailscaled >/dev/null || fail 'An existing tailscaled process was found.'
! systemctl cat tailscaled.service >/dev/null 2>&1 || fail 'An existing tailscaled unit was found.'
IPV6_BEFORE=$(sysctl -n net.ipv6.conf.all.forwarding)
[[ $IPV6_BEFORE == 0 || $IPV6_BEFORE == 1 ]] || fail 'Unexpected IPv6 forwarding value.'
if firewall-cmd --zone="$ZONE" --query-port="$PORT" >/dev/null; then
    RUNTIME_PORT_BEFORE=1
else
    query_exit=$?; [[ $query_exit == 1 ]] || fail 'Cannot inspect the runtime firewall port.'
    RUNTIME_PORT_BEFORE=0
fi
if firewall-cmd --permanent --zone="$ZONE" --query-port="$PORT" >/dev/null; then
    PERMANENT_PORT_BEFORE=1
else
    query_exit=$?; [[ $query_exit == 1 ]] || fail 'Cannot inspect the permanent firewall port.'
    PERMANENT_PORT_BEFORE=0
fi

TMP=$(mktemp -d /root/.headscale-exit-install.XXXXXX)
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 --retry 2 \
    --silent --show-error "$ARCHIVE_URL" -o "$TMP/tailscale.tgz"
printf '%s  %s\n' "$ARCHIVE_SHA" "$TMP/tailscale.tgz" | sha256sum --check --status || fail 'Official archive SHA256 mismatch.'
tar --no-same-owner -xzf "$TMP/tailscale.tgz" -C "$TMP" \
    "tailscale_${TASK_VERSION}_amd64/tailscale" "tailscale_${TASK_VERSION}_amd64/tailscaled"
for binary in tailscale tailscaled; do
    path=$TMP/tailscale_${TASK_VERSION}_amd64/$binary
    [[ -f $path && ! -L $path ]] || fail "Archive does not contain the expected regular binary: $binary"
    if [[ $binary == tailscale ]]; then version_text=$("$path" version); else version_text=$("$path" --version); fi
    [[ ${version_text%%$'\n'*} == "$TASK_VERSION" ]] || fail "The verified $binary binary cannot report the expected version."
done
cat > "$TMP/tailscaled.service" <<'UNIT'
[Unit]
Description=Tailscale node agent (fixed official static 1.104.1)
Wants=network-online.target
After=firewalld.service network-online.target headscale.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/run/tailscale/tailscaled.sock --port=41641 --tun=tailscale0
ExecStopPost=/usr/local/sbin/tailscaled --cleanup
Restart=on-failure
RestartSec=5
RuntimeDirectory=tailscale
RuntimeDirectoryMode=0700
LimitNOFILE=524288

[Install]
WantedBy=multi-user.target
UNIT
printf '%s\n' '# Owned by headscale-exit installer.' 'net.ipv6.conf.all.forwarding = 1' > "$TMP/99-headscale-exit.conf"
CLIENT_SHA=$(sha256sum "$TMP/tailscale_${TASK_VERSION}_amd64/tailscale" | awk '{print $1}')
DAEMON_SHA=$(sha256sum "$TMP/tailscale_${TASK_VERSION}_amd64/tailscaled" | awk '{print $1}')
UNIT_SHA=$(sha256sum "$TMP/tailscaled.service" | awk '{print $1}')
if [[ $IPV6_BEFORE == 0 ]]; then
    IPV6_CHANGED=1
    SYSCTL_SHA=$(sha256sum "$TMP/99-headscale-exit.conf" | awk '{print $1}')
fi
[[ -d $RECORD_DIR ]] || install -d -m 700 "$RECORD_DIR"
ip -4 route show table all > "$RECORD_DIR/installer-ipv4-routes-before.txt"
ip -6 route show table all > "$RECORD_DIR/installer-ipv6-routes-before.txt"
firewall-cmd --direct --get-all-rules > "$RECORD_DIR/installer-firewalld-direct-before.txt"
write_receipt prepared
MUTATING=1
install -m 755 "$TMP/tailscale_${TASK_VERSION}_amd64/tailscale" "$CLIENT"
install -m 755 "$TMP/tailscale_${TASK_VERSION}_amd64/tailscaled" "$DAEMON"
install -m 644 "$TMP/tailscaled.service" "$UNIT"
install -d -m 700 /var/lib/tailscale
if [[ $IPV6_CHANGED == 1 ]]; then
    install -m 644 "$TMP/99-headscale-exit.conf" "$SYSCTL_FILE"
    sysctl -w net.ipv6.conf.all.forwarding=1
fi
[[ $RUNTIME_PORT_BEFORE == 1 ]] || firewall-cmd --zone="$ZONE" --add-port="$PORT"
[[ $PERMANENT_PORT_BEFORE == 1 ]] || firewall-cmd --permanent --zone="$ZONE" --add-port="$PORT"
# Do not reload firewalld: preserve the existing live WireGuard/direct rules.
systemctl daemon-reload
systemctl enable tailscaled.service
systemctl start tailscaled.service
READY=0
for ((attempt=0; attempt<20; attempt++)); do
    # Reading local preferences works while logged out; do not require Running.
    if [[ -S /run/tailscale/tailscaled.sock ]] && "$CLIENT" debug prefs >/dev/null 2>&1; then READY=1; break; fi
    sleep 1
done
[[ $READY == 1 ]] || fail 'The unregistered daemon did not become ready in 20 seconds.'
systemctl is-active --quiet tailscaled.service || fail 'tailscaled exited after startup.'
write_receipt installed
MUTATING=0
printf '%s\n' "Installed Tailscale $TASK_VERSION; daemon is unregistered. Receipt: $OWNER" \
    'No registration, ACL, default route, WireGuard, Caddy, or Headscale configuration was changed.' \
    'IPv6 forwarding is enabled for the advertised exit route; this VPS has no public IPv6 uplink.' \
    'Clients must keep the exit node selected for both IP families; public IPv6 must fail rather than bypass it.'
