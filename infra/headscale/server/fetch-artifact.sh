#!/bin/bash
# Download public release artifacts; never installs or starts a service.
set -euo pipefail
umask 022
TASK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TASK_VENDOR="$TASK_DIR/vendor"
TASK_NAME=headscale_0.29.5_linux_amd64
TASK_SHA=e979d27fe17d924d33bb6ab7504f6338d0635989a0cfdcfbc0ceb637dbcbe980
TASK_BASE=https://github.com/juanfont/headscale/releases/download/v0.29.5
mkdir -p "$TASK_VENDOR"
TASK_TMP=$(mktemp -d "$TASK_VENDOR/.download.XXXXXX")
trap 'rm -rf -- "$TASK_TMP"' EXIT
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 180 --retry 2 \
    "$TASK_BASE/checksums.txt" -o "$TASK_TMP/checksums.txt"
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 180 --retry 2 \
    "$TASK_BASE/$TASK_NAME" -o "$TASK_TMP/$TASK_NAME"
TASK_LISTED=$(awk -v name="$TASK_NAME" '$2 == name {print $1}' "$TASK_TMP/checksums.txt")
test "$TASK_LISTED" = "$TASK_SHA"
printf '%s  %s\n' "$TASK_SHA" "$TASK_TMP/$TASK_NAME" | sha256sum --check --status
chmod 0755 "$TASK_TMP/$TASK_NAME"
mv -f -- "$TASK_TMP/$TASK_NAME" "$TASK_VENDOR/$TASK_NAME"
mv -f -- "$TASK_TMP/checksums.txt" "$TASK_VENDOR/checksums.txt"
printf 'Verified official Headscale 0.29.5 amd64: %s\n' "$TASK_SHA"
