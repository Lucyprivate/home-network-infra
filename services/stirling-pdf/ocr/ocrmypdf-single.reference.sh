#!/bin/sh
# Public reference integration, not the historical deployment wrapper.
set -eu
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK=True
lab=/usr/local/share/stirling-paddle-order2-lab
# Prevent requests from replacing fixed concurrency, plugins or model pins.
for arg in "$@"; do
    case "$arg" in
        --jobs|--jobs=*|-j|-j[0-9]*|--plugin|--plugin=*|--paddle-*)
            echo 'Fixed OCR runtime option cannot be overridden' >&2; exit 2 ;;
    esac
done
# Exit 75 when the only job slot is busy. Child timeout retains process-group semantics.
exec /usr/bin/flock -n -E 75 /tmp/stirling-ocr.lock \
    /usr/bin/timeout --signal=TERM --kill-after=10s 900s \
    "$lab/venv/bin/python3" -I -B -m ocrmypdf --jobs 1 \
    --plugin "$lab/profiles/geometry5/paddle_plugin.py" \
    --paddle-det-dir "$lab/models/det" --paddle-rec-dir "$lab/models/rec-small" \
    --paddle-probe-sha256 e54d1b413a676d85b8df4738d511cc017c86f2f96be0e4b1e2683305c3509998 "$@"
