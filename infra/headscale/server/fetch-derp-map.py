#!/usr/bin/env python3
"""Fetch and validate the official public map into a NEW staging file only."""
import importlib.util
import os
from pathlib import Path
import sys
import urllib.request

MODULE = Path(__file__).with_name('refresh-derp-map.py')
spec = importlib.util.spec_from_file_location('derp_validator', MODULE)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

def main():
    if len(sys.argv) != 2:
        raise ValueError('Usage: python3 fetch-derp-map.py NEW_OUTPUT_FILE')
    output = Path(sys.argv[1])
    request = urllib.request.Request(validator.URL, headers={'User-Agent': 'home-network-infra'})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(validator.MAX_BYTES + 1)
    rendered, summary = validator.validate(raw)
    # Exclusive creation prevents accidental replacement of a live map.
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(rendered)
        stream.flush()
        os.fsync(stream.fileno())
    print('Validated public map: %s regions, %s nodes' % (summary['regions'], summary['nodes']))

if __name__ == '__main__':
    main()
