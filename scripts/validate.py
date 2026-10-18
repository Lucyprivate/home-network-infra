#!/usr/bin/env python3
"""Parse public source and rendered examples without running deployment code."""
import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", "build", "__pycache__", ".venv", "node_modules"}


def validate(root, links=True):
    import yaml
    counts = {"python": 0, "json": 0, "yaml": 0, "javascript": 0, "shell": 0, "markdown_links": 0}
    errors = []
    node = os.environ.get("NODE_BINARY") or shutil.which("node")
    bash = os.environ.get("BASH_BINARY") or shutil.which("bash")
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if not path.is_file() or any(part in SKIP for part in rel.parts):
            continue
        if path.name.endswith(".tmpl"):
            continue
        try:
            if path.suffix == ".py":
                ast.parse(path.read_text(encoding="utf-8-sig"), filename=rel.as_posix())
                counts["python"] += 1
            elif path.suffix in (".json", ".hujson"):
                json.loads(path.read_text(encoding="utf-8-sig"))
                counts["json"] += 1
            elif path.suffix in (".yaml", ".yml"):
                list(yaml.safe_load_all(path.read_text(encoding="utf-8-sig")))
                counts["yaml"] += 1
            elif path.suffix in (".js", ".cjs"):
                if not node:
                    raise ValueError("Node.js is required to parse retained JavaScript")
                subprocess.run([node, "--check", str(path)], check=True, capture_output=True, timeout=20)
                counts["javascript"] += 1
            elif path.suffix == ".sh" or (not path.suffix and path.read_bytes().startswith((b'#!/bin/sh', b'#!/bin/bash', b'#!/sbin/openrc-run'))):
                if not bash:
                    raise ValueError("Bash is required for shell syntax checks")
                subprocess.run([bash, "-n", str(path)], check=True, capture_output=True, timeout=20)
                counts["shell"] += 1
            elif path.suffix == ".md" and links:
                for link in re.findall(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
                    link = link.split("#", 1)[0]
                    if not link or re.match(r"[a-zA-Z]+:", link):
                        continue
                    target = (path.parent / link.strip("<>")).resolve()
                    if not target.exists() or not target.is_relative_to(ROOT):
                        raise ValueError("Missing or external local Markdown link")
                    counts["markdown_links"] += 1
        except (OSError, ValueError, SyntaxError, UnicodeError, subprocess.SubprocessError, yaml.YAMLError) as error:
            errors.append({"path": rel.as_posix(), "error": type(error).__name__, "detail": str(error)[:200]})
    return {"passed": not errors, "checks": counts, "errors": errors}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rendered", type=Path)
    args = parser.parse_args()
    results = {"source": validate(ROOT)}
    if args.rendered:
        if not args.rendered.is_dir():
            parser.error("Rendered directory does not exist")
        results["rendered"] = validate(args.rendered.resolve(), links=False)
    print(json.dumps(results, indent=2))
    sys.exit(0 if all(r["passed"] for r in results.values()) else 1)
