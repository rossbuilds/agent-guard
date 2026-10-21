#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." 2>/dev/null && pwd)"
TARGET="${ROOT_DIR}/agent_guard.py"
OUT="${ROOT_DIR}/SHA256SUMS"

python3 - "$TARGET" "$OUT" <<'PY'
import hashlib
import os
import tempfile
import sys

target = os.path.abspath(sys.argv[1])
out_path = os.path.abspath(sys.argv[2])
name = os.path.basename(target)

h = hashlib.sha256()
with open(target, "rb") as f:
    for chunk in iter(lambda: f.read(65536), b""):
        h.update(chunk)

line = f"{h.hexdigest()}  {name}\n"
parent = os.path.dirname(out_path) or "."
fd, tmp = tempfile.mkstemp(prefix=".sha256sums.", suffix=".tmp", dir=parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(line)
    os.replace(tmp, out_path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
PY

echo "Wrote ${OUT}"
