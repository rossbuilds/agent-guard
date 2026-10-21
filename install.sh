#!/usr/bin/env bash
# agent-guard installer for Claude Code PreToolUse hooks.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/rossbuilds/agent-guard/v0.1.0/install.sh | bash
#   git clone https://github.com/rossbuilds/agent-guard.git && cd agent-guard && ./install.sh
#   AGENT_GUARD_VERSION=v0.1.0 ./install.sh
#   ./install.sh --uninstall  # remove
# HOME may be overridden for testing: HOME=/tmp/foo ./install.sh

set -euo pipefail

UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --uninstall|-u) UNINSTALL=1 ;;
    --help|-h)
      echo "Usage: install.sh [--uninstall]"
      exit 0
      ;;
    *)
      echo "error: unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

HOME_DIR="${HOME:-}"
if [[ -z "$HOME_DIR" ]]; then
  echo "error: HOME is not set" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 1
fi

HOOK_DIR="${HOME_DIR}/.claude/hooks/agent-guard"
HOOK_SCRIPT="${HOOK_DIR}/agent_guard.py"
SETTINGS="${HOME_DIR}/.claude/settings.json"
AGENT_GUARD_VERSION="${AGENT_GUARD_VERSION:-v0.1.0}"
HOOK_TIMEOUT_SECONDS=10

# Resolve source of agent_guard.py (same dir as this script, or download)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
SOURCE_PY=""
if [[ -n "${SCRIPT_DIR}" && -f "${SCRIPT_DIR}/agent_guard.py" ]]; then
  SOURCE_PY="${SCRIPT_DIR}/agent_guard.py"
fi

REPO_BASE="https://raw.githubusercontent.com/rossbuilds/agent-guard/${AGENT_GUARD_VERSION}"
REPO_RAW="${REPO_BASE}/agent_guard.py"
REPO_SUMS="${REPO_BASE}/SHA256SUMS"

TMP_FILES=()
CREATED_HOOK_DIR=0
INSTALL_OK=0

cleanup() {
  local f
  for f in "${TMP_FILES[@]+"${TMP_FILES[@]}"}"; do
    rm -f -- "$f"
  done
  if [[ "${CREATED_HOOK_DIR}" -eq 1 && "${INSTALL_OK}" -ne 1 && -d "${HOOK_DIR}" ]]; then
    rmdir -- "${HOOK_DIR}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

make_tmp() {
  local dir="$1"
  local f
  f="$(mktemp "${dir}/.agent-guard.XXXXXX")"
  TMP_FILES+=("$f")
  printf '%s\n' "$f"
}

timestamp_utc() {
  date -u +"%Y%m%d%H%M%S"
}

backup_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    return 0
  fi
  local ts
  ts="$(timestamp_utc)"
  local backup="${path}.bak.agent-guard.${ts}.$$"
  cp -p -- "$path" "$backup"
  echo "Backup written: ${backup}"
}

download_file() {
  local url="$1"
  local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
    return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
    return 0
  fi
  echo "error: curl or wget is required to download ${url}" >&2
  exit 1
}

verify_checksum() {
  local payload="$1"
  local sums="$2"
  python3 - "$payload" "$sums" <<'PY'
import hashlib
import os
import re
import sys

payload_path = sys.argv[1]
sums_path = sys.argv[2]
target_name = "agent_guard.py"

expected = None
with open(sums_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", line)
        if not m:
            continue
        if os.path.basename(m.group(2)) == target_name:
            expected = m.group(1).lower()
            break

if not expected:
    print("error: SHA256SUMS missing entry for agent_guard.py", file=sys.stderr)
    sys.exit(1)

h = hashlib.sha256()
with open(payload_path, "rb") as f:
    for chunk in iter(lambda: f.read(65536), b""):
        h.update(chunk)
actual = h.hexdigest().lower()

if actual != expected:
    print("error: checksum mismatch for agent_guard.py", file=sys.stderr)
    print(f"expected={expected}", file=sys.stderr)
    print(f"actual={actual}", file=sys.stderr)
    sys.exit(1)
PY
}

# Edit settings.json in place (atomic replace, permissions preserved).
# Aborts without writing if the file is not a JSON object with the expected shape.
update_settings() {
  local action="$1"
  python3 - "$action" "$SETTINGS" "$HOOK_SCRIPT" "$HOOK_TIMEOUT_SECONDS" <<'PY'
import json
import os
import shlex
import stat
import sys
import tempfile

action, settings_path, hook_script, timeout = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
hook_script = os.path.abspath(hook_script)


def fail(msg):
    print(f"error: {settings_path}: {msg}; not modified", file=sys.stderr)
    sys.exit(1)


exists = os.path.exists(settings_path)
if exists:
    try:
        with open(settings_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, UnicodeDecodeError, ValueError) as e:
        fail(f"cannot parse JSON ({e.__class__.__name__})")
else:
    if action == "uninstall":
        print("No settings.json to update.")
        sys.exit(0)
    data = {}

if not isinstance(data, dict):
    fail("top-level value must be an object")
hooks = data.get("hooks", {})
if not isinstance(hooks, dict):
    fail("'hooks' must be an object")
ptu = hooks.get("PreToolUse", [])
if not isinstance(ptu, list):
    fail("'hooks.PreToolUse' must be a list")


def is_ours(h):
    if not isinstance(h, dict):
        return False
    cmd = h.get("command")
    args = h.get("args")
    if cmd == "python3" and args == [hook_script]:
        return True
    if args is None and isinstance(cmd, str):
        try:
            parts = shlex.split(cmd)
        except ValueError:
            return False
        return parts in ([hook_script], ["python3", hook_script])
    return False


ours = {
    "type": "command",
    "command": "python3",
    "args": [hook_script],
    "timeout": timeout,
    "onFailure": "block",
}

new_ptu = []
placed = False
for entry in ptu:
    if not isinstance(entry, dict) or not isinstance(entry.get("hooks", []), list):
        new_ptu.append(entry)
        continue
    inner = entry.get("hooks", [])
    kept = [h for h in inner if not is_ours(h)]
    if action == "install" and not placed and entry.get("matcher") == "Bash":
        kept.append(ours)
        placed = True
    if kept or not inner or len(kept) == len(inner):
        entry = dict(entry)
        entry["hooks"] = kept
        new_ptu.append(entry)

if action == "install" and not placed:
    new_ptu.append({"matcher": "Bash", "hooks": [ours]})

if new_ptu:
    hooks["PreToolUse"] = new_ptu
else:
    hooks.pop("PreToolUse", None)
if hooks:
    data["hooks"] = hooks
else:
    data.pop("hooks", None)

parent = os.path.dirname(settings_path) or "."
mode = stat.S_IMODE(os.stat(settings_path).st_mode) if exists else 0o666 & ~_umask if (_umask := os.umask(0)) is not None and os.umask(_umask) is not None else 0o644
fd, tmp = tempfile.mkstemp(prefix=".settings.agent-guard.", suffix=".tmp", dir=parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.chmod(tmp, mode)
    os.replace(tmp, settings_path)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
print(f"Updated {settings_path}")
PY
}

uninstall() {
  if [[ -f "${SETTINGS}" ]]; then
    backup_file "${SETTINGS}"
  fi
  update_settings uninstall
  if [[ -f "${HOOK_SCRIPT}" ]]; then
    rm -f -- "${HOOK_SCRIPT}"
    echo "Removed ${HOOK_SCRIPT}"
  fi
  if [[ -d "${HOOK_DIR}" ]]; then
    rmdir -- "${HOOK_DIR}" 2>/dev/null || echo "Left ${HOOK_DIR} in place (not empty)."
  fi
  echo "agent-guard uninstalled."
}

install() {
  local staging_dir
  staging_dir="$(mktemp -d)"
  TMP_FILES+=("${staging_dir}/agent_guard.py" "${staging_dir}/SHA256SUMS")
  local payload="${staging_dir}/agent_guard.py"
  local sums="${staging_dir}/SHA256SUMS"

  if [[ -n "${SOURCE_PY}" ]]; then
    cp -- "${SOURCE_PY}" "${payload}"
    if [[ -f "${SCRIPT_DIR}/SHA256SUMS" ]]; then
      cp -- "${SCRIPT_DIR}/SHA256SUMS" "${sums}"
    elif [[ "${AGENT_GUARD_SKIP_VERIFY:-}" == "1" ]]; then
      echo "WARNING: AGENT_GUARD_SKIP_VERIFY=1 — SHA256SUMS missing; installing WITHOUT checksum verification." >&2
      echo "WARNING: This is unsafe. Regenerate checksums with 'make checksums' for production use." >&2
    else
      echo "error: ${SCRIPT_DIR}/SHA256SUMS not found; refusing to install an unverified hook." >&2
      echo "       Run 'make checksums' after editing agent_guard.py." >&2
      echo "       (Set AGENT_GUARD_SKIP_VERIFY=1 only for local dev to bypass this check.)" >&2
      rmdir -- "${staging_dir}" 2>/dev/null || true
      exit 1
    fi
  else
    download_file "${REPO_RAW}" "${payload}"
    if [[ "${AGENT_GUARD_SKIP_VERIFY:-}" == "1" ]]; then
      echo "WARNING: AGENT_GUARD_SKIP_VERIFY=1 — skipping SHA256SUMS download and verification." >&2
    else
      download_file "${REPO_SUMS}" "${sums}"
    fi
  fi
  if [[ -f "${sums}" ]]; then
    if ! verify_checksum "${payload}" "${sums}"; then
      rm -f -- "${payload}" "${sums}"
      rmdir -- "${staging_dir}" 2>/dev/null || true
      exit 1
    fi
  fi

  # Validate settings.json before touching anything on disk.
  if [[ -f "${SETTINGS}" ]]; then
    python3 - "${SETTINGS}" <<'PY'
import json, sys
path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
except (OSError, UnicodeDecodeError, ValueError) as e:
    print(f"error: {path}: cannot parse JSON ({e.__class__.__name__}); fix it and re-run", file=sys.stderr)
    sys.exit(1)
if not isinstance(data, dict):
    print(f"error: {path}: top-level value must be an object", file=sys.stderr)
    sys.exit(1)
PY
  fi

  if [[ ! -d "${HOOK_DIR}" ]]; then
    mkdir -p -- "${HOOK_DIR}"
    CREATED_HOOK_DIR=1
  fi
  mkdir -p -- "$(dirname "${SETTINGS}")"

  local tmp_hook
  tmp_hook="$(make_tmp "${HOOK_DIR}")"
  cp -- "${payload}" "${tmp_hook}"
  chmod 0755 "${tmp_hook}"
  mv -f -- "${tmp_hook}" "${HOOK_SCRIPT}"
  rm -f -- "${payload}" "${sums}"
  rmdir -- "${staging_dir}" 2>/dev/null || true
  echo "Installed ${HOOK_SCRIPT} (version ${AGENT_GUARD_VERSION})"

  backup_file "${SETTINGS}"
  update_settings install
  INSTALL_OK=1

  echo "agent-guard installed. PreToolUse matcher=Bash -> python3 ${HOOK_SCRIPT} (timeout ${HOOK_TIMEOUT_SECONDS}s, onFailure=block)"
}

if [[ "${UNINSTALL}" -eq 1 ]]; then
  uninstall
else
  install
fi
