#!/usr/bin/env bash
#
# verify.sh
# ---------
# POSIX shell wrapper for verify.py. Runs end-to-end verification for CI / pre-commit.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_CMD=""

if command -v python3 &>/dev/null; then
  PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
  PYTHON_CMD="python"
else
  echo "[ERROR] Neither python3 nor python was found in PATH." >&2
  exit 1
fi

exec "$PYTHON_CMD" "$SCRIPT_DIR/verify.py" "$@"
