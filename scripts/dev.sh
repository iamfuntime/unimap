#!/usr/bin/env bash
# UniMap dev harness — run inside WSL Ubuntu-24.04.
# Usage: dev.sh {setup|test|run ...}
set -euo pipefail
REPO="/mnt/c/Users/Seth Feldman/git/unimap"
VENV="$HOME/.venvs/unimap"
cd "$REPO"
case "${1:-}" in
  setup)
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --upgrade pip >/dev/null
    "$VENV/bin/pip" install -e ".[dev]"
    ;;
  test)
    shift
    "$VENV/bin/python" -m pytest "$@"
    ;;
  run)
    shift
    "$VENV/bin/python" -m unimap "$@"
    ;;
  *)
    echo "usage: dev.sh {setup|test|run ...}" >&2; exit 2 ;;
esac
