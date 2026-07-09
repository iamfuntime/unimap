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
    # Do NOT editable-install the package: `pip install -e .` chmods egg-info in
    # the /mnt/c source tree, which DrvFS rejects (Operation not permitted). The
    # package is imported straight from the source tree instead — both pytest and
    # `python -m` put REPO (the cwd) on sys.path.
    "$VENV/bin/pip" install pytest pyyaml
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
