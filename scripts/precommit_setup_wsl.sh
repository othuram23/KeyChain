#!/usr/bin/env bash
# precommit_setup_wsl.sh
# Usage: run this script from WSL (kali) or via PowerShell with WSL:
#  wsl -d kali-linux -- bash -lc "cd /mnt/c/Users/Admin/KeyChain && bash scripts/precommit_setup_wsl.sh"
# What it does:
#  - creates an isolated virtualenv in the repo (.precommit-venv)
#  - installs/updates pre-commit inside the venv
#  - tunes git network settings to reduce fetch errors
#  - clears pre-commit cache, installs hooks and runs them on all files (verbose)
#  - writes detailed logs to ./precommit_setup.log and ./precommit_verbose.txt

set -euo pipefail
IFS=$'\n\t'

LOGFILE="$(pwd)/precommit_setup.log"
VERBOSE_OUT="$(pwd)/precommit_verbose.txt"
exec > >(tee -a "$LOGFILE") 2>&1

echo "[precommit-setup] START: $(date -u)"

# 1) Basic checks
if ! command -v git >/dev/null 2>&1; then
  echo "[error] git is required but not found in PATH. Aborting."; exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[error] python3 is required but not found in PATH. Aborting."; exit 1
fi

REPO_DIR="$(pwd)"
echo "[info] Repo dir: $REPO_DIR"

# 2) Remove previous pre-commit cache (safe)
echo "[info] Removing pre-commit cache (~/.cache/pre-commit) if exists..."
rm -rf "$HOME/.cache/pre-commit" || true

# 3) Create virtualenv for pre-commit
VENV_DIR="$REPO_DIR/.precommit-venv"
if [[ -d "$VENV_DIR" ]]; then
  echo "[info] Virtualenv already exists at $VENV_DIR. Reusing it."
else
  echo "[info] Creating virtualenv at $VENV_DIR..."
  python3 -m venv "$VENV_DIR"
fi

# 4) Activate venv
# shellcheck disable=SC1091
. "$VENV_DIR/bin/activate"

echo "[info] Python executable: $(which python)" 
python -V
pip -V

# 5) Upgrade pip and install pre-commit in venv
echo "[info] Upgrading pip, setuptools, wheel..."
python -m pip install --upgrade pip setuptools wheel

echo "[info] Installing/upgrading pre-commit in venv..."
python -m pip install --upgrade pre-commit

# 6) Git network tuning to reduce fetch failures (safe, global)
echo "[info] Applying Git network tuning (http.postBuffer, http.version, compression)..."
git config --global http.postBuffer 524288000 || true
git config --global http.version HTTP/1.1 || true
git config --global http.lowSpeedLimit 0 || true
git config --global http.lowSpeedTime 999999 || true
git config --global core.compression 0 || true

# 7) Clean pre-commit state and install hooks
echo "[info] Cleaning pre-commit and installing hooks..."
python -m pre_commit clean || true
python -m pre_commit install || true

# 8) Run pre-commit on all files (verbose) and capture output
echo "[info] Running pre-commit on all files (this can take some time). Logs -> $VERBOSE_OUT"
python -m pre_commit run --all-files -v 2>&1 | tee "$VERBOSE_OUT" || echo "[warn] pre-commit returned non-zero (see $VERBOSE_OUT)"

# 9) Summarize
echo "[precommit-setup] FINISHED: $(date -u)"
echo "[precommit-setup] Logs written to: $LOGFILE and $VERBOSE_OUT"

# 10) Deactivate venv (best-effort)
deactivate 2>/dev/null || true

exit 0
