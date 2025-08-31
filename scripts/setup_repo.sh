#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install pre-commit black isort flake8 bandit semgrep pip-audit detect-secrets pytest
python -m pre_commit install || true
chmod +x scripts/*.sh || true
echo "Done. Activate: source .venv/bin/activate"
