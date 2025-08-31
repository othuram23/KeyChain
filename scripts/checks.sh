#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
echo "[checks] running"
if command -v black >/dev/null 2>&1; then black --check . || true; fi
if command -v isort >/dev/null 2>&1; then isort --check-only . || true; fi
if command -v flake8 >/dev/null 2>&1; then flake8 || true; fi
if command -v bandit >/dev/null 2>&1; then bandit -r . || true; fi
if command -v pytest >/dev/null 2>&1; then pytest -q || true; fi
echo "[checks] done"
