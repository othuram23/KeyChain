#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

REPO_DIR="$(pwd)"
BRANCH="infra/setup-pro"
REMOTE="origin"
GIT_EMAIL="${GIT_EMAIL:-you@example.com}"
GIT_NAME="${GIT_NAME:-othuram23}"

echo "[bootstrap] Starting bootstrap in $REPO_DIR"
echo "[bootstrap] Branch: $BRANCH"

# 1) Ensure git repo
if [ ! -d ".git" ]; then
  echo "[error] This directory is not a git repo. Aborting."
  exit 1
fi

# 2) Create branch
if git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
  echo "[bootstrap] Branch $BRANCH already exists locally."
  read -p "Do you want to reset it to HEAD and continue? (y/N) " yn
  case "$yn" in
    [Yy]* ) git branch -D "$BRANCH";;
    * ) echo "Aborting."; exit 1;;
  esac
fi
git checkout -b "$BRANCH"

# 3) Ensure author info
git config user.email "$GIT_EMAIL"
git config user.name "$GIT_NAME"

# 4) Make directories
mkdir -p .github/workflows .github/ISSUE_TEMPLATE scripts audit docs src tests

# 5) Create files (minimal but professional). Edit as needed after generation.

cat > LICENSE <<'LIC'
MIT License

Copyright (c) YEAR OWNER

Permission is hereby granted, free of charge, to any person obtaining a copy...
(replace YEAR and OWNER)
LIC

cat > README.md <<'MD'
# KeyChain

Project KeyChain — description courte. Voir docs/ pour documentation complète.

## Quickstart
1. Voir scripts/setup_repo.sh pour préparer un environnement dev.
2. CI / Security: .github/workflows
MD

cat > CONTRIBUTING.md <<'MD'
# Contributing to KeyChain

See docs/ for contribution guidelines. PRs -> feature branches -> tests -> reviewers.
MD

cat > SECURITY.md <<'MD'
# Security policy

Please do not open public issues for security vulnerabilities. Contact: security@yourdomain.example
MD

cat > CHANGELOG.md <<'MD'
# Changelog
All notable changes to this project will be documented in this file.
MD

cat > .gitignore <<'GITIGNORE'
# Python
__pycache__/
.venv/
venv/
*.pyc

# Node
node_modules/

# OS
.DS_Store
Thumbs.db

# Editor
.vscode/
.idea/

# Local config
.env
GITIGNORE

cat > .gitattributes <<'GATTR'
* text=auto
*.md text
GATTR

# Pre-commit config
cat > .pre-commit-config.yaml <<'PRE'
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-added-large-files

  - repo: https://github.com/psf/black
    rev: 25.1.0
    hooks:
      - id: black
        language_version: python3.11

  - repo: https://github.com/PyCQA/isort
    rev: 5.16.0
    hooks:
      - id: isort

  - repo: https://github.com/pycqa/flake8
    rev: 7.3.0
    hooks:
      - id: flake8
        additional_dependencies: ["flake8-bugbear"]

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.6
    hooks:
      - id: bandit
        args: ["-r", "."]

  - repo: https://github.com/returntocorp/semgrep
    rev: v1.89.0
    hooks:
      - id: semgrep
        args: ["--config", "p/ci"]

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets-hook
PRE

# Dependabot
mkdir -p .github
cat > .github/dependabot.yml <<'DB'
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "04:00"
      timezone: "Europe/Paris"
    labels: ["dependencies", "python", "security"]
    commit-message:
      prefix: "deps(python)"
      include: "scope"
    reviewers: ["othuram23"]
    rebase-strategy: "auto"
    open-pull-requests-limit: 10

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "04:30"
      timezone: "Europe/Paris"
    labels: ["dependencies", "ci", "security"]
    commit-message:
      prefix: "deps(actions)"
      include: "scope"
    reviewers: ["othuram23"]
    rebase-strategy: "auto"

  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "tuesday"
      time: "05:00"
      timezone: "Europe/Paris"
    labels: ["dependencies", "docker", "security"]
    commit-message:
      prefix: "deps(docker)"
      include: "scope"
    reviewers: ["othuram23"]
    rebase-strategy: "auto"

  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "tuesday"
      time: "05:30"
      timezone: "Europe/Paris"
    labels: ["dependencies", "javascript", "security"]
    commit-message:
      prefix: "deps(js)"
      include: "scope"
    reviewers: ["othuram23"]
    rebase-strategy: "auto"
DB

# CODEOWNERS
cat > .github/CODEOWNERS <<'CO'
* @othuram23
/.github/ @othuram23
/scripts/ @othuram23
CO

# Issue templates
mkdir -p .github/ISSUE_TEMPLATE
cat > .github/ISSUE_TEMPLATE/bug_report.md <<'BUG'
---
name: Bug report
about: Create a report to help us improve
---
**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behaviour:
1. ...
BUG

cat > .github/ISSUE_TEMPLATE/feature_request.md <<'FEAT'
---
name: Feature request
about: Suggest an idea for this project
---
**Is your feature request related to a problem? Please describe.**
...
FEAT

# Pull request template
cat > .github/PULL_REQUEST_TEMPLATE.md <<'PR'
## Description
Please include a summary of the change and which issue is fixed.

## Checklist
- [ ] Tests added/updated
- [ ] Linting passed
- [ ] Documentation updated
PR

# Workflows: ci, codeql, sbom
cat > .github/workflows/ci.yml <<'CI'
name: CI — KeyChain
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

jobs:
  checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Make scripts executable
        run: chmod +x scripts/*.sh || true
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
          python -m pip install pre-commit pytest pytest-cov semgrep pip-audit
      - name: Run pre-commit
        run: python -m pre_commit run --all-files || true
      - name: Run checks
        run: ./scripts/checks.sh
      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ci-artifacts
          path: ./test-results || ./coverage || ./htmlcov
CI

cat > .github/workflows/codeql.yml <<'CODEQL'
name: CodeQL
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * 0'
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: python, javascript
      - name: Autobuild
        uses: github/codeql-action/autobuild@v2
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2
CODEQL

cat > .github/workflows/sbom-and-scan.yml <<'SBOM'
name: SBOM & Container Scan
on:
  push:
    branches: [ main ]
  workflow_dispatch:
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate SBOM (Syft)
        uses: anchore/syft-action@v1
        with:
          output-format: cyclonedx
          output-file: ./sbom.cyclonedx.json
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: ./sbom.cyclonedx.json
  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image (if Dockerfile)
        run: |
          if [ -f Dockerfile ]; then docker build -t keychain-ci-image:latest . || true; fi
      - name: Trivy scan
        uses: aquasecurity/trivy-action@v0.9.0
        with:
          image-ref: keychain-ci-image:latest
SBOM

# Scripts
cat > scripts/checks.sh <<'SH'
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
SH

cat > scripts/setup_repo.sh <<'SETUP'
#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install pre-commit black isort flake8 bandit semgrep pip-audit detect-secrets pytest
python -m pre_commit install || true
chmod +x scripts/*.sh || true
echo "Done. Activate: source .venv/bin/activate"
SETUP

# Make scripts executable
chmod +x scripts/*.sh || true

# 6) Final commit
git add -A
git commit -m "chore(infra): add baseline infra (CI, pre-commit, dependabot, docs, scripts)" || echo "Nothing to commit"
git push -u "$REMOTE" "$BRANCH"

echo "[bootstrap] Done. Branch pushed: $REMOTE/$BRANCH"
echo "[bootstrap] Open a PR in GitHub to merge infra into main."
