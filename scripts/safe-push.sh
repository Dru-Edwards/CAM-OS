#!/usr/bin/env bash
# -------------------------------------------------------------
# safe-push.sh — stage, commit, and push only approved artefacts
# -------------------------------------------------------------
set -euo pipefail

BRANCH="${1:-dev/hardening-sprint}"            # default integration branch
MSG="${2:-\"chore: hardening-sprint batch\"}" # commit message

# 1 · Guard: working tree must be clean before regenerating artefacts
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "❌  Uncommitted changes found. Stash or commit them first." >&2
  exit 1
fi

# 2 · Deterministic regeneration (proto, docs, SBOM)
make proto        # → regenerates *.pb.go, stored in repo
make docs         # → updates docs/api/* from Go docstrings
make sbom || true # optional SPDX JSON

go mod tidy       # ensure `go.sum` is locked

# 3 · Whitelist‑only staging
WHITELIST=(
  "*.go" "*.md" "*.proto" "*.toml" "*.yaml" "*.yml"
  "cmd/**" "internal/**" "docs/**" "deployment/**"
  "monitoring/**" "scripts/**" "Makefile" ".github/**"
  "Dockerfile" "docker-compose*.yml"
)
# shellcheck disable=SC2086
git add ${WHITELIST[@]}

# 4 · Red‑flag scan: abort if sensitive artefacts staged
for forbidden in \
  '\\.(pem|key|crt|p12)$' \
  'config/dev.yaml' \
  '\\.env' \
  'stripe_.*\\.json' \
  'redis\\.rdb' \
  '\\.dump$'; do
  if git diff --cached --name-only | grep -E "${forbidden}"; then
    echo "❌  Sensitive file detected: ${forbidden}. Aborting commit." >&2
    exit 1
  fi
done

# 5 · Commit + push
git commit -m "${MSG}"
git push origin "${BRANCH}"
echo "✅  Safe push complete → ${BRANCH}" 