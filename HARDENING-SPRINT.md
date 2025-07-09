# Safe Push Workflow & Hardening TODOs

This document formalises the **safe‑push workflow** and lists the remaining hardening sprint tickets. Share it with every coding‑agent and include it in CI to prevent accidental commits of secrets or bulky artefacts.

---

## 1 · `scripts/safe-push.sh`

```bash
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
```

> **Usage:**
>
> ```bash
> bash scripts/safe-push.sh dev/hardening-sprint "fix: H‑3 namespace validation"
> ```

---

## 2 · `.gitignore` Additions

```gitignore
# secrets & configs
*.env
config/dev.yaml
*.pem
*.key
*.crt
stripe_*.json
paypal_*.json

# build outputs
bin/
*.wasm
coverage/
tests/fuzz/corpus/

# IDE settings
.idea/
.vscode/

# data dumps
redis.rdb
*.dump
```

---

## 3 · Do‑NOT‑commit Reference Table

| Pattern / File                     | Reason                 | Handling strategy                |
| ---------------------------------- | ---------------------- | -------------------------------- |
| `*.pem`, `*.key`, `*.crt`, `*.p12` | Private keys & certs   | Store in Vault / TPM             |
| `config/dev.yaml`, `*.env`         | Local secrets          | Keep local, inject via CI        |
| `stripe_*.json`, `paypal_*.json`   | Payment provider creds | CI secrets injection             |
| `redis.rdb`, `*.dump`              | Runtime data           | Off‑repo backup                  |
| `tests/fuzz/corpus/**` (>10 MB)    | Large seed corpora     | Store in release artefact bucket |
| Coverage `*.out`, `*.prof`         | Volatile CI output     | Publish to Codecov               |
| `bin/`, compiled `.wasm`, `.exe`   | Deterministic rebuilds | Rebuild in CI                    |

---

## 4 · Hardening Sprint Tickets (blocking v2.1.0)

| Ticket   | Gap                         | Owner          | Acceptance Test                                           |
| -------- | --------------------------- | -------------- | --------------------------------------------------------- |
| **H‑1**  | Split monolithic dispatcher | @core‑team     | File length < 600 LOC/handler; unit tests green           |
| **H‑2**  | Per‑syscall timeout         | @core‑team     | Integration test returns `DEADLINE_EXCEEDED` on slow stub |
| **H‑3**  | Namespace sanitisation      | @memory‑team   | Fuzz test can't escape namespace                          |
| **H‑4**  | Auth + rate limiting        | @sec‑team      | 50 k QPS rogue client → `RESOURCE_EXHAUSTED`              |
| **H‑5**  | Error redaction             | @sec‑team      | Client msg redacted, server logs full stack               |
| **H‑6**  | Tests for new verbs         | @qa‑team       | Global coverage ≥ 90 %                                    |
| **H‑7**  | Proto drift CI step         | @dx‑team       | CI fails on stale gen code                                |
| **H‑8**  | Helm image tag pin          | @platform‑team | `helm template` shows tag `v2.0.0`                        |
| **H‑9**  | License duplication         | @legal‑liaison | `reuse lint` passes                                       |
| **H‑10** | TPM API returns keyID       | @sec‑team      | Integration test validates cert chain                     |

> Work on `dev/hardening-sprint`, push via **safe‑push.sh**, then open PR to `main`.

---

## 5 · Release Gate Checklist

* [ ] All H‑tickets closed & merged
* [ ] CI green on Go 1.21 & 1.22‑beta
* [ ] SBOM uploaded to GitHub release asset
* [ ] Helm chart version bumped & tag pinned
* [ ] CHANGELOG entry for v2.0.1‑rc1

Once all boxes are ticked, tag `v2.0.1‑rc1` and start staged roll‑out.

---

## 6 · Security Guidelines

### Secrets Management
- **Never commit**: API keys, certificates, private keys, or credentials
- **Use environment variables**: For runtime configuration
- **Vault integration**: Store sensitive data in HashiCorp Vault or similar
- **TPM hardware**: Leverage TPM 2.0 for cryptographic operations

### Code Quality
- **Modular architecture**: Keep files under 600 LOC
- **Comprehensive testing**: Maintain >90% test coverage
- **Input validation**: Sanitize all user inputs
- **Error handling**: Redact sensitive information from client-facing errors

### CI/CD Security
- **Proto drift detection**: Ensure generated code is up-to-date
- **Dependency scanning**: Check for vulnerable dependencies
- **SBOM generation**: Maintain software bill of materials
- **License compliance**: Ensure license consistency

### Deployment Security
- **Image tag pinning**: Use specific versions, not `latest`
- **Resource limits**: Set appropriate CPU/memory limits
- **Network policies**: Implement network segmentation
- **Monitoring**: Enable comprehensive observability

---

*Last updated: 2024‑12‑01.* 