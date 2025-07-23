# CAM-OS Kernel

<div align="center">

![CAM-OS Logo](docs/assets/logo.svg)

**Cognitive Operating System Kernel for AI-Native Infrastructure**

[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)](https://github.com/Dru-Edwards/CAM-OS/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Dru-Edwards/CAM-OS)](https://goreportcard.com/report/github.com/Dru-Edwards/CAM-OS)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org/dl/)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://hub.docker.com/r/cam-os/kernel)

</div>


> **CAM‑OS** is the **first AI‑native micro‑kernel** that treats autonomous *agents* the way Linux treats *processes.* It ships with sub‑millisecond decision loops, post‑quantum zero‑trust security, and built‑in explainability.

```
$ camctl explain "Why did Agent‑B throttle I/O yesterday?"
→ 09 Jul 23:21   Arbitration #3215   policy:EnergyBalance   trust:+0.8
   ↳ Agent‑B I/O > quota (675 MB/s > 500)
   ↳ Energy cost exceeded 25 Wh budget
   ↳ Decision: throttle 25 % for 90 s
```

| Stable release      | Next minor                                                | Live demo                                          |
| ------------------- | --------------------------------------------------------- | -------------------------------------------------- |
| `v2.0.0` · May 2025 | **v2.1.0** ETA Jul 2025 (K8s Operator · NL CLI · OTel ++) | |

---

## 🚀 Key Differentiators

### 🧠 Cognitive Syscalls

*15 verbs for think · learn · arbitrate · explain* (see full table ↓)
🔍 Every call emits Prom‑metrics + OTEL spans.

### 🔒 Quantum‑Safe Zero‑Trust

Kyber‑768 key exchange · Dilithium‑3 signatures · TPM 2.0 trust‑anchor · OPA policy enforcement.

### 🛰 5‑D Triple‑Helix Scheduler

Schedules by **Urgency · Importance · Efficiency · Energy · Trust** — keeps fleets aligned to your values.

### 📚 Explainability & Audit

`sys_explain_action` returns causal chain + policy snapshot — pass audits without extra tooling.

### 🛠 Developer‑First

Go → single static binary · WASM/WASI driver runtime · Helm & Docker templates · <1 min local boot.

---

<details>
<summary><strong>🧠 Full Syscall Matrix (Click to Open)</strong></summary>

| Category          | Verb                                                           | Purpose                       |
| ----------------- | -------------------------------------------------------------- | ----------------------------- |
| **Core**          | `think` · `decide` · `learn` · `remember` · `forget`           | Embedded cognition primitives |
| **Agent Ops**     | `communicate` · `collaborate` · `arbitrate` · `register_agent` | Multi‑agent coordination      |
| **Task Ops**      | `commit_task` · `rollback_task` · `query_policy`               | Transactional task mgmt       |
| **Observability** | `observe` · `explain_action`                                   | Trace + human rationale       |
| **Tuning**        | `tune_system`                                                  | Live‑patch scheduler weights  |

> 💾 Protobuf spec: [`proto/syscall.proto`](proto/syscall.proto)

</details>

---

## 🏗 Architecture Snapshot

```
┌──────────────────────────────────────────────────────┐
│                   CAM‑OS KERNEL                      │
├───────────┬──────────────┬──────────────────────────┤
│ Syscalls  │  Security    │  Explainability Engine   │
│  (15)     │  Manager     │  + OTEL                  │
├───────────┼──────────────┼──────────────────────────┤
│  Arbitration Engine  │ Memory Context │ 5‑D Scheduler │
├──────────────────────┴──────────────────────────────┤
│     Driver Runtime (gRPC ⇆ WASM/WASI sandboxes)      │
├──────────────────────────────────────────────────────┤
│ Redis / CAS store │ Prometheus │ Jaeger/Tempo tracing │
└──────────────────────────────────────────────────────┘
```

---

## ⚡️ Quick‑Start Matrix

| Scenario                   | Command                                                      |
| -------------------------- | ------------------------------------------------------------ |
| **All‑in‑one dev sandbox** | `./scripts/dev‑up.sh`                                        |
| **Docker PoC**             | `docker compose -f deployment/docker-compose.test.yml up`    |
| **Kubernetes (kind)**      | `helm install cam-os deployment/helm --set image.tag=v2.0.0` |

> *Prereqs:* Go 1.21+, Docker 24+, Redis 7, `protoc ≥ 24`.

---

## 🧪 Quality Gates

```bash
make test       # unit + integ + crypto mocks
make fuzz       # libFuzzer across all syscalls
make ci‑check   # lint · vet · gosec · sbom
```

CI must pass: **≥ 90 % coverage · zero MEDIUM gosec · ABI drift check**  (see `.github/workflows/ci.yml`).

---

## 🎯 Performance Benchmarks (v2.0.0)

| Metric      | Target       | Achieved |
| ----------- | ------------ | -------- |
| Syscall p99 | < 1 ms       | 0.83 ms  |
| Throughput  | > 10 k ops/s | 11.4 k   |
| Base RAM    | < 100 MB     | 82 MB    |
| Crypto ∅    | < 5 % CPU    | 3.1 %    |

Benchmark scripts: `benchmarks/` (runs in GH Actions on release tags).

---

## 🌍 Deployment Footprint

* **Docker / Compose** — turnkey demo.
* **Kubernetes** — Helm chart **+ Operator** (in v2.1.0).
* **Cloud IaC** — AWS CFN, Azure Bicep, GCP Deployment Manager samples.
* **Edge / Bare‑metal** — Systemd units; TPM provisioning helper.

---

## 🔧 Hacking Guide

```bash
# 1. Clone & install deps
git clone https://github.com/Dru-Edwards/CAM-OS.git && cd CAM-OS
go mod download

# 2. Regenerate protobuf & mocks
make proto

# 3. Run kernel in dev‑mode (hot‑reload)
redis-server --daemonize yes
CONFIG=config/dev.yaml go run ./cmd/cam-kernel
```

Branch → `feat/<ticket>` → PR → green CI = auto‑merge ✅
See [`CONTRIBUTING.md`](CONTRIBUTING.md) for code‑style & CLA.

---

## 🛣 Roadmap (Public Milestones)

| Version    | ETA      | Key Features                                  |
| ---------- | -------- | --------------------------------------------- |
| **v2.1.0** | Jul 2025 | K8s Operator · Natural‑language CLI · OTel ++ |
| **v2.2.x** | Q4 2025  | CRDT federation · Driver marketplace beta     |
| **v2.3.x** | 2026     | Quantum offload POC · Edge bundles            |

Full board: [`ROADMAP.md`](ROADMAP.md)

---

## 📊 Observability Stack

* **Prometheus** — kernel, scheduler, Redis metrics.
* **Grafana dashboards** — `monitoring/grafana/` JSON.
* **Jaeger/Tempo** — distributed traces for every syscall.
* **Audit logs** — Loki/Splunk compatible (JSON‑ECS).

---

## 🔒 Security Posture

* PQ‑crypto everywhere (Kyber‑768 / Dilithium‑3)
* TPM 2.0 backed CAM Trust Envelope
* OPA policies for every verb
* Signed WASM drivers & SBOM on release

**Bug bounty:** see [`SECURITY.md`](docs/security/SECURITY.md).

---

## 🤝 Community & Support

| Channel                | Use‑case                                                   |
| ---------------------- | ---------------------------------------------------------- |
| **GitHub Issues**      | Bugs & feature requests                                    |
| **Discussions tab**    | Ideas · Q\&A · RFCs                                        |
| **Driver Marketplace** | [https://registry.cam-os.dev](https://registry.cam-os.dev) |
| **Enterprise Email**   | [enterprise@cam-os.dev](mailto:enterprise@cam-os.dev)      |

> Star ⭐ the repo if CAM‑OS sparks your imagination — it helps the project grow!

---

*Built with ❤️ by the CAM‑OS community — bringing cognitive computing to every edge of the planet.* 🧠✨

</div>
