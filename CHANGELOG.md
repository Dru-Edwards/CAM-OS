# Changelog

All notable changes to the CAM-OS Kernel project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.1] - 2025-07-24

### Fixed
- Fixed broken markdown formatting in README.md (missing closing code block fence)
- Updated v2.1.0 ETA from "Jul 2025" to "Q3 2025" for accuracy
- Fixed broken links: removed dead registry link, updated security policy path
- Filled empty demo column in release table with "Demo Coming Soon" link
- Synchronized version numbers between README.md and ROADMAP.md
- Updated ROADMAP.md to reflect current v2.0.0 release status

### Changed
- Improved documentation consistency and readability
- Enhanced community links and support information
- Aligned project documentation with current development status

## [2.0.0] - 2025-05-01

### Added
- ✅ 15 cognitive syscalls with comprehensive implementation
- ✅ Post-quantum security (Kyber768 + Dilithium3 + TPM 2.0)
- ✅ Multi-cluster federation with CRDT synchronization
- ✅ Driver marketplace with 5% revenue model
- ✅ Kubernetes operator for one-liner installation
- ✅ Natural language interface for operations
- ✅ Microkernel architecture (<15 KLOC)

### Performance
- ✅ <1ms syscall latency (99th percentile)
- ✅ >10,000 ops/sec throughput
- ✅ <100MB memory footprint
- ✅ <5ms WASM driver startup
- ✅ <100ms federation sync

### Security
- ✅ Comprehensive security hardening sprint (10/10 items completed)
- ✅ Modular dispatcher architecture
- ✅ Per-syscall timeout enforcement
- ✅ Input validation and sanitization
- ✅ gRPC auth middleware with mTLS
- ✅ Error response sanitization

## [1.0.0] - 2024-05-01

### Added
- ✅ Initial microkernel architecture
- ✅ Basic syscall interface
- ✅ Memory context management
- ✅ Security framework foundation
- ✅ Driver runtime infrastructure

[Unreleased]: https://github.com/Dru-Edwards/CAM-OS/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/Dru-Edwards/CAM-OS/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/Dru-Edwards/CAM-OS/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/Dru-Edwards/CAM-OS/releases/tag/v1.0.0