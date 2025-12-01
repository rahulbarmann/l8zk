# Changelog

All notable changes to the L8ZK SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-01

### Added

- Initial production release of L8ZK SDK (@l8zk/sdk)
- Zero-knowledge proof generation for verifiable credentials
- Support for SD-JWT credential format
- Native Node.js backend with Spartan2 + ECDSA proving system
- Cross-platform support (Browser, Node.js, React Native)
- Privacy-preserving age verification and policy predicates
- Automatic unlinkability between presentations
- Device binding support
- Complete test suite with 63 passing tests
- Full end-to-end demo with real ZK proofs
- Performance optimizations: <100ms presentation proofs

### Security

- No trusted setup required (transparent Spartan protocol)
- Zero-knowledge property: only policy satisfaction revealed
- Unlinkability: each proof is cryptographically reblinded
- Device binding prevents credential transfer

### Performance

- Prepare phase: ~6s (one-time per credential)
- Show phase: ~96ms (per presentation)
- Verification: ~34ms
- Total end-to-end flow: ~13s
