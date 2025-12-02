# Changelog

All notable changes to the L8ZK SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2024-12-02

### Added

- ZK proof generation with actual proof bytes returned (~112KB prepare, ~41KB show)
- Proof bytes are now read from native backend and included in Proof object
- Shared blinds (commitment) included for proof linking
- Circuit input generator module for future dynamic credential support

### Changed

- `OpenAC.prepare()` now returns actual prepare proof bytes instead of placeholders
- `handle.show()` now returns actual show proof bytes instead of placeholders
- Proofs include real `sharedCommitment` for cryptographic linking

### Notes

- Currently uses pre-compiled circuit inputs for proof generation
- Custom credential data support requires circuit recompilation (under development)
- The ZK proofs generated are cryptographically valid and properly verified

## [1.2.5] - 2024-12-02

### Fixed

- Fixed binary resolution order to prioritize top-level node_modules where postinstall sets execute permissions

## [1.2.4] - 2024-12-02

### Fixed

- Added postinstall scripts to platform packages to ensure binary execute permissions

## [1.2.3] - 2024-12-02

### Fixed

- Fixed circom artifacts tarball to exclude macOS resource fork files that caused build failures on Linux

## [1.2.2] - 2024-12-02

### Fixed

- Fixed lint error in circom-downloader
- Updated workflow to use clean circom artifacts

## [1.2.1] - 2024-12-02

### Fixed

- Fixed circom artifacts download to include input files required by the binary

## [1.2.0] - 2024-12-02

### Added

- Auto-download circom artifacts on first use (~33MB compressed)
- Artifacts cached at `~/.l8zk/circom/` for subsequent runs
- Progress tracking during download with percentage updates

### Changed

- Users no longer need to manually build circom circuits
- First `OpenAC.prepare()` call downloads artifacts automatically

## [1.1.0] - 2024-12-01

### Added

- Platform-specific binary distribution via npm optional dependencies
- Separate packages for each platform:
  - `@l8zk/sdk-darwin-arm64` - macOS Apple Silicon
  - `@l8zk/sdk-darwin-x64` - macOS Intel
  - `@l8zk/sdk-linux-x64` - Linux x64
  - `@l8zk/sdk-linux-arm64` - Linux ARM64
- Automated CI/CD pipeline for building and publishing platform binaries

### Changed

- Users now only download the binary for their platform (~20MB) instead of all platforms
- Installation simplified to just `npm install @l8zk/sdk`

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
