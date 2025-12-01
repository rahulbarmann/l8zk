# Contributing to L8ZK SDK

Thank you for your interest in contributing to the L8ZK SDK (@l8zk/sdk)! This project implements privacy-preserving verifiable credentials using zero-knowledge proofs.

## Development Setup

### Prerequisites

- Node.js 18+
- Rust (for native backend)
- Circom (for circuit compilation)

### Installation

```bash
git clone https://github.com/rahulbarmann/l8zk
cd sdk
npm install

# Initialize submodules
npm run submodule:init

# Build native backend (for full functionality)
cd wallet-unit-poc/circom
yarn && yarn compile:jwt && yarn compile:show
cd ../ecdsa-spartan2
cargo build --release
```

### Running Tests

```bash
npm test              # Run all tests
npm run test:watch    # Watch mode
npm run test:coverage # With coverage
```

### Code Quality

```bash
npm run lint      # Lint code
npm run lint:fix  # Fix linting issues
npm run format    # Format code
```

## Project Structure

```
src/
├── credential/     # SD-JWT parsing and validation
├── prover/         # ZK proof generation (prepare/show/verify)
├── storage/        # Cross-platform storage adapters
├── utils/          # Cryptographic utilities
└── types.ts        # TypeScript type definitions

tests/              # Comprehensive test suite
examples/           # Usage examples and demos
wallet-unit-poc/    # Native Rust backend
```

## Contributing Guidelines

### Code Style

- Use TypeScript with strict mode
- Follow the existing code style (Prettier + ESLint)
- Write comprehensive tests for new features
- Document public APIs with JSDoc comments

### Commit Messages

Use conventional commits format:

```
feat(prover): add support for new policy predicates
fix(storage): resolve IndexedDB transaction issues
docs(readme): update installation instructions
```

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Ensure all tests pass: `npm test`
5. Commit your changes
6. Push and open a Pull Request

### Security Considerations

- Never commit private keys or sensitive test data
- Ensure constant-time operations for cryptographic functions
- Add security-focused tests for new cryptographic code
- Consider timing attacks and side-channel vulnerabilities

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
