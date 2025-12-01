# @l8zk/sdk

Production-ready SDK for privacy-preserving verifiable credentials using zero-knowledge proofs.

Built on the [OpenAC protocol](https://github.com/privacy-scaling-explorations/zkID) by Privacy and Scaling Explorations (PSE), Ethereum Foundation.

## Overview

The L8ZK SDK enables privacy-preserving credential verification where users can prove properties about their credentials (e.g., "I am over 18") without revealing the underlying data (e.g., exact birthdate). Each proof is cryptographically unlinkable, preventing tracking across verifiers.

### Key Features

- **Zero-Knowledge Proofs**: Prove credential properties without revealing data
- **No Trusted Setup**: Uses transparent Spartan protocol with Hyrax commitments
- **SD-JWT Compatible**: Works with existing Selective Disclosure JWT credentials
- **Cross-Platform**: Node.js, Browser, and React Native support
- **Fast Performance**: <100ms presentation proofs after one-time setup
- **Unlinkable**: Each proof is cryptographically reblinded to prevent correlation
- **Device Binding**: Optional secure element binding for enhanced security

### Security Properties

- **Zero-Knowledge**: Only policy satisfaction is revealed, not the actual credential data
- **Unlinkability**: Each presentation is cryptographically unique and cannot be correlated
- **Soundness**: Verifier is convinced only if the statement is true
- **Device Binding**: Credentials can be bound to a specific device to prevent transfer

## Installation

```bash
npm install @l8zk/sdk
```

### Prerequisites

For full functionality with native ZK proofs:

- Node.js 18+
- Rust toolchain (for building native backend)
- Circom (for circuit compilation)

## Quick Start

### Basic Usage (Node.js)

```typescript
import { OpenAC } from "@l8zk/sdk";

// Initialize with a credential
const credential = "eyJhbGc..."; // SD-JWT credential string

// Step 1: Prepare credential (one-time, ~6s)
const handle = await OpenAC.prepare({
  credential,
  deviceBinding: true,
});

// Step 2: Generate proof (per presentation, ~100ms)
const proof = await handle.show({
  policy: { age: { gte: 18 } },
  nonce: "verifier-challenge-nonce",
});

// Step 3: Verify proof (verifier side, ~34ms)
const result = await OpenAC.verify(proof, {
  policy: { age: { gte: 18 } },
  nonce: "verifier-challenge-nonce",
});

console.log(result.valid); // true
```

### Complete Example: Age Verification

```typescript
import { OpenAC } from "@l8zk/sdk";

// Issuer: Government issues identity credential
const issuer = {
  name: "Federal Republic of Germany",
  url: "https://federal-republic-of-germany.gov",
};

// User receives SD-JWT credential with claims
const credential = {
  iss: issuer.url,
  sub: "user-123",
  name: "Alice Schmidt",
  birthdate: "1990-05-15",
  nationality: "DE",
};

// User: Prepare credential with ZK proof capability
const wallet = await OpenAC.prepare({
  credential: sdJwtString,
  deviceBinding: true,
  storage: "memory", // or "indexeddb" for browser
});

// Verifier: Request proof of age >= 18
const verifier = {
  name: "Berlin Biergarten",
  challenge: OpenAC.generateNonce(),
};

// User: Generate privacy-preserving proof
const presentation = await wallet.show({
  policy: {
    age: { gte: 18 },
  },
  nonce: verifier.challenge,
});

// Verifier: Verify the proof
const verification = await OpenAC.verify(presentation, {
  policy: { age: { gte: 18 } },
  nonce: verifier.challenge,
  trustedIssuers: [issuer.url],
});

if (verification.valid) {
  console.log("Access granted: User is 18+");
  // Verifier knows: User is 18+
  // Verifier does NOT know: Exact age, birthdate, name, nationality
} else {
  console.log("Access denied");
}
```

### Advanced: Multiple Policies

```typescript
// Crypto exchange onboarding
const proof = await wallet.show({
  policy: {
    age: { gte: 18 },
    nationality: { nin: ["KP", "IR", "SY"] }, // Not in sanctioned countries
    countryCode: { in: ["US", "CA", "GB", "DE", "FR"] }, // Supported regions
  },
  nonce: exchangeChallenge,
});

// EU residency verification
const euProof = await wallet.show({
  policy: {
    countryCode: {
      in: ["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE"],
    },
  },
  nonce: serviceChallenge,
});
```

## API Reference

### `OpenAC.prepare(options)`

Prepares a credential for zero-knowledge presentations. This is a one-time operation per credential (~6s).

**Parameters:**

```typescript
{
  credential: string;           // SD-JWT credential
  deviceBinding?: boolean;      // Bind to device (default: false)
  storage?: StorageAdapter;     // Storage backend (default: memory)
}
```

**Returns:** `Promise<CredentialHandle>`

**Example:**

```typescript
const handle = await OpenAC.prepare({
  credential: sdJwtString,
  deviceBinding: true,
});
```

### `handle.show(options)`

Generates a zero-knowledge presentation proof (~100ms).

**Parameters:**

```typescript
{
  policy: PolicyPredicates;     // What to prove
  nonce: string;                // Verifier challenge
  disclosures?: string[];       // Optional explicit disclosures
}
```

**Returns:** `Promise<Presentation>`

**Example:**

```typescript
const proof = await handle.show({
  policy: { age: { gte: 21 } },
  nonce: verifierNonce,
});
```

### `OpenAC.verify(presentation, options)`

Verifies a zero-knowledge presentation proof (~34ms).

**Parameters:**

```typescript
{
  presentation: Presentation;   // Proof to verify
  policy: PolicyPredicates;     // Expected policy
  nonce: string;                // Challenge nonce
  trustedIssuers?: string[];    // Allowed issuer URLs
}
```

**Returns:** `Promise<VerificationResult>`

**Example:**

```typescript
const result = await OpenAC.verify(proof, {
  policy: { age: { gte: 21 } },
  nonce: verifierNonce,
  trustedIssuers: ["https://government.example"],
});
```

## Policy Predicates

The SDK supports rich policy expressions:

### Comparison Operators

```typescript
{
  age: { gte: 18 },        // Greater than or equal
  age: { gt: 21 },         // Greater than
  age: { lte: 65 },        // Less than or equal
  age: { lt: 100 },        // Less than
}
```

### Equality

```typescript
{
  countryCode: "DE",       // Exact match
  nationality: "US",
}
```

### Set Membership

```typescript
{
  nationality: { in: ["DE", "FR", "IT"] },      // Must be in set
  countryCode: { nin: ["KP", "IR"] },           // Must NOT be in set
}
```

### Range Queries

```typescript
{
  income: { gte: 50000, lt: 100000 },  // Between 50k and 100k
  age: { gte: 18, lte: 65 },           // Between 18 and 65
}
```

### Combined Policies

```typescript
{
  age: { gte: 18 },
  nationality: { in: ["US", "CA", "GB"] },
  income: { gte: 50000 },
  countryCode: { nin: ["KP", "IR", "SY"] },
}
```

## Storage Adapters

### Memory Storage (Default)

```typescript
import { MemoryAdapter } from "@l8zk/sdk";

const handle = await OpenAC.prepare({
  credential,
  storage: new MemoryAdapter(),
});
```

### IndexedDB (Browser)

```typescript
import { IndexedDBAdapter } from "@l8zk/sdk";

const handle = await OpenAC.prepare({
  credential,
  storage: new IndexedDBAdapter("my-wallet"),
});
```

### Custom Storage

```typescript
import { StorageAdapter } from "@l8zk/sdk";

class MyStorage implements StorageAdapter {
  async get(key: string): Promise<string | null> {
    // Your implementation
  }

  async set(key: string, value: string): Promise<void> {
    // Your implementation
  }

  async delete(key: string): Promise<void> {
    // Your implementation
  }

  async keys(): Promise<string[]> {
    // Your implementation
  }

  async clear(): Promise<void> {
    // Your implementation
  }
}
```

## Native Backend Setup

For production use with real ZK proofs, build the native backend:

```bash
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Install Circom
# See: https://docs.circom.io/getting-started/installation/

# 3. Initialize submodules
npm run submodule:init

# 4. Build circuits
cd wallet-unit-poc/circom
yarn && yarn compile:jwt && yarn compile:show

# 5. Build Rust binary
cd ../ecdsa-spartan2
cargo build --release
```

The binary will be at `wallet-unit-poc/ecdsa-spartan2/target/release/ecdsa-spartan2`.

## Performance

Benchmarks on Apple M1 Pro:

| Operation      | Time   | Description            |
| -------------- | ------ | ---------------------- |
| Prepare Setup  | ~6s    | One-time circuit setup |
| Prepare Prove  | ~3.6s  | Generate prepare proof |
| Prepare Verify | ~1.8s  | Verify prepare proof   |
| Show Prove     | ~100ms | Generate presentation  |
| Show Verify    | ~34ms  | Verify presentation    |

**Total end-to-end flow**: ~13s (one-time) + ~100ms (per presentation)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        L8ZK SDK                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Prepare    │  │     Show     │  │    Verify    │    │
│  │   (Setup)    │  │  (Present)   │  │   (Check)    │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                  │                  │             │
│         └──────────────────┴──────────────────┘             │
│                            │                                │
│                   ┌────────▼────────┐                       │
│                   │  Native Backend │                       │
│                   │  (Spartan2 ZK)  │                       │
│                   └─────────────────┘                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Components

- **Credential Parser**: SD-JWT parsing and validation
- **Prover**: ZK proof generation (prepare/show phases)
- **Verifier**: Proof verification and policy checking
- **Storage**: Cross-platform credential storage
- **Native Backend**: Rust-based Spartan2 + ECDSA proving system

## Examples

See the `examples/` directory for complete working examples:

- `examples/age-verification/` - Basic age verification
- `examples/crypto-onboarding/` - Crypto exchange KYC
- `examples/eu-residency/` - EU residency verification
- `examples/full-demo/` - Complete end-to-end demo

Run examples:

```bash
npx tsx examples/full-demo/index.ts
```

## Security Considerations

### Privacy Guarantees

- **Zero-Knowledge**: Only the policy satisfaction is revealed
- **Unlinkability**: Each proof is cryptographically reblinded
- **No Correlation**: Verifiers cannot link presentations from the same user

### What Verifiers Learn

When proving `age >= 18`:

- ✅ Verifier knows: User satisfies the policy
- ❌ Verifier does NOT know: Exact age, birthdate, name, or other attributes

### Threat Model

- **Honest Verifier**: Verifier follows protocol but may try to learn extra information
- **Malicious Prover**: Cannot create valid proofs for false statements
- **Collusion**: Multiple verifiers cannot link presentations

### Best Practices

1. **Always use nonces**: Prevents replay attacks
2. **Verify issuer**: Check `trustedIssuers` list
3. **Rotate credentials**: Periodically refresh credentials
4. **Secure storage**: Use encrypted storage for sensitive data
5. **Device binding**: Enable for high-security use cases

## Browser Support

The SDK works in modern browsers with WebAssembly support:

```typescript
import { OpenAC } from "@l8zk/sdk";
import { IndexedDBAdapter } from "@l8zk/sdk";

// Browser usage
const handle = await OpenAC.prepare({
  credential: sdJwtString,
  storage: new IndexedDBAdapter("wallet"),
});

const proof = await handle.show({
  policy: { age: { gte: 18 } },
  nonce: challenge,
});
```

## React Native Support

```typescript
import { OpenAC } from "@l8zk/sdk";
import AsyncStorage from "@react-native-async-storage/async-storage";

// Custom storage adapter for React Native
class RNStorage implements StorageAdapter {
  async get(key: string) {
    return await AsyncStorage.getItem(key);
  }
  async set(key: string, value: string) {
    await AsyncStorage.setItem(key, value);
  }
  // ... implement other methods
}

const handle = await OpenAC.prepare({
  credential,
  storage: new RNStorage(),
});
```

## Troubleshooting

### Native Backend Not Found

If you see "Native backend not available":

1. Build the native backend (see Native Backend Setup)
2. Ensure the binary is at `wallet-unit-poc/ecdsa-spartan2/target/release/ecdsa-spartan2`
3. Check binary permissions: `chmod +x wallet-unit-poc/ecdsa-spartan2/target/release/ecdsa-spartan2`

### Circuit Compilation Errors

If circuit compilation fails:

1. Install Circom: https://docs.circom.io/getting-started/installation/
2. Ensure Node.js 18+ is installed
3. Run `yarn` in `wallet-unit-poc/circom`
4. Run `yarn compile:jwt && yarn compile:show`

### Performance Issues

For slow proof generation:

1. Ensure native backend is built in release mode: `cargo build --release`
2. Check CPU usage - proof generation is CPU-intensive
3. Consider caching prepared credentials

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/rahulbarmann/l8zk
cd sdk
npm install
npm run submodule:init
npm test
```

### Running Tests

```bash
npm test              # Run all tests
npm run test:watch    # Watch mode
npm run test:coverage # With coverage
```

## Credits

This SDK is built on the [OpenAC protocol](https://github.com/privacy-scaling-explorations/zkID) developed by the zkID team at Privacy and Scaling Explorations (PSE), Ethereum Foundation.

### Core Technology

- **Spartan**: Transparent SNARK protocol (no trusted setup)
- **Hyrax**: Polynomial commitment scheme
- **ECDSA**: Signature verification in zero-knowledge
- **SD-JWT**: Selective Disclosure JSON Web Tokens

## License

MIT License - see [LICENSE](./LICENSE) for details.

Built on OpenAC by PSE / Ethereum Foundation - https://github.com/privacy-scaling-explorations/zkID

## Support

- GitHub Issues: https://github.com/rahulbarmann/l8zk/issues
- Documentation: https://github.com/rahulbarmann/l8zk
- Examples: https://github.com/rahulbarmann/l8zk/tree/main/examples

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for version history and release notes.
