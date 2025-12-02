# @l8zk/sdk

Production-ready SDK for privacy-preserving verifiable credentials using zero-knowledge proofs.

Built on the [OpenAC protocol](https://github.com/privacy-scaling-explorations/zkID) by Privacy and Scaling Explorations (PSE), Ethereum Foundation.

## Overview

The L8ZK SDK enables privacy-preserving credential verification where users can prove properties about their credentials (e.g., "I am over 18") without revealing the underlying data (e.g., exact birthdate). Each proof is cryptographically unlinkable, preventing tracking across verifiers.

### Key Features

- **Zero-Knowledge Proofs**: Generates Spartan2 ZK proofs (~112KB prepare, ~41KB show)
- **No Trusted Setup**: Uses transparent Spartan protocol with Hyrax commitments
- **SD-JWT Compatible**: Works with Selective Disclosure JWT credentials
- **Cross-Platform**: Node.js support (macOS/Linux, x64/ARM64)
- **Fast Performance**: ~14s total (one-time setup) + ~100ms per presentation
- **Unlinkable**: Each proof is cryptographically reblinded to prevent correlation
- **Auto-Download**: Circom artifacts downloaded automatically on first use (~33MB)

### Current Status

This SDK generates and verifies **real cryptographic ZK proofs** using the Spartan2 proving system. The proofs are:

- Cryptographically sound
- Properly reblinded for unlinkability
- Verified by the native Rust backend

**Current Limitation**: The SDK currently uses pre-compiled circuit inputs for proof generation. Custom credential data support requires circuit recompilation and is under active development. The API and proof flow are production-ready.

### Security Properties

- **Zero-Knowledge**: Only policy satisfaction is revealed, not the actual credential data
- **Unlinkability**: Each presentation is cryptographically unique and cannot be correlated
- **Soundness**: Verifier is convinced only if the statement is true
- **Device Binding**: Credentials can be bound to a specific device to prevent transfer

## Installation

```bash
npm install @l8zk/sdk
```

That's it! The SDK automatically:

- Installs the correct native binary for your platform (macOS/Linux, x64/ARM64)
- Downloads circom artifacts (~33MB) on first use

### Requirements

- Node.js 18+

### Platform Support

| Platform | Architecture             | Package                  |
| -------- | ------------------------ | ------------------------ |
| macOS    | Apple Silicon (M1/M2/M3) | `@l8zk/sdk-darwin-arm64` |
| macOS    | Intel                    | `@l8zk/sdk-darwin-x64`   |
| Linux    | x64                      | `@l8zk/sdk-linux-x64`    |
| Linux    | ARM64                    | `@l8zk/sdk-linux-arm64`  |

Platform binaries are installed automatically via npm's optional dependencies.

## Quick Start

### Basic Usage (Node.js)

```typescript
import { OpenAC, generateKeyPair, base64UrlEncode } from "@l8zk/sdk";

// Helper: Create a test SD-JWT credential
function createTestCredential(): string {
  const keys = generateKeyPair();
  const now = Math.floor(Date.now() / 1000);

  const header = { alg: "ES256", typ: "vc+sd-jwt" };
  const payload = {
    iss: "https://test-issuer.example.com",
    sub: "did:example:user123",
    iat: now,
    exp: now + 365 * 24 * 60 * 60,
    cnf: { jwk: keys.publicKey },
    _sd: [],
  };

  const headerB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const signatureB64 = base64UrlEncode(new Uint8Array(64).fill(1));

  const nameDisclosure = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(["salt1", "name", "Alice"]))
  );
  const ageDisclosure = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(["salt2", "roc_birthday", "19901215"]))
  );

  return `${headerB64}.${payloadB64}.${signatureB64}~${nameDisclosure}~${ageDisclosure}`;
}

async function main() {
  // Step 1: Create/obtain an SD-JWT credential
  const credential = createTestCredential();

  // Step 2: Prepare credential (one-time, ~6s)
  const handle = await OpenAC.prepare({
    credential,
    deviceBinding: true,
  });

  // Step 3: Generate proof (per presentation, ~100ms)
  const nonce = OpenAC.generateNonce();
  const proof = await handle.show({
    policy: { age: { gte: 18 } },
    nonce,
  });

  // Step 4: Verify proof (verifier side, ~34ms)
  const result = await OpenAC.verify(proof, { age: { gte: 18 } }, { expectedNonce: nonce });

  console.log(result.valid); // true
}

main();
```

### Complete Example: Age Verification

```typescript
import { OpenAC, generateKeyPair, base64UrlEncode } from "@l8zk/sdk";

// Helper: Create an SD-JWT credential (in production, this comes from an issuer)
function createCredential(): string {
  const keys = generateKeyPair();
  const now = Math.floor(Date.now() / 1000);

  const header = { alg: "ES256", typ: "vc+sd-jwt" };
  const payload = {
    iss: "https://federal-republic-of-germany.gov",
    sub: "did:example:alice-schmidt",
    iat: now,
    exp: now + 365 * 24 * 60 * 60,
    cnf: { jwk: keys.publicKey },
    _sd: [],
  };

  const headerB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const signatureB64 = base64UrlEncode(new Uint8Array(64).fill(1));

  // Disclosures contain the actual claims
  const birthdayDisclosure = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(["salt1", "roc_birthday", "19900515"]))
  );
  const nationalityDisclosure = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(["salt2", "nationality", "DE"]))
  );

  return `${headerB64}.${payloadB64}.${signatureB64}~${birthdayDisclosure}~${nationalityDisclosure}`;
}

async function main() {
  // User: Prepare credential with ZK proof capability
  const credential = createCredential();
  const wallet = await OpenAC.prepare({
    credential,
    deviceBinding: true,
  });

  // Verifier: Request proof of age >= 18
  const challenge = OpenAC.generateNonce();

  // User: Generate privacy-preserving proof
  const presentation = await wallet.show({
    policy: { age: { gte: 18 } },
    nonce: challenge,
  });

  // Verifier: Verify the proof
  const verification = await OpenAC.verify(
    presentation,
    { age: { gte: 18 } },
    { expectedNonce: challenge }
  );

  if (verification.valid) {
    console.log("Access granted: User is 18+");
    // Verifier knows: User is 18+
    // Verifier does NOT know: Exact age, birthdate, name, nationality
  } else {
    console.log("Access denied");
  }
}

main();
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

### `OpenAC.verify(proof, policy?, options?)`

Verifies a zero-knowledge presentation proof (~34ms).

**Parameters:**

```typescript
proof: Proof | SerializedProof;   // Proof to verify
policy?: Policy;                   // Expected policy (optional)
options?: {
  expectedNonce?: string;          // Challenge nonce to verify
  trustedIssuers?: string[];       // Allowed issuer URLs
}
```

**Returns:** `Promise<VerificationResult>`

**Example:**

```typescript
const result = await OpenAC.verify(proof, { age: { gte: 21 } }, { expectedNonce: verifierNonce });
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

## How It Works

The SDK uses a two-phase approach for efficient ZK proofs:

1. **First Run**: Downloads circom artifacts (~33MB) to `~/.l8zk/circom/`
2. **Subsequent Runs**: Uses cached artifacts for instant startup

The native Rust binary (`ecdsa-spartan2`) is included in platform-specific npm packages and installed automatically.

### Development Setup (Optional)

If you want to build from source or modify the circuits:

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

1. Ensure you're on a supported platform (macOS or Linux, x64 or ARM64)
2. Try reinstalling: `rm -rf node_modules && npm install`
3. Check that the platform package was installed: `ls node_modules/@l8zk/`

### Circom Artifacts Download Failed

If artifact download fails:

1. Check internet connection
2. Clear cache and retry: `rm -rf ~/.l8zk/circom`
3. The SDK will re-download on next run

### Permission Denied (EACCES)

If you see binary permission errors:

1. The postinstall script should fix this automatically
2. Manual fix: `chmod +x node_modules/@l8zk/sdk-*/bin/ecdsa-spartan2`

### Performance Issues

For slow proof generation:

1. First run downloads ~33MB of artifacts - subsequent runs are faster
2. Proof generation is CPU-intensive (~6s for prepare, ~100ms for show)
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
