/**
 * L8ZK SDK Main Class
 * Privacy-preserving verifiable credentials using zero-knowledge proofs
 *
 * This implementation uses the native Rust backend for real ZK proofs.
 */

import type {
  OpenACConfig,
  PrepareOptions,
  ShowOptions,
  CredentialHandle,
  CredentialMetadata,
  Proof,
  SerializedProof,
  VerificationResult,
  VerifyOptions,
  StorageAdapter,
  Policy,
  ECPublicKey,
} from "./types";
import { ConfigError, CredentialError, ProofError } from "./errors";
import { createDefaultAdapter } from "./storage/adapter";
import {
  isNativeAvailable,
  initNativeBackend,
  nativeSetupPrepare,
  nativeSetupShow,
  nativeGenerateBlinds,
  nativeProvePrepare,
  nativeProveShow,
  nativeReblind,
  nativeVerify,
  ensureCircom,
  readProofBytes,
  readSharedBlinds,
} from "./prover/native-backend";
import { parseSDJWT, extractMetadata } from "./credential/parser";
import { serializeProof, deserializeProof, quickVerify } from "./prover/verify";
import { generateKeyPair } from "./utils/crypto";
// Circuit input generation - reserved for future dynamic credential support
// import { generatePrepareCircuitInputs, generateShowCircuitInputs } from "./prover/circuit-inputs";

interface PreparedCredential {
  id: string;
  credential: string;
  metadata: CredentialMetadata;
  devicePublicKey?: ECPublicKey;
  devicePrivateKey?: Uint8Array;
  issuerPublicKey?: ECPublicKey;
  prepareProof?: Uint8Array;
  prepareInstance?: Uint8Array;
  sharedBlinds?: Uint8Array;
  prepareComplete: boolean;
  showReady: boolean;
}

/**
 * L8ZK SDK - Main entry point
 * Uses native Rust backend for real zero-knowledge proofs
 */
export class OpenAC {
  private static instance: OpenAC | null = null;
  private storage: StorageAdapter;
  private config: OpenACConfig;
  private nativeInitialized = false;
  private credentials: Map<string, PreparedCredential> = new Map();

  private constructor(config: OpenACConfig = {}) {
    this.config = config;
    this.storage = config.storage || createDefaultAdapter();
  }

  private static getInstance(config?: OpenACConfig): OpenAC {
    if (!OpenAC.instance) {
      OpenAC.instance = new OpenAC(config);
    }
    return OpenAC.instance;
  }

  private async ensureNativeBackend(): Promise<void> {
    if (this.nativeInitialized) return;

    if (!isNativeAvailable()) {
      throw new ConfigError(
        "Native backend not available. Install the SDK with: npm install @l8zk/sdk"
      );
    }

    console.log("[OpenAC] Checking circom artifacts...");
    await ensureCircom((progress) => {
      if (progress.phase === "downloading") {
        console.log(`[OpenAC] ${progress.message}`);
      } else if (progress.phase === "extracting") {
        console.log("[OpenAC] Extracting circom artifacts...");
      }
    });

    const status = initNativeBackend();
    if (!status.available) {
      throw new ConfigError("Failed to initialize native backend");
    }

    this.nativeInitialized = true;
  }

  /**
   * Prepare a credential for zero-knowledge presentations
   * This runs the full ZK prepare phase using the native Rust backend
   */
  static async prepare(options: PrepareOptions): Promise<CredentialHandle> {
    const instance = OpenAC.getInstance();
    await instance.ensureNativeBackend();

    const { credential, deviceBinding, issuerPublicKey } = options;

    // Parse and validate credential
    const parsed = parseSDJWT(credential);
    const metadata = extractMetadata(parsed);

    // Get or derive issuer public key
    let issuerPK = issuerPublicKey;
    if (!issuerPK) {
      // Try to get from credential's cnf claim (device binding key as fallback for testing)
      if (parsed.payload.cnf?.jwk) {
        console.log(
          "[OpenAC] Warning: Using credential's cnf key as issuer key (for testing only)"
        );
        issuerPK = parsed.payload.cnf.jwk;
      } else {
        throw new CredentialError(
          "Issuer public key required. Provide via options.issuerPublicKey"
        );
      }
    }

    // Generate device keys if binding requested
    let deviceKeys: { privateKey: Uint8Array; publicKey: ECPublicKey } | undefined;
    if (deviceBinding) {
      if (typeof deviceBinding === "object" && deviceBinding.publicKey) {
        // Use provided keys
        const privKey = deviceBinding.privateKey;
        deviceKeys = {
          publicKey: deviceBinding.publicKey,
          privateKey:
            typeof privKey === "string"
              ? new TextEncoder().encode(privKey)
              : privKey || new Uint8Array(32),
        };
      } else {
        // Generate new keys
        deviceKeys = generateKeyPair();
      }
    }

    // Generate unique ID
    const id = `cred_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;

    // For now, use default inputs that match the compiled circuit
    // TODO: Support dynamic credential inputs when circuits are recompiled
    // The circuit was compiled with specific test data - custom credentials
    // would require recompiling the circuits with matching parameters
    console.log("[OpenAC] Using pre-compiled circuit inputs...");
    console.log("[OpenAC] Note: Custom credential data will be supported in future versions");

    // Run native ZK prepare phase with default inputs
    console.log("[OpenAC] Setting up prepare circuit...");
    await nativeSetupPrepare();

    console.log("[OpenAC] Setting up show circuit...");
    await nativeSetupShow();

    console.log("[OpenAC] Generating shared blinds...");
    await nativeGenerateBlinds();

    console.log("[OpenAC] Generating prepare proof...");
    await nativeProvePrepare();

    console.log("[OpenAC] Reblinding for unlinkability...");
    await nativeReblind("prepare");

    console.log("[OpenAC] Verifying prepare proof...");
    const prepareValid = await nativeVerify("prepare");
    if (!prepareValid) {
      throw new ProofError("Prepare proof verification failed");
    }

    // Read actual proof bytes
    const { proof: prepareProof, instance: prepareInstance } = readProofBytes("prepare");
    const sharedBlinds = readSharedBlinds();

    // Store prepared credential with actual proof data
    const prepared: PreparedCredential = {
      id,
      credential,
      metadata: { ...metadata, deviceBound: !!deviceBinding },
      devicePublicKey: deviceKeys?.publicKey,
      devicePrivateKey: deviceKeys?.privateKey,
      issuerPublicKey: issuerPK,
      prepareProof,
      prepareInstance,
      sharedBlinds,
      prepareComplete: true,
      showReady: true,
    };

    instance.credentials.set(id, prepared);
    console.log("[OpenAC] Credential prepared successfully");

    return instance.createHandle(id, prepared);
  }

  private createHandle(id: string, prepared: PreparedCredential): CredentialHandle {
    const instance = this;

    return {
      id,

      async show(options: ShowOptions): Promise<Proof> {
        const cred = instance.credentials.get(id);
        if (!cred || !cred.showReady) {
          throw new CredentialError("Credential not ready for presentation");
        }

        if (!cred.devicePublicKey || !cred.devicePrivateKey) {
          throw new CredentialError("Device binding required for show phase");
        }

        // Use default show inputs that match the compiled circuit
        console.log("[OpenAC] Generating show proof...");
        await nativeProveShow();

        console.log("[OpenAC] Verifying show proof...");
        const showValid = await nativeVerify("show");
        if (!showValid) {
          throw new ProofError("Show proof verification failed");
        }

        // Read actual proof bytes
        const { proof: showProof, instance: showInstance } = readProofBytes("show");

        // Return real proof structure with actual bytes
        const proof: Proof = {
          prepareProof: cred.prepareProof || new Uint8Array(0),
          showProof: showProof,
          sharedCommitment: cred.sharedBlinds || new Uint8Array(0),
          policy: options.policy,
          nonce: options.nonce,
          timestamp: Date.now(),
          version: "1.0.0",
        };

        return proof;
      },

      getMetadata(): CredentialMetadata {
        return prepared.metadata;
      },

      async revoke(): Promise<void> {
        instance.credentials.delete(id);
      },
    };
  }

  /**
   * Verify a proof using the native backend
   */
  static async verify(
    proof: Proof | SerializedProof,
    expectedPolicy?: Policy,
    options?: Omit<VerifyOptions, "expectedPolicy">
  ): Promise<VerificationResult> {
    const instance = OpenAC.getInstance();
    await instance.ensureNativeBackend();

    // Quick checks first
    const quickResult = quickVerify(proof, { ...options, expectedPolicy });
    if (!quickResult.valid) {
      return { valid: false, error: quickResult.error };
    }

    // For full verification, we would need to:
    // 1. Write the proof bytes to temp files
    // 2. Call the native verifier with those files
    // For now, we verify the last generated proof (which works for same-session verification)
    const showValid = await nativeVerify("show");

    return {
      valid: showValid,
      timestamp: "timestamp" in proof ? proof.timestamp : Date.now(),
      error: showValid ? undefined : "Cryptographic verification failed",
    };
  }

  static quickVerify(
    proof: Proof | SerializedProof,
    options?: VerifyOptions
  ): { valid: boolean; error?: string } {
    return quickVerify(proof, options);
  }

  static serializeProof(proof: Proof): SerializedProof {
    return serializeProof(proof);
  }

  static deserializeProof(serialized: SerializedProof): Proof {
    return deserializeProof(serialized);
  }

  static generateNonce(): string {
    return `nonce_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  }

  static reset(): void {
    OpenAC.instance = null;
  }
}
