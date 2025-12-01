/**
 * Prepare Phase Implementation
 * Handles the offline credential preparation (issuer signature verification, parsing, commitment)
 */

import type {
    PrepareOptions,
    PreparedState,
    CredentialMetadata,
    ExtractedClaims,
    ECPublicKey,
    CircuitParams,
    DEFAULT_CIRCUIT_PARAMS,
} from "../types";
import { CredentialError, ProofError } from "../errors";
import {
    parseSDJWT,
    extractMetadata,
    extractClaimsForCircuit,
    generatePrepareInputs,
} from "../credential/parser";
import { loadWasm, getWasm } from "./wasm-loader";
import { randomBytes, sha256Hash, generateKeyPair } from "../utils/crypto";
import { base64UrlEncode } from "../utils/base64";

/**
 * Execute the prepare phase for a credential
 * This is run once per credential and can take a few seconds
 */
export async function prepareCredential(
    options: PrepareOptions,
    params: CircuitParams,
    provingKey: Uint8Array
): Promise<PreparedState> {
    const {
        credential,
        format = "sd-jwt",
        deviceBinding,
        issuerPublicKey,
    } = options;

    // Validate format
    if (format !== "sd-jwt") {
        throw new CredentialError(
            `Unsupported credential format: ${format}. Only 'sd-jwt' is currently supported.`
        );
    }

    // Parse the credential
    const parsed = parseSDJWT(credential);

    // Extract metadata
    const metadata = extractMetadata(parsed);

    // Extract claims for circuit
    const claims = extractClaimsForCircuit(parsed, params);

    // Handle device binding
    let deviceKey: ECPublicKey | undefined;
    if (deviceBinding) {
        if (typeof deviceBinding === "object") {
            deviceKey = deviceBinding.publicKey;
        } else if (parsed.payload.cnf?.jwk) {
            deviceKey = parsed.payload.cnf.jwk;
        }
    }

    // Get issuer public key
    const issuerPK =
        issuerPublicKey || (await resolveIssuerPublicKey(parsed.payload.iss));
    if (!issuerPK) {
        throw new CredentialError(
            "Issuer public key not provided and could not be resolved"
        );
    }

    // Generate circuit inputs
    const circuitInputs = generatePrepareInputs(credential, parsed, params);
    circuitInputs.pubKeyX = claims.keyBindingX.toString();
    circuitInputs.pubKeyY = claims.keyBindingY.toString();

    // Generate witness
    const witness = generatePrepareWitness(circuitInputs, params);

    // Load WASM and generate proof
    await loadWasm();
    const wasm = getWasm();

    const proveResult = wasm.prove_prepare(provingKey, witness);

    // Generate shared blinds for linking prepare and show proofs
    const sharedBlinds = wasm.generate_blinds(1);

    // Generate unique ID
    const id = generateCredentialId(credential);

    // Encrypt credential for storage
    const encryptedCredential = encryptCredential(credential);

    return {
        id,
        encryptedCredential,
        prepareProof: proveResult.proof,
        prepareInstance: proveResult.instance,
        prepareWitness: proveResult.witness,
        sharedBlinds,
        deviceKey: deviceKey as any,
        metadata: {
            ...metadata,
            deviceBound: !!deviceKey,
        },
        claims,
        createdAt: Date.now(),
    };
}

/**
 * Generate witness for the prepare circuit
 */
function generatePrepareWitness(
    inputs: Record<string, unknown>,
    params: CircuitParams
): Uint8Array {
    // Convert inputs to the format expected by the circuit
    // This matches the rust-witness format used in the PoC
    const witnessData: bigint[] = [];

    // Add message bytes
    const message = inputs.message as string[];
    for (const byte of message) {
        witnessData.push(BigInt(byte));
    }

    // Add other scalar inputs
    witnessData.push(BigInt(inputs.messageLength as number));
    witnessData.push(BigInt(inputs.periodIndex as number));
    witnessData.push(BigInt(inputs.sig_r as string));
    witnessData.push(BigInt(inputs.sig_s_inverse as string));
    witnessData.push(BigInt(inputs.pubKeyX as string));
    witnessData.push(BigInt(inputs.pubKeyY as string));
    witnessData.push(BigInt(inputs.matchesCount as number));

    // Add match data
    const matchSubstring = inputs.matchSubstring as bigint[][];
    const matchLength = inputs.matchLength as number[];
    const matchIndex = inputs.matchIndex as number[];

    for (const match of matchSubstring) {
        for (const byte of match) {
            witnessData.push(byte);
        }
    }

    for (const len of matchLength) {
        witnessData.push(BigInt(len));
    }

    for (const idx of matchIndex) {
        witnessData.push(BigInt(idx));
    }

    // Add claims data
    const claims = inputs.claims as bigint[][];
    const claimLengths = inputs.claimLengths as bigint[];
    const decodeFlags = inputs.decodeFlags as number[];

    for (const claim of claims) {
        for (const byte of claim) {
            witnessData.push(byte);
        }
    }

    for (const len of claimLengths) {
        witnessData.push(len);
    }

    for (const flag of decodeFlags) {
        witnessData.push(BigInt(flag));
    }

    witnessData.push(BigInt(inputs.ageClaimIndex as number));

    // Serialize to bytes (each bigint as 32-byte little-endian)
    const bytes = new Uint8Array(witnessData.length * 32);
    for (let i = 0; i < witnessData.length; i++) {
        const value = witnessData[i];
        const hex = value.toString(16).padStart(64, "0");
        for (let j = 0; j < 32; j++) {
            bytes[i * 32 + j] = parseInt(hex.slice(62 - j * 2, 64 - j * 2), 16);
        }
    }

    return bytes;
}

/**
 * Resolve issuer public key from DID or URL
 */
async function resolveIssuerPublicKey(
    issuer?: string
): Promise<ECPublicKey | null> {
    if (!issuer) return null;

    // DID resolution would go here
    // For now, return null to require explicit key provision
    return null;
}

/**
 * Generate a unique credential ID
 */
function generateCredentialId(credential: string): string {
    const hash = sha256Hash(credential);
    return base64UrlEncode(hash.slice(0, 16));
}

/**
 * Encrypt credential for secure storage
 * Uses a simple XOR with random key for now - production should use AES-GCM
 */
function encryptCredential(credential: string): Uint8Array {
    const bytes = new TextEncoder().encode(credential);
    const key = randomBytes(bytes.length);
    const encrypted = new Uint8Array(key.length + bytes.length);
    encrypted.set(key, 0);
    for (let i = 0; i < bytes.length; i++) {
        encrypted[key.length + i] = bytes[i] ^ key[i];
    }
    return encrypted;
}

/**
 * Decrypt credential from storage
 */
export function decryptCredential(encrypted: Uint8Array): string {
    const keyLength = encrypted.length / 2;
    const key = encrypted.slice(0, keyLength);
    const data = encrypted.slice(keyLength);
    const decrypted = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
        decrypted[i] = data[i] ^ key[i];
    }
    return new TextDecoder().decode(decrypted);
}
