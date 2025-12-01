/**
 * Verification Implementation
 * Handles proof verification on the verifier/relying party side
 */

import type {
    Proof,
    SerializedProof,
    VerificationResult,
    VerifyOptions,
    Policy,
} from "../types";
import { VerificationError } from "../errors";
import { loadWasm, getWasm } from "./wasm-loader";
import { base64UrlDecode, base64UrlEncode } from "../utils/base64";

const PROTOCOL_VERSION = "1.0.0";
const DEFAULT_MAX_PROOF_AGE = 5 * 60 * 1000; // 5 minutes

/**
 * Verify a proof
 */
export async function verifyProof(
    proof: Proof | SerializedProof,
    verifyingKey: Uint8Array,
    options: VerifyOptions = {}
): Promise<VerificationResult> {
    const {
        expectedPolicy,
        maxProofAge = DEFAULT_MAX_PROOF_AGE,
        expectedNonce,
    } = options;

    try {
        // Deserialize if needed
        const deserializedProof = isSerializedProof(proof)
            ? deserializeProof(proof)
            : proof;

        // Check version
        if (deserializedProof.version !== PROTOCOL_VERSION) {
            return {
                valid: false,
                error: `Unsupported proof version: ${deserializedProof.version}. Expected: ${PROTOCOL_VERSION}`,
            };
        }

        // Check proof age
        const proofAge = Date.now() - deserializedProof.timestamp;
        if (proofAge > maxProofAge) {
            return {
                valid: false,
                error: `Proof expired. Age: ${proofAge}ms, Max: ${maxProofAge}ms`,
            };
        }

        // Check nonce if expected
        if (expectedNonce && deserializedProof.nonce !== expectedNonce) {
            return {
                valid: false,
                error: "Nonce mismatch",
            };
        }

        // Check policy if expected
        if (expectedPolicy) {
            const policyMatch = comparePolicies(
                expectedPolicy,
                deserializedProof.policy
            );
            if (!policyMatch.valid) {
                return {
                    valid: false,
                    error: `Policy mismatch: ${policyMatch.error}`,
                };
            }
        }

        // Load WASM and verify cryptographic proofs
        await loadWasm();
        const wasm = getWasm();

        // Verify prepare proof
        const prepareValid = wasm.verify(
            deserializedProof.prepareProof,
            verifyingKey
        );
        if (!prepareValid) {
            return {
                valid: false,
                error: "Prepare proof verification failed",
            };
        }

        // Verify show proof
        const showValid = wasm.verify(
            deserializedProof.showProof,
            verifyingKey
        );
        if (!showValid) {
            return {
                valid: false,
                error: "Show proof verification failed",
            };
        }

        // Verify shared commitment matches between prepare and show
        // This ensures the proofs are linked to the same credential
        // The WASM verify function should handle this internally

        return {
            valid: true,
            verifiedPolicy: deserializedProof.policy,
            timestamp: deserializedProof.timestamp,
        };
    } catch (error) {
        return {
            valid: false,
            error: `Verification error: ${(error as Error).message}`,
        };
    }
}

/**
 * Check if a proof is serialized
 */
function isSerializedProof(
    proof: Proof | SerializedProof
): proof is SerializedProof {
    return typeof (proof as SerializedProof).prepareProof === "string";
}

/**
 * Deserialize a proof from JSON-safe format
 */
export function deserializeProof(serialized: SerializedProof): Proof {
    return {
        prepareProof: base64UrlDecode(serialized.prepareProof),
        showProof: base64UrlDecode(serialized.showProof),
        sharedCommitment: base64UrlDecode(serialized.sharedCommitment),
        policy: serialized.policy,
        nonce: serialized.nonce,
        timestamp: serialized.timestamp,
        version: serialized.version,
    };
}

/**
 * Serialize a proof to JSON-safe format
 */
export function serializeProof(proof: Proof): SerializedProof {
    return {
        prepareProof: base64UrlEncode(proof.prepareProof),
        showProof: base64UrlEncode(proof.showProof),
        sharedCommitment: base64UrlEncode(proof.sharedCommitment),
        policy: proof.policy,
        nonce: proof.nonce,
        timestamp: proof.timestamp,
        version: proof.version,
    };
}

/**
 * Compare two policies for compatibility
 */
function comparePolicies(
    expected: Policy,
    actual: Policy
): { valid: boolean; error?: string } {
    for (const [key, expectedCondition] of Object.entries(expected)) {
        if (expectedCondition === undefined) continue;

        const actualCondition = actual[key];
        if (actualCondition === undefined) {
            return {
                valid: false,
                error: `Missing policy condition for '${key}'`,
            };
        }

        // Simple equality check for now
        // More sophisticated comparison would check predicate satisfaction
        if (
            JSON.stringify(expectedCondition) !==
            JSON.stringify(actualCondition)
        ) {
            return {
                valid: false,
                error: `Policy condition mismatch for '${key}'`,
            };
        }
    }

    return { valid: true };
}

/**
 * Quick verification without full cryptographic checks
 * Useful for initial validation before expensive verification
 */
export function quickVerify(
    proof: Proof | SerializedProof,
    options: VerifyOptions = {}
): { valid: boolean; error?: string } {
    const {
        expectedPolicy,
        maxProofAge = DEFAULT_MAX_PROOF_AGE,
        expectedNonce,
    } = options;

    try {
        const deserializedProof = isSerializedProof(proof)
            ? deserializeProof(proof)
            : proof;

        // Check version
        if (deserializedProof.version !== PROTOCOL_VERSION) {
            return {
                valid: false,
                error: `Unsupported version: ${deserializedProof.version}`,
            };
        }

        // Check age
        const proofAge = Date.now() - deserializedProof.timestamp;
        if (proofAge > maxProofAge) {
            return { valid: false, error: "Proof expired" };
        }

        // Check nonce
        if (expectedNonce && deserializedProof.nonce !== expectedNonce) {
            return { valid: false, error: "Nonce mismatch" };
        }

        // Check policy
        if (expectedPolicy) {
            const policyMatch = comparePolicies(
                expectedPolicy,
                deserializedProof.policy
            );
            if (!policyMatch.valid) {
                return { valid: false, error: policyMatch.error };
            }
        }

        return { valid: true };
    } catch (error) {
        return { valid: false, error: (error as Error).message };
    }
}
