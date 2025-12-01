/**
 * Show Phase Implementation
 * Handles the online proof generation for credential presentation
 */

import type {
    ShowOptions,
    PreparedState,
    Proof,
    Policy,
    CircuitParams,
    ECPublicKey,
} from "../types";
import { ProofError, PolicyError } from "../errors";
import { getWasm, loadWasm } from "./wasm-loader";
import {
    sign,
    parseSignatureForCircuit,
    hashMessageForCircuit,
    jwkToCoordinates,
} from "../utils/crypto";

const PROTOCOL_VERSION = "1.0.0";

/**
 * Execute the show phase to generate a proof
 * This is run for each presentation and must be fast (<150ms target)
 */
export async function showCredential(
    state: PreparedState,
    options: ShowOptions,
    params: CircuitParams,
    provingKey: Uint8Array,
    devicePrivateKey?: Uint8Array
): Promise<Proof> {
    const { policy, nonce, currentDate } = options;

    // Validate policy
    validatePolicy(policy, state);

    // Get current date
    const date = currentDate || getCurrentDate();

    // Reblind the prepare proof for unlinkability
    await loadWasm();
    const wasm = getWasm();

    const reblindedPrepare = wasm.reblind(
        provingKey,
        state.prepareInstance,
        state.prepareWitness,
        state.sharedBlinds
    );

    // Sign the nonce for device binding
    let deviceSignature: Uint8Array | undefined;
    if (devicePrivateKey && state.deviceKey) {
        deviceSignature = sign(nonce, devicePrivateKey);
    }

    // Generate show circuit inputs
    const showInputs = generateShowInputs(
        state,
        nonce,
        deviceSignature,
        date,
        params
    );

    // Generate show witness
    const showWitness = generateShowWitness(showInputs, params);

    // Generate show proof
    const showResult = wasm.prove_show(provingKey, showWitness);

    return {
        prepareProof: reblindedPrepare.proof,
        showProof: showResult.proof,
        sharedCommitment: reblindedPrepare.sharedCommitment,
        policy,
        nonce,
        timestamp: Date.now(),
        version: PROTOCOL_VERSION,
    };
}

/**
 * Validate that the policy can be satisfied by the credential
 */
function validatePolicy(policy: Policy, state: PreparedState): void {
    const availableClaims = state.metadata.availableClaims;

    for (const [key, condition] of Object.entries(policy)) {
        if (condition === undefined) continue;

        // Age is a special case - derived from birthdate
        if (key === "age") {
            const hasBirthdate =
                availableClaims.includes("roc_birthday") ||
                availableClaims.includes("birthdate") ||
                state.claims.ageClaim.some((v) => v !== 0);
            if (!hasBirthdate) {
                throw new PolicyError(
                    `Cannot prove age: no birthdate claim available in credential`
                );
            }
            continue;
        }

        // Check if claim exists
        if (
            !availableClaims.includes(key) &&
            !state.claims.rawClaims.has(key)
        ) {
            throw new PolicyError(
                `Claim '${key}' not available in credential. Available: ${availableClaims.join(
                    ", "
                )}`
            );
        }
    }
}

/**
 * Get current date
 */
function getCurrentDate(): { year: number; month: number; day: number } {
    const now = new Date();
    return {
        year: now.getUTCFullYear(),
        month: now.getUTCMonth() + 1,
        day: now.getUTCDate(),
    };
}

/**
 * Generate inputs for the show circuit
 */
function generateShowInputs(
    state: PreparedState,
    nonce: string,
    deviceSignature: Uint8Array | undefined,
    date: { year: number; month: number; day: number },
    params: CircuitParams
): ShowCircuitInputs {
    const decodedLen = Math.floor((params.maxClaimsLength * 3) / 4);

    // Device key coordinates
    const deviceKeyX = state.claims.keyBindingX;
    const deviceKeyY = state.claims.keyBindingY;

    // Parse signature if present
    let sigR = 0n;
    let sigSInverse = 0n;
    let messageHash = 0n;

    if (deviceSignature) {
        const parsed = parseSignatureForCircuit(deviceSignature);
        sigR = parsed.r;
        sigSInverse = parsed.sInverse;
        messageHash = hashMessageForCircuit(nonce);
    }

    // Prepare claim array
    const claim = new Array(decodedLen).fill(0n);
    for (let i = 0; i < state.claims.ageClaim.length && i < decodedLen; i++) {
        claim[i] = BigInt(state.claims.ageClaim[i]);
    }

    return {
        deviceKeyX,
        deviceKeyY,
        sigR,
        sigSInverse,
        messageHash,
        claim,
        currentYear: BigInt(date.year),
        currentMonth: BigInt(date.month),
        currentDay: BigInt(date.day),
    };
}

interface ShowCircuitInputs {
    deviceKeyX: bigint;
    deviceKeyY: bigint;
    sigR: bigint;
    sigSInverse: bigint;
    messageHash: bigint;
    claim: bigint[];
    currentYear: bigint;
    currentMonth: bigint;
    currentDay: bigint;
}

/**
 * Generate witness for the show circuit
 */
function generateShowWitness(
    inputs: ShowCircuitInputs,
    params: CircuitParams
): Uint8Array {
    const witnessData: bigint[] = [];

    // Add inputs in the order expected by the circuit
    witnessData.push(inputs.deviceKeyX);
    witnessData.push(inputs.deviceKeyY);
    witnessData.push(inputs.messageHash);
    witnessData.push(inputs.sigR);
    witnessData.push(inputs.sigSInverse);

    // Add claim array
    for (const byte of inputs.claim) {
        witnessData.push(byte);
    }

    // Add date
    witnessData.push(inputs.currentYear);
    witnessData.push(inputs.currentMonth);
    witnessData.push(inputs.currentDay);

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
 * Reblind a prepared state for a new presentation
 * This ensures unlinkability between presentations
 */
export async function reblindPreparedState(
    state: PreparedState,
    provingKey: Uint8Array
): Promise<{
    instance: Uint8Array;
    witness: Uint8Array;
    proof: Uint8Array;
    sharedCommitment: Uint8Array;
}> {
    await loadWasm();
    const wasm = getWasm();

    // Generate new blinds
    const newBlinds = wasm.generate_blinds(1);

    // Reblind
    const result = wasm.reblind(
        provingKey,
        state.prepareInstance,
        state.prepareWitness,
        newBlinds
    );

    return {
        instance: result.instance,
        witness: result.witness,
        proof: result.proof,
        sharedCommitment: result.sharedCommitment,
    };
}
