/**
 * SD-JWT Credential Parser
 * Parses and validates SD-JWT credentials for the prepare phase
 */

import { CredentialError } from "../errors";
import type {
    ECPublicKey,
    CredentialMetadata,
    ExtractedClaims,
    CircuitParams,
    DEFAULT_CIRCUIT_PARAMS,
} from "../types";
import {
    base64UrlDecode,
    base64DecodeString,
    base64ToBigInt,
} from "../utils/base64";
import { sha256Hash, bytesToBigInt } from "../utils/crypto";

/** Parsed SD-JWT structure */
export interface ParsedSDJWT {
    header: SDJWTHeader;
    payload: SDJWTPayload;
    signature: Uint8Array;
    rawHeader: string;
    rawPayload: string;
    rawSignature: string;
    disclosures: SDJWTDisclosure[];
    keyBinding?: string;
}

/** SD-JWT header */
export interface SDJWTHeader {
    alg: string;
    typ?: string;
    kid?: string;
}

/** SD-JWT payload */
export interface SDJWTPayload {
    iss?: string;
    sub?: string;
    iat?: number;
    exp?: number;
    cnf?: {
        jwk?: ECPublicKey;
    };
    _sd?: string[];
    _sd_alg?: string;
    [key: string]: unknown;
}

/** SD-JWT disclosure */
export interface SDJWTDisclosure {
    salt: string;
    claimName: string;
    claimValue: unknown;
    encoded: string;
    hash: string;
}

/**
 * Parse an SD-JWT credential string
 */
export function parseSDJWT(credential: string): ParsedSDJWT {
    const parts = credential.split("~");
    const jwtPart = parts[0];
    const disclosureParts = parts.slice(1).filter((p) => p.length > 0);

    const jwtSegments = jwtPart.split(".");
    if (jwtSegments.length !== 3) {
        throw new CredentialError(
            "Invalid SD-JWT format: expected 3 JWT segments"
        );
    }

    const [rawHeader, rawPayload, rawSignature] = jwtSegments;

    let header: SDJWTHeader;
    let payload: SDJWTPayload;

    try {
        header = JSON.parse(base64DecodeString(rawHeader));
    } catch (e) {
        throw new CredentialError("Failed to parse SD-JWT header", e as Error);
    }

    try {
        payload = JSON.parse(base64DecodeString(rawPayload));
    } catch (e) {
        throw new CredentialError("Failed to parse SD-JWT payload", e as Error);
    }

    if (header.alg !== "ES256") {
        throw new CredentialError(
            `Unsupported algorithm: ${header.alg}. Only ES256 is supported.`
        );
    }

    const signature = base64UrlDecode(rawSignature);

    const disclosures = disclosureParts.map((encoded) =>
        parseDisclosure(encoded)
    );

    // Check for key binding JWT (last part after ~)
    const lastPart = parts[parts.length - 1];
    const keyBinding = lastPart.includes(".") ? lastPart : undefined;

    return {
        header,
        payload,
        signature,
        rawHeader,
        rawPayload,
        rawSignature,
        disclosures,
        keyBinding,
    };
}

/**
 * Parse a single SD-JWT disclosure
 */
function parseDisclosure(encoded: string): SDJWTDisclosure {
    try {
        const decoded = base64DecodeString(encoded);
        const parsed = JSON.parse(decoded);

        if (!Array.isArray(parsed) || parsed.length < 2) {
            throw new Error("Invalid disclosure format");
        }

        const [salt, claimName, claimValue] = parsed;
        const hash = computeDisclosureHash(encoded);

        return {
            salt,
            claimName: String(claimName),
            claimValue: parsed.length > 2 ? claimValue : claimName,
            encoded,
            hash,
        };
    } catch (e) {
        throw new CredentialError(
            `Failed to parse disclosure: ${encoded}`,
            e as Error
        );
    }
}

/**
 * Compute SHA-256 hash of disclosure (Base64URL encoded)
 */
function computeDisclosureHash(encoded: string): string {
    const bytes = new TextEncoder().encode(encoded);
    const hash = sha256Hash(bytes);
    return bytesToHex(hash);
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * Extract metadata from parsed SD-JWT
 */
export function extractMetadata(parsed: ParsedSDJWT): CredentialMetadata {
    const availableClaims: string[] = [];

    // Add claims from payload
    for (const key of Object.keys(parsed.payload)) {
        if (
            !key.startsWith("_") &&
            !["iss", "sub", "iat", "exp", "cnf"].includes(key)
        ) {
            availableClaims.push(key);
        }
    }

    // Add claims from disclosures
    for (const disclosure of parsed.disclosures) {
        if (!availableClaims.includes(disclosure.claimName)) {
            availableClaims.push(disclosure.claimName);
        }
    }

    return {
        format: "sd-jwt",
        issuer: parsed.payload.iss || "unknown",
        subject: parsed.payload.sub,
        issuedAt: parsed.payload.iat
            ? new Date(parsed.payload.iat * 1000)
            : undefined,
        expiresAt: parsed.payload.exp
            ? new Date(parsed.payload.exp * 1000)
            : undefined,
        availableClaims,
        deviceBound: !!parsed.payload.cnf?.jwk,
    };
}

/**
 * Extract claims needed for circuit inputs
 */
export function extractClaimsForCircuit(
    parsed: ParsedSDJWT,
    params: CircuitParams
): ExtractedClaims {
    const rawClaims = new Map<string, unknown>();

    // Extract claims from disclosures
    for (const disclosure of parsed.disclosures) {
        rawClaims.set(disclosure.claimName, disclosure.claimValue);
    }

    // Extract device binding key
    let keyBindingX = 0n;
    let keyBindingY = 0n;

    if (parsed.payload.cnf?.jwk) {
        const jwk = parsed.payload.cnf.jwk;
        keyBindingX = base64ToBigInt(jwk.x);
        keyBindingY = base64ToBigInt(jwk.y);
    }

    // Find and extract age claim (roc_birthday format)
    const ageClaim = extractAgeClaim(parsed, params);

    return {
        keyBindingX,
        keyBindingY,
        ageClaim,
        rawClaims,
    };
}

/**
 * Extract age claim in the format expected by the circuit
 */
function extractAgeClaim(parsed: ParsedSDJWT, params: CircuitParams): number[] {
    const decodedLen = Math.floor((params.maxClaimsLength * 3) / 4);
    const ageClaim = new Array(decodedLen).fill(0);

    // Look for roc_birthday claim in disclosures
    const birthdayDisclosure = parsed.disclosures.find(
        (d) => d.claimName === "roc_birthday" || d.claimName === "birthdate"
    );

    if (birthdayDisclosure) {
        // The claim value should be decoded and converted to ASCII codes
        const claimStr = JSON.stringify([
            birthdayDisclosure.salt,
            birthdayDisclosure.claimName,
            birthdayDisclosure.claimValue,
        ]);

        for (let i = 0; i < claimStr.length && i < decodedLen; i++) {
            ageClaim[i] = claimStr.charCodeAt(i);
        }
    }

    return ageClaim;
}

/**
 * Generate circuit inputs for the prepare (JWT) circuit
 */
export function generatePrepareInputs(
    credential: string,
    parsed: ParsedSDJWT,
    params: CircuitParams
): Record<string, unknown> {
    const message = `${parsed.rawHeader}.${parsed.rawPayload}`;
    const messageBytes = new TextEncoder().encode(message);

    // Pad message to maxMessageLength
    const paddedMessage = new Array(params.maxMessageLength).fill(0n);
    for (let i = 0; i < messageBytes.length; i++) {
        paddedMessage[i] = BigInt(messageBytes[i]);
    }

    // Parse signature
    const sig = parseECDSASignature(parsed.signature);

    // Extract issuer public key (would need to be provided or fetched)
    // For now, we'll need this to be passed in

    // Find period index
    const periodIndex = message.indexOf(".");

    // Extract matches (claim hashes in payload)
    const { matchSubstring, matchLength, matchIndex, matchesCount } =
        extractMatches(parsed, params);

    // Encode claims
    const { claims, claimLengths, decodeFlags, ageClaimIndex } = encodeClaims(
        parsed,
        params
    );

    return {
        message: paddedMessage.map(String),
        messageLength: messageBytes.length,
        periodIndex,
        sig_r: sig.r.toString(),
        sig_s_inverse: sig.sInverse.toString(),
        pubKeyX: "0", // To be filled by caller
        pubKeyY: "0", // To be filled by caller
        matchesCount,
        matchSubstring,
        matchLength,
        matchIndex,
        claims,
        claimLengths,
        decodeFlags,
        ageClaimIndex,
    };
}

/**
 * Parse ECDSA signature from compact format
 */
function parseECDSASignature(signature: Uint8Array): {
    r: bigint;
    sInverse: bigint;
} {
    // Import dynamically to avoid circular deps
    const { p256 } = require("@noble/curves/p256");
    const { Field } = require("@noble/curves/abstract/modular");

    const SCALAR_ORDER = BigInt(
        "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    );
    const Fq = Field(SCALAR_ORDER);

    const sig = p256.Signature.fromCompact(signature);
    const sInverse = Fq.inv(sig.s);

    return { r: sig.r, sInverse };
}

/**
 * Extract match patterns from payload
 */
function extractMatches(
    parsed: ParsedSDJWT,
    params: CircuitParams
): {
    matchSubstring: bigint[][];
    matchLength: number[];
    matchIndex: number[];
    matchesCount: number;
} {
    const payload = base64DecodeString(parsed.rawPayload);

    // Standard patterns for device binding key extraction
    const patterns = ['"x":"', '"y":"'];

    // Add disclosure hash patterns
    for (const disclosure of parsed.disclosures.slice(
        0,
        params.maxMatches - 2
    )) {
        patterns.push(disclosure.hash.slice(0, params.maxSubstringLength));
    }

    const matchSubstring: bigint[][] = [];
    const matchLength: number[] = [];
    const matchIndex: number[] = [];

    for (const pattern of patterns) {
        const index = payload.indexOf(pattern);
        const paddedPattern = new Array(params.maxSubstringLength).fill(0n);

        for (let i = 0; i < pattern.length; i++) {
            paddedPattern[i] = BigInt(pattern.charCodeAt(i));
        }

        matchSubstring.push(paddedPattern);
        matchLength.push(pattern.length);
        matchIndex.push(index >= 0 ? index : 0);
    }

    // Pad to maxMatches
    while (matchSubstring.length < params.maxMatches) {
        matchSubstring.push(new Array(params.maxSubstringLength).fill(0n));
        matchLength.push(0);
        matchIndex.push(0);
    }

    return {
        matchSubstring: matchSubstring.map((arr) => arr.map((v) => v)),
        matchLength,
        matchIndex,
        matchesCount: patterns.length,
    };
}

/**
 * Encode claims for circuit input
 */
function encodeClaims(
    parsed: ParsedSDJWT,
    params: CircuitParams
): {
    claims: bigint[][];
    claimLengths: bigint[];
    decodeFlags: number[];
    ageClaimIndex: number;
} {
    const claims: bigint[][] = [];
    const claimLengths: bigint[] = [];
    const decodeFlags: number[] = [];
    let ageClaimIndex = 0;

    // First two slots reserved for key binding patterns
    for (let i = 0; i < 2; i++) {
        claims.push(new Array(params.maxClaimsLength).fill(0n));
        claimLengths.push(0n);
        decodeFlags.push(0);
    }

    // Add disclosures
    for (
        let i = 0;
        i < parsed.disclosures.length && claims.length < params.maxMatches;
        i++
    ) {
        const disclosure = parsed.disclosures[i];
        const encoded = disclosure.encoded;

        const paddedClaim = new Array(params.maxClaimsLength).fill(0n);
        for (let j = 0; j < encoded.length && j < params.maxClaimsLength; j++) {
            paddedClaim[j] = BigInt(encoded.charCodeAt(j));
        }

        claims.push(paddedClaim);
        claimLengths.push(BigInt(encoded.length));
        decodeFlags.push(1);

        if (
            disclosure.claimName === "roc_birthday" ||
            disclosure.claimName === "birthdate"
        ) {
            ageClaimIndex = claims.length - 1;
        }
    }

    // Pad to maxMatches
    while (claims.length < params.maxMatches) {
        claims.push(new Array(params.maxClaimsLength).fill(0n));
        claimLengths.push(0n);
        decodeFlags.push(0);
    }

    return {
        claims: claims.map((arr) => arr.map((v) => v)),
        claimLengths,
        decodeFlags,
        ageClaimIndex,
    };
}
