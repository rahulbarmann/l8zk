/**
 * Circuit Input Generator
 * Generates proper inputs for the ZK circuits from SD-JWT credentials
 */

import { writeFileSync, mkdirSync, readFileSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { randomBytes } from "crypto";
import type { ParsedSDJWT } from "../credential/parser";
import type { ECPublicKey, CircuitParams } from "../types";
import {
  parseSignatureForCircuit,
  hashMessageForCircuit,
  jwkToCoordinates,
  sha256Hash,
  bytesToBigInt,
} from "../utils/crypto";
import { base64UrlDecode, base64DecodeString } from "../utils/base64";

// Circuit parameters matching the compiled circuits
const DEFAULT_PARAMS: CircuitParams = {
  maxMessageLength: 1920,
  maxB64PayloadLength: 1900,
  maxMatches: 4,
  maxSubstringLength: 50,
  maxClaimsLength: 128,
};

export interface PrepareCircuitInputs {
  sig_r: string;
  sig_s_inverse: string;
  pubKeyX: string;
  pubKeyY: string;
  message: string[];
  messageLength: number;
  periodIndex: number;
  matchesCount: number;
  matchSubstring: string[][];
  matchLength: number[];
  matchIndex: number[];
  claims: string[][];
  claimLengths: string[];
  decodeFlags: number[];
  ageClaimIndex: number;
}

export interface ShowCircuitInputs {
  deviceKeyX: string;
  deviceKeyY: string;
  sig_r: string;
  sig_s_inverse: string;
  messageHash: string;
  claim: string[];
  currentYear: string;
  currentMonth: string;
  currentDay: string;
}

/**
 * Generate inputs for the prepare (JWT) circuit
 */
export function generatePrepareCircuitInputs(
  parsed: ParsedSDJWT,
  issuerPublicKey: ECPublicKey,
  params: CircuitParams = DEFAULT_PARAMS
): PrepareCircuitInputs {
  // Parse the ECDSA signature
  const { r, sInverse } = parseSignatureForCircuit(parsed.signature);

  // Get issuer public key coordinates
  const { x: pubKeyX, y: pubKeyY } = jwkToCoordinates(issuerPublicKey);

  // Build the message (header.payload)
  const message = `${parsed.rawHeader}.${parsed.rawPayload}`;
  const messageBytes = new TextEncoder().encode(message);

  // Pad message to maxMessageLength
  const paddedMessage: string[] = new Array(params.maxMessageLength).fill("0");
  for (let i = 0; i < messageBytes.length && i < params.maxMessageLength; i++) {
    paddedMessage[i] = messageBytes[i].toString();
  }

  // Find period index
  const periodIndex = message.indexOf(".");

  // Decode payload for pattern matching
  const payloadJson = base64DecodeString(parsed.rawPayload);

  // Extract match patterns
  const { matchSubstring, matchLength, matchIndex, matchesCount } = extractMatchPatterns(
    payloadJson,
    parsed,
    params
  );

  // Encode claims
  const { claims, claimLengths, decodeFlags, ageClaimIndex } = encodeClaims(parsed, params);

  return {
    sig_r: r.toString(),
    sig_s_inverse: sInverse.toString(),
    pubKeyX: pubKeyX.toString(),
    pubKeyY: pubKeyY.toString(),
    message: paddedMessage,
    messageLength: messageBytes.length,
    periodIndex,
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
 * Generate inputs for the show circuit
 */
export function generateShowCircuitInputs(
  parsed: ParsedSDJWT,
  devicePublicKey: ECPublicKey,
  devicePrivateKey: Uint8Array
): ShowCircuitInputs {
  // Get device key coordinates
  const { x: deviceKeyX, y: deviceKeyY } = jwkToCoordinates(devicePublicKey);

  // Find the age/birthday claim
  const birthdayDisclosure = parsed.disclosures.find(
    (d) => d.claimName === "roc_birthday" || d.claimName === "birthdate"
  );

  if (!birthdayDisclosure) {
    throw new Error("No birthday claim found in credential");
  }

  // Build the claim array (the decoded disclosure)
  const claimStr = JSON.stringify([
    birthdayDisclosure.salt,
    birthdayDisclosure.claimName,
    birthdayDisclosure.claimValue,
  ]);

  const claimBytes: string[] = new Array(96).fill("0");
  for (let i = 0; i < claimStr.length && i < 96; i++) {
    claimBytes[i] = claimStr.charCodeAt(i).toString();
  }

  // Hash the message for signing
  const message = `${parsed.rawHeader}.${parsed.rawPayload}`;
  const messageHash = hashMessageForCircuit(message);

  // Sign with device key to prove possession
  const { p256 } = require("@noble/curves/p256");
  const { sha256 } = require("@noble/hashes/sha256");

  const msgHash = sha256(new TextEncoder().encode(message));
  const deviceSig = p256.sign(msgHash, devicePrivateKey);
  const { r, sInverse } = parseSignatureForCircuit(deviceSig.toCompactRawBytes());

  // Current date for age verification
  const now = new Date();

  return {
    deviceKeyX: deviceKeyX.toString(),
    deviceKeyY: deviceKeyY.toString(),
    sig_r: r.toString(),
    sig_s_inverse: sInverse.toString(),
    messageHash: messageHash.toString(),
    claim: claimBytes,
    currentYear: now.getFullYear().toString(),
    currentMonth: (now.getMonth() + 1).toString(),
    currentDay: now.getDate().toString(),
  };
}

/**
 * Extract match patterns from payload
 */
function extractMatchPatterns(
  payloadJson: string,
  parsed: ParsedSDJWT,
  params: CircuitParams
): {
  matchSubstring: string[][];
  matchLength: number[];
  matchIndex: number[];
  matchesCount: number;
} {
  const patterns: string[] = [];
  const matchSubstring: string[][] = [];
  const matchLength: number[] = [];
  const matchIndex: number[] = [];

  // Pattern 1: "x":" for device key X coordinate
  patterns.push('"x":"');

  // Pattern 2: "y":" for device key Y coordinate
  patterns.push('"y":"');

  // Add disclosure hash patterns (first 43 chars of base64url hash)
  for (const disclosure of parsed.disclosures.slice(0, params.maxMatches - 2)) {
    const hashBytes = sha256Hash(disclosure.encoded);
    const hashB64 = Buffer.from(hashBytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    patterns.push(hashB64.slice(0, 43));
  }

  // Build match arrays
  for (const pattern of patterns) {
    const index = payloadJson.indexOf(pattern);
    const paddedPattern: string[] = new Array(params.maxSubstringLength).fill("0");

    for (let i = 0; i < pattern.length && i < params.maxSubstringLength; i++) {
      paddedPattern[i] = pattern.charCodeAt(i).toString();
    }

    matchSubstring.push(paddedPattern);
    matchLength.push(pattern.length);
    matchIndex.push(index >= 0 ? index : 0);
  }

  // Pad to maxMatches
  while (matchSubstring.length < params.maxMatches) {
    matchSubstring.push(new Array(params.maxSubstringLength).fill("0"));
    matchLength.push(0);
    matchIndex.push(0);
  }

  return {
    matchSubstring,
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
  claims: string[][];
  claimLengths: string[];
  decodeFlags: number[];
  ageClaimIndex: number;
} {
  const claims: string[][] = [];
  const claimLengths: string[] = [];
  const decodeFlags: number[] = [];
  let ageClaimIndex = 0;

  // First two slots reserved for key binding patterns (filled with padding)
  for (let i = 0; i < 2; i++) {
    const paddedClaim = new Array(params.maxClaimsLength).fill("0");
    paddedClaim[0] = "128"; // Padding byte
    claims.push(paddedClaim);
    claimLengths.push("0");
    decodeFlags.push(0);
  }

  // Add disclosures
  for (let i = 0; i < parsed.disclosures.length && claims.length < params.maxMatches; i++) {
    const disclosure = parsed.disclosures[i];
    const encoded = disclosure.encoded;

    const paddedClaim: string[] = new Array(params.maxClaimsLength).fill("0");
    for (let j = 0; j < encoded.length && j < params.maxClaimsLength; j++) {
      paddedClaim[j] = encoded.charCodeAt(j).toString();
    }
    // Add padding byte after content
    if (encoded.length < params.maxClaimsLength) {
      paddedClaim[encoded.length] = "128";
    }

    claims.push(paddedClaim);
    claimLengths.push(encoded.length.toString());
    decodeFlags.push(
      disclosure.claimName === "roc_birthday" || disclosure.claimName === "birthdate" ? 1 : 0
    );

    if (disclosure.claimName === "roc_birthday" || disclosure.claimName === "birthdate") {
      ageClaimIndex = claims.length - 1;
    }
  }

  // Pad to maxMatches
  while (claims.length < params.maxMatches) {
    const paddedClaim = new Array(params.maxClaimsLength).fill("0");
    paddedClaim[0] = "128";
    claims.push(paddedClaim);
    claimLengths.push("0");
    decodeFlags.push(0);
  }

  return {
    claims,
    claimLengths,
    decodeFlags,
    ageClaimIndex,
  };
}

/**
 * Write circuit inputs to a temporary file
 */
export function writeCircuitInputs(
  inputs: PrepareCircuitInputs | ShowCircuitInputs,
  circuit: "jwt" | "show"
): string {
  const tempDir = join(tmpdir(), `l8zk-${randomBytes(8).toString("hex")}`);
  mkdirSync(tempDir, { recursive: true });

  const inputPath = join(tempDir, `${circuit}_input.json`);
  writeFileSync(inputPath, JSON.stringify(inputs, null, 2));

  return inputPath;
}

/**
 * Read proof bytes from the keys directory
 */
export function readProofBytes(
  keysDir: string,
  circuit: "prepare" | "show"
): {
  proof: Uint8Array;
  instance: Uint8Array;
  witness: Uint8Array;
} {
  const proofPath = join(keysDir, `${circuit}_proof.bin`);
  const instancePath = join(keysDir, `${circuit}_instance.bin`);
  const witnessPath = join(keysDir, `${circuit}_witness.bin`);

  if (!existsSync(proofPath)) {
    throw new Error(`Proof file not found: ${proofPath}`);
  }

  return {
    proof: new Uint8Array(readFileSync(proofPath)),
    instance: existsSync(instancePath)
      ? new Uint8Array(readFileSync(instancePath))
      : new Uint8Array(0),
    witness: existsSync(witnessPath)
      ? new Uint8Array(readFileSync(witnessPath))
      : new Uint8Array(0),
  };
}
