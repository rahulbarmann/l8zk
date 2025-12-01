/**
 * Cryptographic utilities for L8ZK SDK
 * Uses @noble/curves for ECDSA operations
 */

import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import type { ECPublicKey } from "../types";
import { base64ToBigInt, bigIntToBase64Url } from "./base64";

/** P-256 scalar field order */
const SCALAR_FIELD_ORDER = BigInt(
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);

/** Modular inverse using extended Euclidean algorithm */
export function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [a % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

/** Generate a new P-256 key pair */
export function generateKeyPair(): {
  privateKey: Uint8Array;
  publicKey: ECPublicKey;
} {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKeyPoint = p256.getPublicKey(privateKey);
  const point = p256.ProjectivePoint.fromHex(publicKeyPoint);

  return {
    privateKey,
    publicKey: {
      kty: "EC",
      crv: "P-256",
      x: bigIntToBase64Url(point.x),
      y: bigIntToBase64Url(point.y),
    },
  };
}

/** Sign a message with ECDSA P-256 */
export function sign(message: string | Uint8Array, privateKey: Uint8Array | string): Uint8Array {
  const privateKeyBytes = typeof privateKey === "string" ? hexToBytes(privateKey) : privateKey;

  const messageBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;

  const messageHash = sha256(messageBytes);
  const signature = p256.sign(messageHash, privateKeyBytes);

  return signature.toCompactRawBytes();
}

/** Verify an ECDSA P-256 signature */
export function verify(
  message: string | Uint8Array,
  signature: Uint8Array,
  publicKey: ECPublicKey
): boolean {
  const messageBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;

  const messageHash = sha256(messageBytes);
  const pubKeyX = base64ToBigInt(publicKey.x);
  const pubKeyY = base64ToBigInt(publicKey.y);
  const point = new p256.ProjectivePoint(pubKeyX, pubKeyY, 1n);

  return p256.verify(signature, messageHash, point.toRawBytes());
}

/** Parse ECDSA signature for circuit input */
export function parseSignatureForCircuit(signature: Uint8Array): {
  r: bigint;
  sInverse: bigint;
} {
  const sig = p256.Signature.fromCompact(signature);
  const sInverse = modInverse(sig.s, SCALAR_FIELD_ORDER);

  return {
    r: sig.r,
    sInverse,
  };
}

/** Hash message and reduce modulo scalar field order */
export function hashMessageForCircuit(message: string | Uint8Array): bigint {
  const messageBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;

  const hash = sha256(messageBytes);
  const hashBigInt = bytesToBigInt(hash);

  return hashBigInt % SCALAR_FIELD_ORDER;
}

/** Convert hex string to Uint8Array */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Convert Uint8Array to hex string */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Convert Uint8Array to BigInt */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) + BigInt(byte);
  }
  return result;
}

/** Convert BigInt to Uint8Array (32 bytes) */
export function bigIntToBytes(value: bigint, length = 32): Uint8Array {
  const hex = value.toString(16).padStart(length * 2, "0");
  return hexToBytes(hex);
}

/** SHA-256 hash */
export function sha256Hash(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return sha256(bytes);
}

/** Generate random bytes */
export function randomBytes(length: number): Uint8Array {
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  // Node.js fallback
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const nodeCrypto = require("crypto");
  return new Uint8Array(nodeCrypto.randomBytes(length));
}

/** Generate a random scalar in the P-256 field */
export function randomScalar(): bigint {
  const bytes = randomBytes(32);
  const value = bytesToBigInt(bytes);
  return value % SCALAR_FIELD_ORDER;
}

/** Convert JWK public key to coordinates */
export function jwkToCoordinates(jwk: ECPublicKey): { x: bigint; y: bigint } {
  return {
    x: base64ToBigInt(jwk.x),
    y: base64ToBigInt(jwk.y),
  };
}

/** Convert coordinates to JWK public key */
export function coordinatesToJwk(x: bigint, y: bigint): ECPublicKey {
  return {
    kty: "EC",
    crv: "P-256",
    x: bigIntToBase64Url(x),
    y: bigIntToBase64Url(y),
  };
}
