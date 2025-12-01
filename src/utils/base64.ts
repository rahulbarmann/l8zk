/**
 * Base64 encoding/decoding utilities
 * Supports both standard Base64 and Base64URL
 */

// Base64 character sets (for reference)
// const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// const BASE64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Convert Base64URL to standard Base64 */
export function base64UrlToBase64(base64url: string): string {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (base64.length % 4)) % 4;
  return base64 + "=".repeat(padding);
}

/** Convert standard Base64 to Base64URL */
export function base64ToBase64Url(base64: string): string {
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode Base64 string to Uint8Array */
export function base64Decode(base64: string): Uint8Array {
  const normalized = base64UrlToBase64(base64);

  if (typeof atob === "function") {
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Node.js fallback
  return new Uint8Array(Buffer.from(normalized, "base64"));
}

/** Encode Uint8Array to Base64 string */
export function base64Encode(bytes: Uint8Array): string {
  if (typeof btoa === "function") {
    const binary = String.fromCharCode(...bytes);
    return btoa(binary);
  }

  // Node.js fallback
  return Buffer.from(bytes).toString("base64");
}

/** Encode Uint8Array to Base64URL string */
export function base64UrlEncode(bytes: Uint8Array): string {
  return base64ToBase64Url(base64Encode(bytes));
}

/** Decode Base64URL string to Uint8Array */
export function base64UrlDecode(base64url: string): Uint8Array {
  return base64Decode(base64UrlToBase64(base64url));
}

/** Decode Base64 string to UTF-8 string */
export function base64DecodeString(base64: string): string {
  const bytes = base64Decode(base64);
  return new TextDecoder().decode(bytes);
}

/** Encode UTF-8 string to Base64 */
export function base64EncodeString(str: string): string {
  const bytes = new TextEncoder().encode(str);
  return base64Encode(bytes);
}

/** Convert Base64 string to BigInt */
export function base64ToBigInt(base64: string): bigint {
  const bytes = base64Decode(base64);
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) + BigInt(byte);
  }
  return result;
}

/** Convert BigInt to Base64URL string (32 bytes, zero-padded) */
export function bigIntToBase64Url(value: bigint): string {
  const hex = value.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return base64UrlEncode(bytes);
}
