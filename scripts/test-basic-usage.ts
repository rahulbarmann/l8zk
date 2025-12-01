#!/usr/bin/env npx tsx
/**
 * L8ZK SDK - Basic Usage Test Script
 * Tests the SDK imports and basic functionality as documented in README
 */

import { OpenAC } from "../src";
import { initNativeBackend, isNativeAvailable } from "../src/prover/native-backend";
import { generateKeyPair, sign } from "../src/utils/crypto";
import { base64UrlEncode } from "../src/utils/base64";
import { MemoryAdapter } from "../src/storage";

console.log("=".repeat(60));
console.log("  L8ZK SDK - Basic Usage Test");
console.log("=".repeat(60));
console.log();

async function testImports() {
  console.log("[1/5] Testing imports...");

  // Test that all main exports are available
  if (typeof OpenAC !== "function") {
    throw new Error("OpenAC class not exported correctly");
  }

  if (typeof generateKeyPair !== "function") {
    throw new Error("generateKeyPair not exported correctly");
  }

  if (typeof MemoryAdapter !== "function") {
    throw new Error("MemoryAdapter not exported correctly");
  }

  console.log("  - All imports successful");
}

async function testCryptoUtils() {
  console.log("[2/5] Testing crypto utilities...");

  // Generate key pair
  const keys = generateKeyPair();
  if (!keys.privateKey || !keys.publicKey) {
    throw new Error("Key generation failed");
  }
  console.log("  - Key generation: OK");

  // Sign a message
  const message = "test message";
  const signature = sign(message, keys.privateKey);
  if (!signature || signature.length === 0) {
    throw new Error("Signing failed");
  }
  console.log("  - Message signing: OK");

  // Base64 encoding
  const encoded = base64UrlEncode(new Uint8Array([1, 2, 3, 4]));
  if (!encoded || encoded.length === 0) {
    throw new Error("Base64 encoding failed");
  }
  console.log("  - Base64 encoding: OK");
}

async function testStorage() {
  console.log("[3/5] Testing storage adapter...");

  const storage = new MemoryAdapter();

  // Set value
  await storage.set("test-key", new TextEncoder().encode("test-value"));
  console.log("  - Storage set: OK");

  // Get value
  const value = await storage.get("test-key");
  if (!value) {
    throw new Error("Storage get failed");
  }
  console.log("  - Storage get: OK");

  // List keys
  const keys = await storage.keys();
  if (!keys.includes("test-key")) {
    throw new Error("Storage keys failed");
  }
  console.log("  - Storage keys: OK");

  // Delete value
  await storage.delete("test-key");
  const deleted = await storage.get("test-key");
  if (deleted !== null) {
    throw new Error("Storage delete failed");
  }
  console.log("  - Storage delete: OK");
}

async function testNativeBackend() {
  console.log("[4/5] Testing native backend detection...");

  const status = initNativeBackend();
  console.log(`  - Native available: ${status.available}`);

  if (status.available) {
    console.log(`  - Binary path: ${status.binaryPath}`);
    console.log(`  - Circom path: ${status.circomPath || "not found"}`);
  } else {
    console.log("  - Native backend not built (optional for basic usage)");
  }
}

async function testCredentialCreation() {
  console.log("[5/5] Testing credential creation helpers...");

  // Create a mock SD-JWT credential
  const keys = generateKeyPair();
  const header = { alg: "ES256", typ: "vc+sd-jwt" };
  const payload = {
    iss: "https://example.gov",
    sub: "did:example:123",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400,
    cnf: { jwk: keys.publicKey },
  };

  const headerB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = sign(signingInput, keys.privateKey);
  const signatureB64 = base64UrlEncode(signature);

  const sdJwt = `${headerB64}.${payloadB64}.${signatureB64}`;

  if (!sdJwt || sdJwt.split(".").length !== 3) {
    throw new Error("SD-JWT creation failed");
  }
  console.log("  - SD-JWT creation: OK");
  console.log(`  - Credential length: ${sdJwt.length} bytes`);
}

async function main() {
  try {
    await testImports();
    await testCryptoUtils();
    await testStorage();
    await testNativeBackend();
    await testCredentialCreation();

    console.log();
    console.log("=".repeat(60));
    console.log("  All basic usage tests PASSED");
    console.log("=".repeat(60));
    console.log();
    console.log("The @l8zk/sdk package is working correctly.");
    console.log();
    console.log("Next steps:");
    console.log("  - Run full demo: npx tsx examples/full-demo/index.ts");
    console.log("  - Run tests: npm test");
    console.log("  - Build package: npm run build");
    console.log();

    process.exit(0);
  } catch (error) {
    console.error();
    console.error("TEST FAILED:", (error as Error).message);
    console.error();
    process.exit(1);
  }
}

main();
