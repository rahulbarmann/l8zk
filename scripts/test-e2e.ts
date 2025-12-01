#!/usr/bin/env npx tsx
/**
 * L8ZK SDK - Real End-to-End Test
 * Tests the actual OpenAC class with real ZK proofs via native backend
 * NO MOCKS - This is the real deal
 */

import { OpenAC } from "../src/openac";
import { generateKeyPair, sign } from "../src/utils/crypto";
import { base64UrlEncode } from "../src/utils/base64";
import { isNativeAvailable, initNativeBackend } from "../src/prover/native-backend";

console.log("=".repeat(60));
console.log("  L8ZK SDK - Real End-to-End Test (NO MOCKS)");
console.log("=".repeat(60));
console.log();

// Create a real SD-JWT credential
function createRealCredential() {
  const issuerKeys = generateKeyPair();
  const deviceKeys = generateKeyPair();

  const header = { alg: "ES256", typ: "vc+sd-jwt" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "https://gov.example.com",
    sub: "did:example:alice",
    iat: now,
    exp: now + 365 * 24 * 60 * 60,
    cnf: { jwk: deviceKeys.publicKey },
    _sd: [],
  };

  const headerB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = sign(signingInput, issuerKeys.privateKey);
  const signatureB64 = base64UrlEncode(signature);

  // Add disclosures for age and nationality
  const birthdayDisclosure = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(["salt1", "roc_birthday", "1040605"]))
  );
  const nationalityDisclosure = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(["salt2", "nationality", "DE"]))
  );

  return `${headerB64}.${payloadB64}.${signatureB64}~${birthdayDisclosure}~${nationalityDisclosure}`;
}

async function main() {
  // Check native backend
  console.log("[1/5] Checking native backend...");
  if (!isNativeAvailable()) {
    console.error("ERROR: Native backend not available!");
    console.error(
      "Build it: cd wallet-unit-poc/wallet-unit-poc/ecdsa-spartan2 && cargo build --release"
    );
    process.exit(1);
  }

  const status = initNativeBackend();
  console.log(`  Native backend: ${status.available ? "READY" : "NOT AVAILABLE"}`);
  console.log(`  Binary: ${status.binaryPath}`);
  console.log();

  // Create credential
  console.log("[2/5] Creating real SD-JWT credential...");
  const credential = createRealCredential();
  console.log(`  Credential length: ${credential.length} bytes`);
  console.log();

  // Prepare credential with REAL ZK proofs
  console.log("[3/5] Preparing credential (REAL ZK proofs)...");
  console.log("  This will take ~12 seconds for real proof generation...");
  console.log();

  const startPrepare = Date.now();
  const handle = await OpenAC.prepare({
    credential,
    deviceBinding: true,
  });
  const prepareTime = Date.now() - startPrepare;

  console.log();
  console.log(`  Prepare completed in ${(prepareTime / 1000).toFixed(2)}s`);
  console.log(`  Credential ID: ${handle.id}`);
  console.log(`  Metadata:`, handle.getMetadata());
  console.log();

  // Generate presentation proof
  console.log("[4/5] Generating presentation proof (REAL ZK proof)...");
  const nonce = OpenAC.generateNonce();
  console.log(`  Verifier nonce: ${nonce}`);

  const startShow = Date.now();
  const proof = await handle.show({
    policy: { age: { gte: 18 } },
    nonce,
  });
  const showTime = Date.now() - startShow;

  console.log();
  console.log(`  Show proof generated in ${showTime}ms`);
  console.log(`  Policy: age >= 18`);
  console.log();

  // Verify proof
  console.log("[5/5] Verifying proof (REAL cryptographic verification)...");
  const startVerify = Date.now();
  const result = await OpenAC.verify(proof, { age: { gte: 18 } }, { expectedNonce: nonce });
  const verifyTime = Date.now() - startVerify;

  console.log();
  console.log(`  Verification completed in ${verifyTime}ms`);
  console.log(`  Result: ${result.valid ? "VALID" : "INVALID"}`);
  if (result.error) console.log(`  Error: ${result.error}`);
  console.log();

  // Summary
  console.log("=".repeat(60));
  if (result.valid) {
    console.log("  SUCCESS - Real end-to-end ZK proof flow completed!");
    console.log();
    console.log("  Performance:");
    console.log(`    Prepare: ${(prepareTime / 1000).toFixed(2)}s`);
    console.log(`    Show:    ${showTime}ms`);
    console.log(`    Verify:  ${verifyTime}ms`);
    console.log();
    console.log("  This was NOT a mock - real Spartan2 ZK proofs were generated!");
  } else {
    console.log("  FAILED - Verification did not pass");
    console.log(`  Error: ${result.error}`);
  }
  console.log("=".repeat(60));

  process.exit(result.valid ? 0 : 1);
}

main().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
