/**
 * Example 1: Age Verification
 * A bar/nightclub app that verifies users are 18+ without revealing their actual age
 */

import { OpenAC, type Policy } from "@l8zk/sdk";

// Simulated SD-JWT credential from a government ID provider
const MOCK_SD_JWT = `eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL2dvdi5leGFtcGxlLmNvbSIsInN1YiI6ImRpZDpleGFtcGxlOjEyMzQ1Njc4OSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDAwLCJjbmYiOnsiand0Ijp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiLi4uIiwieSI6Ii4uLiJ9fSwiX3NkIjpbIi4uLiJdfQ.signature~WyJzYWx0MSIsInJvY19iaXJ0aGRheSIsIjEwNDA2MDUiXQ`;

/**
 * Wallet-side: Prepare credential when user imports their ID
 */
async function walletPrepareCredential() {
    console.log("Preparing credential for age verification...");

    const handle = await OpenAC.prepare({
        credential: MOCK_SD_JWT,
        deviceBinding: true, // Bind to this device's secure enclave
    });

    console.log("Credential prepared successfully");
    console.log("Available claims:", handle.getMetadata().availableClaims);

    return handle;
}

/**
 * Wallet-side: Generate proof when entering the venue
 */
async function walletGenerateProof(
    handle: Awaited<ReturnType<typeof walletPrepareCredential>>,
    verifierNonce: string
) {
    console.log("Generating age proof...");

    const policy: Policy = {
        age: { gte: 18 }, // Prove age >= 18
    };

    const proof = await handle.show({
        policy,
        nonce: verifierNonce,
    });

    console.log("Proof generated in", Date.now() - proof.timestamp, "ms");

    // Serialize for transmission
    return OpenAC.serializeProof(proof);
}

/**
 * Verifier-side: Verify the proof at the door
 */
async function verifierCheckProof(
    serializedProof: ReturnType<typeof OpenAC.serializeProof>
) {
    console.log("Verifying age proof...");

    const expectedPolicy: Policy = {
        age: { gte: 18 },
    };

    const result = await OpenAC.verify(serializedProof, expectedPolicy);

    if (result.valid) {
        console.log("Access granted - User is 18+");
        console.log(
            "Proof timestamp:",
            new Date(result.timestamp!).toISOString()
        );
    } else {
        console.log("Access denied:", result.error);
    }

    return result;
}

/**
 * Full flow demonstration
 */
async function main() {
    console.log("=== Age Verification Example ===\n");

    // Step 1: User imports their government ID into the wallet
    const credentialHandle = await walletPrepareCredential();

    // Step 2: User arrives at venue, verifier generates a nonce
    const verifierNonce = crypto.randomUUID();
    console.log("\nVerifier nonce:", verifierNonce);

    // Step 3: User's wallet generates a proof
    const proof = await walletGenerateProof(credentialHandle, verifierNonce);

    // Step 4: Verifier checks the proof
    console.log("\n");
    const result = await verifierCheckProof(proof);

    // Privacy guarantee: The verifier only learns that the user is 18+
    // They do NOT learn:
    // - The user's actual age or birthdate
    // - The user's name or any other personal information
    // - Any way to link this verification to future visits

    console.log("\nPrivacy preserved:");
    console.log("- Actual age: HIDDEN");
    console.log("- Birthdate: HIDDEN");
    console.log("- Name: HIDDEN");
    console.log("- Linkability: NONE (each proof is unique)");
}

main().catch(console.error);
