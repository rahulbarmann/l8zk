/**
 * Example 2: EU Residency Proof
 * A DeFi KYC flow that verifies EU residency without revealing the specific country
 */

import { OpenAC, type Policy, type CredentialHandle } from "@l8zk/sdk";

// EU member state codes
const EU_COUNTRIES = [
    "AT",
    "BE",
    "BG",
    "HR",
    "CY",
    "CZ",
    "DK",
    "EE",
    "FI",
    "FR",
    "DE",
    "GR",
    "HU",
    "IE",
    "IT",
    "LV",
    "LT",
    "LU",
    "MT",
    "NL",
    "PL",
    "PT",
    "RO",
    "SK",
    "SI",
    "ES",
    "SE",
];

// Simulated EUDI Wallet credential
const MOCK_EUDI_CREDENTIAL = `eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL2V1ZGkuZXUiLCJzdWIiOiJkaWQ6ZXVkaToxMjM0NTY3ODkiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTgwMDAwMDAwMCwiY25mIjp7Imp3dCI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ii4uLiIsInkiOiIuLi4ifX0sIl9zZCI6WyIuLi4iXX0.signature~WyJzYWx0MSIsImNvdW50cnlfY29kZSIsIkRFIl0~WyJzYWx0MiIsInJlc2lkZW5jZV9zdGF0dXMiLCJwZXJtYW5lbnQiXQ`;

/**
 * DeFi Platform: KYC Service
 */
class DeFiKYCService {
    private verifiedUsers = new Map<
        string,
        { timestamp: number; region: string }
    >();

    /**
     * Generate a challenge for the user to prove their residency
     */
    generateChallenge(): { nonce: string; policy: Policy } {
        return {
            nonce: crypto.randomUUID(),
            policy: {
                // Prove country is in EU without revealing which country
                countryCode: { in: EU_COUNTRIES },
                // Prove residency status is permanent or temporary
                residenceStatus: { in: ["permanent", "temporary"] },
            },
        };
    }

    /**
     * Verify the user's proof and grant access
     */
    async verifyAndGrant(
        userId: string,
        proof: ReturnType<typeof OpenAC.serializeProof>,
        expectedNonce: string
    ): Promise<{ success: boolean; message: string }> {
        const result = await OpenAC.verify(
            proof,
            {
                countryCode: { in: EU_COUNTRIES },
                residenceStatus: { in: ["permanent", "temporary"] },
            },
            {
                expectedNonce,
                maxProofAge: 5 * 60 * 1000, // 5 minutes
            }
        );

        if (!result.valid) {
            return {
                success: false,
                message: `Verification failed: ${result.error}`,
            };
        }

        // Store verification (without any personal data)
        this.verifiedUsers.set(userId, {
            timestamp: result.timestamp!,
            region: "EU", // We only know they're in EU, not which country
        });

        return {
            success: true,
            message: "EU residency verified. You can now access DeFi services.",
        };
    }

    /**
     * Check if user is verified
     */
    isVerified(userId: string): boolean {
        const verification = this.verifiedUsers.get(userId);
        if (!verification) return false;

        // Verification valid for 30 days
        const thirtyDays = 30 * 24 * 60 * 60 * 1000;
        return Date.now() - verification.timestamp < thirtyDays;
    }
}

/**
 * User's Wallet
 */
class UserWallet {
    private credentials = new Map<string, CredentialHandle>();

    /**
     * Import EUDI credential
     */
    async importCredential(sdJwt: string, label: string): Promise<void> {
        const handle = await OpenAC.prepare({
            credential: sdJwt,
            deviceBinding: true,
            storageKey: label,
        });

        this.credentials.set(label, handle);
        console.log(`Imported credential: ${label}`);
        console.log("Claims available:", handle.getMetadata().availableClaims);
    }

    /**
     * Generate proof for KYC
     */
    async proveResidency(
        credentialLabel: string,
        challenge: { nonce: string; policy: Policy }
    ): Promise<ReturnType<typeof OpenAC.serializeProof>> {
        const handle = this.credentials.get(credentialLabel);
        if (!handle) {
            throw new Error(`Credential not found: ${credentialLabel}`);
        }

        const proof = await handle.show({
            policy: challenge.policy,
            nonce: challenge.nonce,
        });

        return OpenAC.serializeProof(proof);
    }
}

/**
 * Full KYC flow demonstration
 */
async function main() {
    console.log("=== EU Residency Proof for DeFi KYC ===\n");

    // Initialize services
    const kycService = new DeFiKYCService();
    const userWallet = new UserWallet();
    const userId = "user_" + crypto.randomUUID().slice(0, 8);

    // Step 1: User imports their EUDI credential
    console.log("Step 1: Importing EUDI credential...");
    await userWallet.importCredential(MOCK_EUDI_CREDENTIAL, "eudi-pid");

    // Step 2: User wants to access DeFi platform
    console.log("\nStep 2: User requests access to DeFi platform...");
    const challenge = kycService.generateChallenge();
    console.log("Challenge received:", {
        nonce: challenge.nonce.slice(0, 8) + "...",
        policy: challenge.policy,
    });

    // Step 3: User generates proof
    console.log("\nStep 3: Generating residency proof...");
    const proof = await userWallet.proveResidency("eudi-pid", challenge);
    console.log(
        "Proof generated (size:",
        JSON.stringify(proof).length,
        "bytes)"
    );

    // Step 4: Platform verifies and grants access
    console.log("\nStep 4: Platform verifying proof...");
    const result = await kycService.verifyAndGrant(
        userId,
        proof,
        challenge.nonce
    );
    console.log("Result:", result.message);

    // Step 5: User can now use the platform
    console.log("\nStep 5: Checking user status...");
    console.log("User verified:", kycService.isVerified(userId));

    // Privacy summary
    console.log("\n=== Privacy Summary ===");
    console.log("What the DeFi platform knows:");
    console.log("  - User is an EU resident");
    console.log("  - User has permanent or temporary residency");
    console.log("What the DeFi platform does NOT know:");
    console.log("  - Which EU country");
    console.log("  - User's name, address, or any PII");
    console.log("  - Ability to link this to other verifications");
}

main().catch(console.error);
