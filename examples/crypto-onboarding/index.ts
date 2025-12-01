/**
 * Example 3: Crypto Onboarding
 * Verify user is 18+ AND not on sanctions list for crypto exchange onboarding
 */

import {
    OpenAC,
    type Policy,
    type CredentialHandle,
    type SerializedProof,
} from "@l8zk/sdk";

// Sanctioned countries (OFAC example list)
const SANCTIONED_COUNTRIES = ["KP", "IR", "SY", "CU", "RU"];

// Mock credential with age and nationality
const MOCK_CREDENTIAL = `eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwic3ViIjoiZGlkOmV4YW1wbGU6MTIzIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE4MDAwMDAwMDAsImNuZiI6eyJqd3QiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIuLi4iLCJ5IjoiLi4uIn19LCJfc2QiOlsiLi4uIl19.sig~WyJzMSIsInJvY19iaXJ0aGRheSIsIjEwNDA2MDUiXQ~WyJzMiIsIm5hdGlvbmFsaXR5IiwiREUiXQ`;

/**
 * Crypto Exchange Compliance Service
 */
class ComplianceService {
    /**
     * Generate onboarding challenge
     */
    createOnboardingChallenge(): {
        challengeId: string;
        nonce: string;
        policy: Policy;
        expiresAt: number;
    } {
        const challengeId = crypto.randomUUID();
        return {
            challengeId,
            nonce: crypto.randomUUID(),
            policy: {
                age: { gte: 18 },
                nationality: { nin: SANCTIONED_COUNTRIES },
            },
            expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
        };
    }

    /**
     * Verify onboarding proof
     */
    async verifyOnboarding(
        proof: SerializedProof,
        challenge: ReturnType<typeof this.createOnboardingChallenge>
    ): Promise<{
        approved: boolean;
        reason?: string;
        complianceToken?: string;
    }> {
        // Check challenge expiry
        if (Date.now() > challenge.expiresAt) {
            return { approved: false, reason: "Challenge expired" };
        }

        // Quick validation first
        const quickCheck = OpenAC.quickVerify(proof, {
            expectedNonce: challenge.nonce,
            expectedPolicy: challenge.policy,
        });

        if (!quickCheck.valid) {
            return { approved: false, reason: quickCheck.error };
        }

        // Full cryptographic verification
        const result = await OpenAC.verify(proof, challenge.policy, {
            expectedNonce: challenge.nonce,
            maxProofAge: 10 * 60 * 1000,
        });

        if (!result.valid) {
            return { approved: false, reason: result.error };
        }

        // Generate compliance token (no PII stored)
        const complianceToken = this.generateComplianceToken(
            challenge.challengeId
        );

        return {
            approved: true,
            complianceToken,
        };
    }

    private generateComplianceToken(challengeId: string): string {
        // In production, this would be a signed JWT
        return Buffer.from(
            JSON.stringify({
                type: "compliance_verified",
                challengeId,
                verifiedAt: Date.now(),
                checks: ["age_18_plus", "not_sanctioned"],
            })
        ).toString("base64url");
    }
}

/**
 * Mobile Wallet App
 */
class MobileWallet {
    private handle: CredentialHandle | null = null;

    async setup(credential: string): Promise<void> {
        this.handle = await OpenAC.prepare({
            credential,
            deviceBinding: true,
        });
    }

    async generateComplianceProof(
        nonce: string,
        policy: Policy
    ): Promise<SerializedProof> {
        if (!this.handle) {
            throw new Error("Wallet not initialized");
        }

        const proof = await this.handle.show({ policy, nonce });
        return OpenAC.serializeProof(proof);
    }

    getCredentialInfo(): { issuer: string; claims: string[] } | null {
        if (!this.handle) return null;
        const meta = this.handle.getMetadata();
        return {
            issuer: meta.issuer,
            claims: meta.availableClaims,
        };
    }
}

/**
 * Onboarding flow
 */
async function main() {
    console.log("=== Crypto Exchange Onboarding ===\n");

    const compliance = new ComplianceService();
    const wallet = new MobileWallet();

    // User sets up wallet with their ID credential
    console.log("Setting up wallet...");
    await wallet.setup(MOCK_CREDENTIAL);
    console.log("Credential loaded:", wallet.getCredentialInfo());

    // User starts onboarding
    console.log("\nStarting onboarding flow...");
    const challenge = compliance.createOnboardingChallenge();
    console.log("Challenge:", {
        id: challenge.challengeId.slice(0, 8) + "...",
        policy: challenge.policy,
    });

    // User generates proof
    console.log("\nGenerating compliance proof...");
    const proof = await wallet.generateComplianceProof(
        challenge.nonce,
        challenge.policy
    );

    // Exchange verifies
    console.log("\nVerifying compliance...");
    const result = await compliance.verifyOnboarding(proof, challenge);

    if (result.approved) {
        console.log("Onboarding approved");
        console.log(
            "Compliance token:",
            result.complianceToken?.slice(0, 20) + "..."
        );
    } else {
        console.log("Onboarding denied:", result.reason);
    }

    // What was proven vs what remains private
    console.log("\n=== Compliance Summary ===");
    console.log("Verified:");
    console.log("  - User is 18 or older");
    console.log("  - User is not from a sanctioned country");
    console.log("Private:");
    console.log("  - Exact age/birthdate");
    console.log("  - Actual nationality");
    console.log("  - Name, address, ID number");
}

main().catch(console.error);
