/**
 * Integration tests for OpenAC SDK
 * Tests the full flow that can work without WASM prover
 */

import { describe, it, expect, beforeEach } from "vitest";
import { OpenAC } from "../src/openac";
import { MemoryAdapter } from "../src/storage/adapter";
import { parseSDJWT, extractMetadata } from "../src/credential/parser";
import { generateKeyPair, sign, verify } from "../src/utils/crypto";
import { base64UrlEncode } from "../src/utils/base64";
import {
    serializeProof,
    deserializeProof,
    quickVerify,
} from "../src/prover/verify";
import type { Proof, Policy } from "../src/types";

// Create a realistic SD-JWT for testing
function createTestSDJWT() {
    const { privateKey, publicKey } = generateKeyPair();

    const header = { alg: "ES256", typ: "vc+sd-jwt" };
    const payload = {
        iss: "https://gov.example.com",
        sub: "did:example:user123",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 86400 * 365,
        cnf: {
            jwk: publicKey,
        },
        _sd: [],
    };

    const headerB64 = base64UrlEncode(
        new TextEncoder().encode(JSON.stringify(header))
    );
    const payloadB64 = base64UrlEncode(
        new TextEncoder().encode(JSON.stringify(payload))
    );

    // Sign the JWT
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = sign(signingInput, privateKey);
    const signatureB64 = base64UrlEncode(signature);

    // Create disclosures
    const birthdayDisclosure = base64UrlEncode(
        new TextEncoder().encode(
            JSON.stringify(["salt123", "roc_birthday", "1040605"])
        )
    );
    const nationalityDisclosure = base64UrlEncode(
        new TextEncoder().encode(
            JSON.stringify(["salt456", "nationality", "DE"])
        )
    );

    return {
        sdJwt: `${headerB64}.${payloadB64}.${signatureB64}~${birthdayDisclosure}~${nationalityDisclosure}`,
        privateKey,
        publicKey,
    };
}

describe("SD-JWT Parsing Integration", () => {
    it("should parse a complete SD-JWT with real signatures", () => {
        const { sdJwt, publicKey } = createTestSDJWT();
        const parsed = parseSDJWT(sdJwt);

        expect(parsed.header.alg).toBe("ES256");
        expect(parsed.payload.iss).toBe("https://gov.example.com");
        expect(parsed.payload.cnf?.jwk?.x).toBe(publicKey.x);
        expect(parsed.payload.cnf?.jwk?.y).toBe(publicKey.y);
        expect(parsed.disclosures).toHaveLength(2);
    });

    it("should extract correct metadata", () => {
        const { sdJwt } = createTestSDJWT();
        const parsed = parseSDJWT(sdJwt);
        const metadata = extractMetadata(parsed);

        expect(metadata.format).toBe("sd-jwt");
        expect(metadata.issuer).toBe("https://gov.example.com");
        expect(metadata.deviceBound).toBe(true);
        expect(metadata.availableClaims).toContain("roc_birthday");
        expect(metadata.availableClaims).toContain("nationality");
    });

    it("should verify the JWT signature is valid", () => {
        const { sdJwt, publicKey } = createTestSDJWT();
        const parsed = parseSDJWT(sdJwt);

        // Reconstruct signing input
        const signingInput = `${parsed.rawHeader}.${parsed.rawPayload}`;

        // Verify signature
        const isValid = verify(signingInput, parsed.signature, publicKey);
        expect(isValid).toBe(true);
    });
});

describe("Proof Serialization Integration", () => {
    const createMockProof = (): Proof => ({
        prepareProof: new Uint8Array(Array.from({ length: 100 }, (_, i) => i)),
        showProof: new Uint8Array(Array.from({ length: 50 }, (_, i) => i * 2)),
        sharedCommitment: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        policy: { age: { gte: 18 }, nationality: { nin: ["KP", "IR"] } },
        nonce: "verifier-nonce-" + Date.now(),
        timestamp: Date.now(),
        version: "1.0.0",
    });

    it("should serialize and deserialize complex proofs", () => {
        const original = createMockProof();
        const serialized = serializeProof(original);

        // Verify it's JSON-safe
        const jsonString = JSON.stringify(serialized);
        const fromJson = JSON.parse(jsonString);

        const deserialized = deserializeProof(fromJson);

        expect(deserialized.prepareProof).toEqual(original.prepareProof);
        expect(deserialized.showProof).toEqual(original.showProof);
        expect(deserialized.sharedCommitment).toEqual(
            original.sharedCommitment
        );
        expect(deserialized.policy).toEqual(original.policy);
        expect(deserialized.nonce).toBe(original.nonce);
    });

    it("should pass quick verification for valid proofs", () => {
        const proof = createMockProof();
        const result = quickVerify(proof, {
            expectedNonce: proof.nonce,
            expectedPolicy: proof.policy,
        });

        expect(result.valid).toBe(true);
    });

    it("should fail quick verification for expired proofs", () => {
        const proof = createMockProof();
        proof.timestamp = Date.now() - 10 * 60 * 1000; // 10 minutes ago

        const result = quickVerify(proof, {
            maxProofAge: 5 * 60 * 1000, // 5 minutes
        });

        expect(result.valid).toBe(false);
        expect(result.error).toContain("expired");
    });

    it("should fail quick verification for wrong nonce", () => {
        const proof = createMockProof();
        const result = quickVerify(proof, {
            expectedNonce: "wrong-nonce",
        });

        expect(result.valid).toBe(false);
        expect(result.error).toContain("Nonce");
    });
});

describe("Storage Integration", () => {
    it("should persist and retrieve data correctly", async () => {
        const storage = new MemoryAdapter();

        const testData = {
            id: "cred-123",
            claims: ["age", "nationality"],
            timestamp: Date.now(),
        };

        const serialized = new TextEncoder().encode(JSON.stringify(testData));
        await storage.set("test-key", serialized);

        const retrieved = await storage.get("test-key");
        expect(retrieved).not.toBeNull();

        const parsed = JSON.parse(new TextDecoder().decode(retrieved!));
        expect(parsed).toEqual(testData);
    });

    it("should list all stored keys", async () => {
        const storage = new MemoryAdapter();

        await storage.set("cred:1", new Uint8Array([1]));
        await storage.set("cred:2", new Uint8Array([2]));
        await storage.set("cred:3", new Uint8Array([3]));

        const keys = await storage.keys();
        expect(keys).toHaveLength(3);
        expect(keys).toContain("cred:1");
        expect(keys).toContain("cred:2");
        expect(keys).toContain("cred:3");
    });
});

describe("Crypto Integration", () => {
    it("should generate unique key pairs", () => {
        const pairs = Array.from({ length: 5 }, () => generateKeyPair());

        // All private keys should be unique
        const privateKeyStrings = pairs.map((p) =>
            Array.from(p.privateKey).join(",")
        );
        const uniquePrivateKeys = new Set(privateKeyStrings);
        expect(uniquePrivateKeys.size).toBe(5);

        // All public keys should be unique
        const publicKeyStrings = pairs.map(
            (p) => p.publicKey.x + p.publicKey.y
        );
        const uniquePublicKeys = new Set(publicKeyStrings);
        expect(uniquePublicKeys.size).toBe(5);
    });

    it("should sign and verify multiple messages", () => {
        const { privateKey, publicKey } = generateKeyPair();
        const messages = [
            "Hello, World!",
            "Test message 123",
            "Another test with special chars: @#$%",
            "Unicode: ",
            "",
        ];

        for (const message of messages) {
            const signature = sign(message, privateKey);
            expect(verify(message, signature, publicKey)).toBe(true);
            expect(verify(message + "x", signature, publicKey)).toBe(false);
        }
    });

    it("should produce deterministic signatures (RFC 6979)", () => {
        const { privateKey } = generateKeyPair();
        const message = "test message";

        // @noble/curves uses RFC 6979 deterministic signatures
        // Same message + same key = same signature (more secure, no k reuse attacks)
        const sig1 = sign(message, privateKey);
        const sig2 = sign(message, privateKey);

        expect(Array.from(sig1).join(",")).toBe(Array.from(sig2).join(","));
    });
});

describe("Policy Validation", () => {
    it("should validate age predicates", () => {
        const policy: Policy = {
            age: { gte: 18, lt: 100 },
        };

        const proof: Proof = {
            prepareProof: new Uint8Array([1]),
            showProof: new Uint8Array([2]),
            sharedCommitment: new Uint8Array([3]),
            policy,
            nonce: "test",
            timestamp: Date.now(),
            version: "1.0.0",
        };

        const result = quickVerify(proof, { expectedPolicy: policy });
        expect(result.valid).toBe(true);
    });

    it("should validate set membership predicates", () => {
        const policy: Policy = {
            nationality: { in: ["DE", "FR", "IT"] },
            countryCode: { nin: ["KP", "IR", "SY"] },
        };

        const proof: Proof = {
            prepareProof: new Uint8Array([1]),
            showProof: new Uint8Array([2]),
            sharedCommitment: new Uint8Array([3]),
            policy,
            nonce: "test",
            timestamp: Date.now(),
            version: "1.0.0",
        };

        const result = quickVerify(proof, { expectedPolicy: policy });
        expect(result.valid).toBe(true);
    });

    it("should reject mismatched policies", () => {
        const proofPolicy: Policy = { age: { gte: 18 } };
        const expectedPolicy: Policy = { age: { gte: 21 } };

        const proof: Proof = {
            prepareProof: new Uint8Array([1]),
            showProof: new Uint8Array([2]),
            sharedCommitment: new Uint8Array([3]),
            policy: proofPolicy,
            nonce: "test",
            timestamp: Date.now(),
            version: "1.0.0",
        };

        const result = quickVerify(proof, { expectedPolicy });
        expect(result.valid).toBe(false);
        expect(result.error).toContain("Policy");
    });
});
