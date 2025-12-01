import { describe, it, expect } from "vitest";
import {
    serializeProof,
    deserializeProof,
    quickVerify,
} from "../src/prover/verify";
import type { Proof, Policy } from "../src/types";

describe("Proof Serialization", () => {
    const createMockProof = (): Proof => ({
        prepareProof: new Uint8Array([1, 2, 3, 4, 5]),
        showProof: new Uint8Array([6, 7, 8, 9, 10]),
        sharedCommitment: new Uint8Array([11, 12, 13]),
        policy: { age: { gte: 18 } },
        nonce: "test-nonce-123",
        timestamp: Date.now(),
        version: "1.0.0",
    });

    it("should serialize and deserialize proofs", () => {
        const original = createMockProof();
        const serialized = serializeProof(original);
        const deserialized = deserializeProof(serialized);

        expect(deserialized.prepareProof).toEqual(original.prepareProof);
        expect(deserialized.showProof).toEqual(original.showProof);
        expect(deserialized.sharedCommitment).toEqual(
            original.sharedCommitment
        );
        expect(deserialized.policy).toEqual(original.policy);
        expect(deserialized.nonce).toBe(original.nonce);
        expect(deserialized.timestamp).toBe(original.timestamp);
        expect(deserialized.version).toBe(original.version);
    });

    it("should produce JSON-safe serialized format", () => {
        const proof = createMockProof();
        const serialized = serializeProof(proof);

        expect(typeof serialized.prepareProof).toBe("string");
        expect(typeof serialized.showProof).toBe("string");
        expect(typeof serialized.sharedCommitment).toBe("string");

        // Should be valid JSON
        const json = JSON.stringify(serialized);
        const parsed = JSON.parse(json);
        expect(parsed).toEqual(serialized);
    });
});

describe("Quick Verify", () => {
    const createMockProof = (overrides: Partial<Proof> = {}): Proof => ({
        prepareProof: new Uint8Array([1, 2, 3]),
        showProof: new Uint8Array([4, 5, 6]),
        sharedCommitment: new Uint8Array([7, 8, 9]),
        policy: { age: { gte: 18 } },
        nonce: "test-nonce",
        timestamp: Date.now(),
        version: "1.0.0",
        ...overrides,
    });

    it("should pass valid proofs", () => {
        const proof = createMockProof();
        const result = quickVerify(proof);

        expect(result.valid).toBe(true);
        expect(result.error).toBeUndefined();
    });

    it("should reject expired proofs", () => {
        const proof = createMockProof({
            timestamp: Date.now() - 10 * 60 * 1000, // 10 minutes ago
        });

        const result = quickVerify(proof, { maxProofAge: 5 * 60 * 1000 });

        expect(result.valid).toBe(false);
        expect(result.error).toContain("expired");
    });

    it("should reject wrong nonce", () => {
        const proof = createMockProof({ nonce: "wrong-nonce" });

        const result = quickVerify(proof, { expectedNonce: "correct-nonce" });

        expect(result.valid).toBe(false);
        expect(result.error).toContain("Nonce");
    });

    it("should reject unsupported version", () => {
        const proof = createMockProof({ version: "2.0.0" });

        const result = quickVerify(proof);

        expect(result.valid).toBe(false);
        expect(result.error).toContain("version");
    });

    it("should validate policy match", () => {
        const proof = createMockProof({
            policy: { age: { gte: 18 } },
        });

        const matchResult = quickVerify(proof, {
            expectedPolicy: { age: { gte: 18 } },
        });
        expect(matchResult.valid).toBe(true);

        const mismatchResult = quickVerify(proof, {
            expectedPolicy: { age: { gte: 21 } },
        });
        expect(mismatchResult.valid).toBe(false);
        expect(mismatchResult.error).toContain("Policy");
    });

    it("should work with serialized proofs", () => {
        const proof = createMockProof();
        const serialized = serializeProof(proof);

        const result = quickVerify(serialized);

        expect(result.valid).toBe(true);
    });
});
