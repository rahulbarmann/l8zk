/**
 * End-to-end SDK test
 * Tests all components that work without the WASM prover
 */

import { describe, it, expect } from "vitest";
import {
    parseSDJWT,
    extractMetadata,
    extractClaimsForCircuit,
} from "../src/credential/parser";
import { generateKeyPair, sign, verify } from "../src/utils/crypto";
import { base64UrlEncode } from "../src/utils/base64";
import { MemoryAdapter } from "../src/storage/adapter";
import {
    serializeProof,
    deserializeProof,
    quickVerify,
} from "../src/prover/verify";
import type { Proof, Policy, CircuitParams } from "../src/types";

const CIRCUIT_PARAMS: CircuitParams = {
    maxMessageLength: 1920,
    maxB64PayloadLength: 1900,
    maxMatches: 4,
    maxSubstringLength: 50,
    maxClaimsLength: 128,
};

function createRealSDJWT() {
    const issuerKeys = generateKeyPair();
    const deviceKeys = generateKeyPair();

    const header = { alg: "ES256", typ: "vc+sd-jwt" };
    const payload = {
        iss: "https://gov.example.com",
        sub: "did:example:user123",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 86400 * 365,
        cnf: { jwk: deviceKeys.publicKey },
        _sd: [],
    };

    const headerB64 = base64UrlEncode(
        new TextEncoder().encode(JSON.stringify(header))
    );
    const payloadB64 = base64UrlEncode(
        new TextEncoder().encode(JSON.stringify(payload))
    );
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = sign(signingInput, issuerKeys.privateKey);
    const signatureB64 = base64UrlEncode(signature);

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

    const sdJwt = `${headerB64}.${payloadB64}.${signatureB64}~${birthdayDisclosure}~${nationalityDisclosure}`;

    return { sdJwt, issuerKeys, deviceKeys, signingInput };
}

describe("E2E: Full SDK Flow", () => {
    it("should complete full credential lifecycle", async () => {
        // Step 1: Create credential
        const { sdJwt, issuerKeys, deviceKeys, signingInput } =
            createRealSDJWT();
        expect(sdJwt.length).toBeGreaterThan(100);

        // Step 2: Parse credential
        const parsed = parseSDJWT(sdJwt);
        expect(parsed.header.alg).toBe("ES256");
        expect(parsed.payload.iss).toBe("https://gov.example.com");
        expect(parsed.disclosures).toHaveLength(2);

        // Step 3: Verify issuer signature
        const sigValid = verify(
            signingInput,
            parsed.signature,
            issuerKeys.publicKey
        );
        expect(sigValid).toBe(true);

        // Step 4: Extract metadata
        const metadata = extractMetadata(parsed);
        expect(metadata.format).toBe("sd-jwt");
        expect(metadata.deviceBound).toBe(true);
        expect(metadata.availableClaims).toContain("roc_birthday");

        // Step 5: Extract circuit inputs
        const claims = extractClaimsForCircuit(parsed, CIRCUIT_PARAMS);
        expect(claims.keyBindingX).toBeGreaterThan(0n);
        expect(claims.keyBindingY).toBeGreaterThan(0n);

        // Step 6: Store credential
        const storage = new MemoryAdapter();
        const credData = new TextEncoder().encode(
            JSON.stringify({ id: "cred-1", sdJwt })
        );
        await storage.set("cred:1", credData);
        const retrieved = await storage.get("cred:1");
        expect(retrieved).not.toBeNull();

        // Step 7: Device binding
        const nonce = "verifier-nonce-" + Date.now();
        const deviceSig = sign(nonce, deviceKeys.privateKey);
        const deviceSigValid = verify(nonce, deviceSig, deviceKeys.publicKey);
        expect(deviceSigValid).toBe(true);

        // Step 8: Create and serialize proof
        const proof: Proof = {
            prepareProof: new Uint8Array(100).fill(1),
            showProof: new Uint8Array(50).fill(2),
            sharedCommitment: new Uint8Array(8).fill(3),
            policy: { age: { gte: 18 } },
            nonce,
            timestamp: Date.now(),
            version: "1.0.0",
        };

        const serialized = serializeProof(proof);
        const json = JSON.stringify(serialized);
        const fromJson = JSON.parse(json);
        const deserialized = deserializeProof(fromJson);

        expect(deserialized.nonce).toBe(proof.nonce);
        expect(deserialized.prepareProof).toEqual(proof.prepareProof);

        // Step 9: Quick verify
        const verifyResult = quickVerify(proof, {
            expectedNonce: nonce,
            expectedPolicy: { age: { gte: 18 } },
        });
        expect(verifyResult.valid).toBe(true);
    });

    it("should reject tampered credentials", () => {
        const { sdJwt, issuerKeys } = createRealSDJWT();
        const parsed = parseSDJWT(sdJwt);

        // Tamper with the payload
        const tamperedInput = `${parsed.rawHeader}.tampered`;
        const sigValid = verify(
            tamperedInput,
            parsed.signature,
            issuerKeys.publicKey
        );
        expect(sigValid).toBe(false);
    });

    it("should reject wrong issuer key", () => {
        const { signingInput } = createRealSDJWT();
        const wrongKeys = generateKeyPair();
        const { sdJwt } = createRealSDJWT();
        const parsed = parseSDJWT(sdJwt);

        const sigValid = verify(
            signingInput,
            parsed.signature,
            wrongKeys.publicKey
        );
        expect(sigValid).toBe(false);
    });

    it("should handle multiple credentials", async () => {
        const storage = new MemoryAdapter();

        // Store multiple credentials
        for (let i = 0; i < 5; i++) {
            const { sdJwt } = createRealSDJWT();
            const data = new TextEncoder().encode(
                JSON.stringify({ id: `cred-${i}`, sdJwt })
            );
            await storage.set(`cred:${i}`, data);
        }

        const keys = await storage.keys();
        expect(keys).toHaveLength(5);

        // Retrieve and verify each
        for (let i = 0; i < 5; i++) {
            const data = await storage.get(`cred:${i}`);
            expect(data).not.toBeNull();
            const parsed = JSON.parse(new TextDecoder().decode(data!));
            expect(parsed.id).toBe(`cred-${i}`);
        }
    });

    it("should enforce proof expiry", () => {
        const proof: Proof = {
            prepareProof: new Uint8Array([1]),
            showProof: new Uint8Array([2]),
            sharedCommitment: new Uint8Array([3]),
            policy: { age: { gte: 18 } },
            nonce: "test",
            timestamp: Date.now() - 10 * 60 * 1000, // 10 min ago
            version: "1.0.0",
        };

        const result = quickVerify(proof, { maxProofAge: 5 * 60 * 1000 });
        expect(result.valid).toBe(false);
        expect(result.error).toContain("expired");
    });

    it("should enforce nonce matching", () => {
        const proof: Proof = {
            prepareProof: new Uint8Array([1]),
            showProof: new Uint8Array([2]),
            sharedCommitment: new Uint8Array([3]),
            policy: { age: { gte: 18 } },
            nonce: "correct-nonce",
            timestamp: Date.now(),
            version: "1.0.0",
        };

        const wrongNonce = quickVerify(proof, { expectedNonce: "wrong-nonce" });
        expect(wrongNonce.valid).toBe(false);

        const correctNonce = quickVerify(proof, {
            expectedNonce: "correct-nonce",
        });
        expect(correctNonce.valid).toBe(true);
    });

    it("should enforce policy matching", () => {
        const proof: Proof = {
            prepareProof: new Uint8Array([1]),
            showProof: new Uint8Array([2]),
            sharedCommitment: new Uint8Array([3]),
            policy: { age: { gte: 18 }, nationality: { nin: ["KP"] } },
            nonce: "test",
            timestamp: Date.now(),
            version: "1.0.0",
        };

        const exactMatch = quickVerify(proof, {
            expectedPolicy: { age: { gte: 18 }, nationality: { nin: ["KP"] } },
        });
        expect(exactMatch.valid).toBe(true);

        const wrongAge = quickVerify(proof, {
            expectedPolicy: { age: { gte: 21 } },
        });
        expect(wrongAge.valid).toBe(false);
    });
});
