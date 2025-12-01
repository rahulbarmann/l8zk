import { describe, it, expect } from "vitest";
import { parseSDJWT, extractMetadata } from "../src/credential/parser";
import {
    base64UrlEncode,
    base64Encode,
    base64Decode,
    base64UrlDecode,
} from "../src/utils/base64";
import { generateKeyPair, sign, verify } from "../src/utils/crypto";

describe("SD-JWT Parser", () => {
    const createMockSDJWT = () => {
        const header = { alg: "ES256", typ: "vc+sd-jwt" };
        const payload = {
            iss: "https://issuer.example.com",
            sub: "did:example:123",
            iat: 1700000000,
            exp: 1800000000,
            cnf: {
                jwk: {
                    kty: "EC",
                    crv: "P-256",
                    x: "WbbXwVQpPRCPqxmJvnuVJGC9dz8k9YvKfJYcGxTaSyE",
                    y: "caS-VMfTSfrcqXDLtmNxhqM9Hd_VRkgg_EqNvb7GKSA",
                },
            },
            _sd: ["hash1", "hash2"],
        };

        const headerB64 = base64UrlEncode(
            new TextEncoder().encode(JSON.stringify(header))
        );
        const payloadB64 = base64UrlEncode(
            new TextEncoder().encode(JSON.stringify(payload))
        );
        const signature = "mock_signature_base64url";

        const disclosure1 = base64UrlEncode(
            new TextEncoder().encode(
                JSON.stringify(["salt1", "roc_birthday", "1040605"])
            )
        );
        const disclosure2 = base64UrlEncode(
            new TextEncoder().encode(
                JSON.stringify(["salt2", "nationality", "DE"])
            )
        );

        return `${headerB64}.${payloadB64}.${signature}~${disclosure1}~${disclosure2}`;
    };

    it("should parse a valid SD-JWT", () => {
        const sdJwt = createMockSDJWT();
        const parsed = parseSDJWT(sdJwt);

        expect(parsed.header.alg).toBe("ES256");
        expect(parsed.payload.iss).toBe("https://issuer.example.com");
        expect(parsed.disclosures).toHaveLength(2);
        expect(parsed.disclosures[0].claimName).toBe("roc_birthday");
        expect(parsed.disclosures[1].claimName).toBe("nationality");
    });

    it("should extract metadata from parsed SD-JWT", () => {
        const sdJwt = createMockSDJWT();
        const parsed = parseSDJWT(sdJwt);
        const metadata = extractMetadata(parsed);

        expect(metadata.format).toBe("sd-jwt");
        expect(metadata.issuer).toBe("https://issuer.example.com");
        expect(metadata.deviceBound).toBe(true);
        expect(metadata.availableClaims).toContain("roc_birthday");
        expect(metadata.availableClaims).toContain("nationality");
    });

    it("should throw on invalid JWT format", () => {
        expect(() => parseSDJWT("invalid")).toThrow("Invalid SD-JWT format");
        expect(() => parseSDJWT("a.b")).toThrow("Invalid SD-JWT format");
    });

    it("should throw on unsupported algorithm", () => {
        const header = { alg: "RS256", typ: "jwt" };
        const payload = { iss: "test" };
        const headerB64 = base64UrlEncode(
            new TextEncoder().encode(JSON.stringify(header))
        );
        const payloadB64 = base64UrlEncode(
            new TextEncoder().encode(JSON.stringify(payload))
        );

        expect(() => parseSDJWT(`${headerB64}.${payloadB64}.sig`)).toThrow(
            "Unsupported algorithm"
        );
    });
});

describe("Base64 Utils", () => {
    it("should encode and decode correctly", () => {
        const original = new Uint8Array([1, 2, 3, 4, 5]);
        const encoded = base64Encode(original);
        const decoded = base64Decode(encoded);

        expect(decoded).toEqual(original);
    });

    it("should handle base64url encoding", () => {
        const original = new Uint8Array([255, 254, 253]);
        const encoded = base64UrlEncode(original);

        expect(encoded).not.toContain("+");
        expect(encoded).not.toContain("/");
        expect(encoded).not.toContain("=");

        const decoded = base64UrlDecode(encoded);
        expect(decoded).toEqual(original);
    });
});

describe("Crypto Utils", () => {
    it("should generate valid key pairs", () => {
        const { privateKey, publicKey } = generateKeyPair();

        expect(privateKey).toBeInstanceOf(Uint8Array);
        expect(privateKey.length).toBe(32);
        expect(publicKey.kty).toBe("EC");
        expect(publicKey.crv).toBe("P-256");
        expect(publicKey.x).toBeDefined();
        expect(publicKey.y).toBeDefined();
    });

    it("should sign and verify messages", () => {
        const { privateKey, publicKey } = generateKeyPair();
        const message = "test message";

        const signature = sign(message, privateKey);
        const isValid = verify(message, signature, publicKey);

        expect(isValid).toBe(true);
    });

    it("should reject invalid signatures", () => {
        const { privateKey, publicKey } = generateKeyPair();
        const { publicKey: otherPublicKey } = generateKeyPair();

        const signature = sign("message", privateKey);

        expect(verify("message", signature, publicKey)).toBe(true);
        expect(verify("different", signature, publicKey)).toBe(false);
        expect(verify("message", signature, otherPublicKey)).toBe(false);
    });
});
