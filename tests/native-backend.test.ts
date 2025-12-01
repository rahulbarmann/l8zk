/**
 * Native Backend Tests
 * Tests the Node.js native backend functionality
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
    isNodeJS,
    isNativeAvailable,
    initNativeBackend,
} from "../src/prover/native-backend";
import {
    initBackend,
    getBackendType,
    getBackendStatus,
    resetBackend,
} from "../src/prover/backend";

describe("Native Backend Detection", () => {
    it("should detect Node.js environment", () => {
        expect(isNodeJS()).toBe(true);
    });

    it("should check native availability", () => {
        const available = isNativeAvailable();
        // Will be false unless binary is built
        expect(typeof available).toBe("boolean");
    });

    it("should initialize and return status", () => {
        const result = initNativeBackend();
        expect(result).toHaveProperty("available");
        expect(result).toHaveProperty("binaryPath");
        expect(result).toHaveProperty("circomPath");
    });
});

describe("Backend Selection", () => {
    beforeEach(() => {
        resetBackend();
    });

    it("should report backend status", () => {
        const status = getBackendStatus();
        expect(status).toHaveProperty("selected");
        expect(status).toHaveProperty("nativeAvailable");
        expect(status).toHaveProperty("wasmLoaded");
        expect(status).toHaveProperty("isNode");
        expect(status.isNode).toBe(true);
    });

    it("should initialize backend", async () => {
        const backend = await initBackend();
        // Will be "none" if neither native nor WASM available
        expect(["native", "wasm", "none"]).toContain(backend);
    });

    it("should return consistent backend type", async () => {
        await initBackend();
        const type1 = getBackendType();
        const type2 = getBackendType();
        expect(type1).toBe(type2);
    });

    it("should reset backend selection", async () => {
        await initBackend();
        resetBackend();
        expect(getBackendType()).toBe("none");
    });
});

describe("Native Backend Integration", () => {
    it("should provide clear error when binary not available", async () => {
        const result = initNativeBackend();

        if (!result.available) {
            // Expected when binary not built
            expect(result.binaryPath).toBeNull();
        } else {
            // Binary is available
            expect(result.binaryPath).not.toBeNull();
        }
    });

    it("should find circom directory if present", () => {
        const result = initNativeBackend();
        // circomPath may or may not be found depending on workspace structure
        expect(result).toHaveProperty("circomPath");
    });
});
