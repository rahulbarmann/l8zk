/**
 * Native Prover Integration Tests
 * Tests real ZK proof generation using the Rust binary
 */

import { describe, it, expect, beforeAll } from "vitest";
import { resolve } from "path";
import {
    isNativeAvailable,
    initNativeBackend,
    nativeSetupPrepare,
    nativeSetupShow,
    nativeGenerateBlinds,
    nativeProvePrepare,
    nativeProveShow,
    nativeReblind,
    nativeVerify,
} from "../src/prover/native-backend";

// Skip tests if native backend not available
const runNativeTests = isNativeAvailable();

describe.skipIf(!runNativeTests)("Native Prover", () => {
    beforeAll(() => {
        const status = initNativeBackend();
        console.log("Native backend status:", status);
    });

    it("should setup prepare circuit keys", async () => {
        const result = await nativeSetupPrepare();
        expect(result.pkPath).toContain("prepare_proving.key");
        expect(result.vkPath).toContain("prepare_verifying.key");
    }, 120000); // 2 min timeout for setup

    it("should setup show circuit keys", async () => {
        const result = await nativeSetupShow();
        expect(result.pkPath).toContain("show_proving.key");
        expect(result.vkPath).toContain("show_verifying.key");
    }, 30000);

    it("should generate shared blinds", async () => {
        const result = await nativeGenerateBlinds();
        expect(result).toContain("shared_blinds");
    });

    it("should prove prepare circuit", async () => {
        const result = await nativeProvePrepare();
        expect(result.proofPath).toContain("prepare_proof");
        expect(result.instancePath).toContain("prepare_instance");
        expect(result.witnessPath).toContain("prepare_witness");
    }, 60000);

    it("should reblind prepare proof", async () => {
        const result = await nativeReblind("prepare");
        expect(result.proofPath).toContain("prepare_proof");
    }, 30000);

    it("should verify prepare proof", async () => {
        const result = await nativeVerify("prepare");
        expect(result).toBe(true);
    }, 30000);

    it("should prove show circuit", async () => {
        const result = await nativeProveShow();
        expect(result.proofPath).toContain("show_proof");
    }, 30000);

    it("should verify show proof", async () => {
        const result = await nativeVerify("show");
        expect(result).toBe(true);
    }, 30000);
});

describe.skipIf(!runNativeTests)("Native Prover Full Flow", () => {
    it("should complete full prepare -> show -> verify flow", async () => {
        // 1. Setup (if not already done)
        console.log("Setting up prepare circuit...");
        await nativeSetupPrepare();

        console.log("Setting up show circuit...");
        await nativeSetupShow();

        // 2. Generate blinds
        console.log("Generating shared blinds...");
        await nativeGenerateBlinds();

        // 3. Prove prepare
        console.log("Proving prepare circuit...");
        const prepareResult = await nativeProvePrepare();
        expect(prepareResult.proofPath).toBeDefined();

        // 4. Reblind prepare
        console.log("Reblinding prepare proof...");
        await nativeReblind("prepare");

        // 5. Verify prepare
        console.log("Verifying prepare proof...");
        const prepareValid = await nativeVerify("prepare");
        expect(prepareValid).toBe(true);

        // 6. Prove show
        console.log("Proving show circuit...");
        const showResult = await nativeProveShow();
        expect(showResult.proofPath).toBeDefined();

        // 7. Verify show
        console.log("Verifying show proof...");
        const showValid = await nativeVerify("show");
        expect(showValid).toBe(true);

        console.log("Full flow completed successfully!");
    }, 300000); // 5 min timeout for full flow
});
