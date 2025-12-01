/**
 * WASM Module Loader
 * Handles loading the Spartan2 WASM prover across different environments
 */

import { WasmError } from "../errors";

/** WASM module interface matching the Rust exports */
export interface SpartanWasm {
    setup_prepare(r1csBytes: Uint8Array): { pk: Uint8Array; vk: Uint8Array };
    setup_show(r1csBytes: Uint8Array): { pk: Uint8Array; vk: Uint8Array };
    prove_prepare(pk: Uint8Array, witness: Uint8Array): ProveResult;
    prove_show(pk: Uint8Array, witness: Uint8Array): ProveResult;
    reblind(
        pk: Uint8Array,
        instance: Uint8Array,
        witness: Uint8Array,
        blinds: Uint8Array
    ): ProveResult;
    verify(proof: Uint8Array, vk: Uint8Array): boolean;
    generate_blinds(count: number): Uint8Array;
}

export interface ProveResult {
    proof: Uint8Array;
    instance: Uint8Array;
    witness: Uint8Array;
    sharedCommitment: Uint8Array;
}

let wasmModule: SpartanWasm | null = null;
let wasmLoadPromise: Promise<SpartanWasm> | null = null;

/**
 * Load the WASM module
 */
export async function loadWasm(wasmPath?: string): Promise<SpartanWasm> {
    if (wasmModule) return wasmModule;
    if (wasmLoadPromise) return wasmLoadPromise;

    wasmLoadPromise = doLoadWasm(wasmPath);
    wasmModule = await wasmLoadPromise;
    return wasmModule;
}

async function doLoadWasm(wasmPath?: string): Promise<SpartanWasm> {
    const path = wasmPath || getDefaultWasmPath();

    try {
        // Browser environment
        if (typeof window !== "undefined") {
            return await loadWasmBrowser(path);
        }

        // Node.js environment
        if (typeof process !== "undefined" && process.versions?.node) {
            return await loadWasmNode(path);
        }

        // React Native - use native module
        if (
            typeof navigator !== "undefined" &&
            navigator.product === "ReactNative"
        ) {
            return await loadWasmReactNative();
        }

        throw new WasmError("Unsupported environment for WASM loading");
    } catch (error) {
        throw new WasmError(
            `Failed to load WASM module from ${path}. Ensure the WASM file is accessible.`,
            error as Error
        );
    }
}

function getDefaultWasmPath(): string {
    // In browser, look for the WASM file relative to the script
    if (typeof window !== "undefined") {
        return "/wasm/spartan2_bg.wasm";
    }
    // In Node.js, use the package path
    return require.resolve("@l8zk/sdk/wasm/spartan2_bg.wasm");
}

async function loadWasmBrowser(path: string): Promise<SpartanWasm> {
    const response = await fetch(path);
    if (!response.ok) {
        throw new Error(`Failed to fetch WASM: ${response.status}`);
    }

    const wasmBytes = await response.arrayBuffer();
    const wasmModule = await WebAssembly.instantiate(wasmBytes, {
        env: {
            memory: new WebAssembly.Memory({ initial: 256, maximum: 16384 }),
        },
    });

    return wrapWasmExports(wasmModule.instance.exports);
}

async function loadWasmNode(path: string): Promise<SpartanWasm> {
    const fs = await import("fs");
    const wasmBytes = fs.readFileSync(path);
    const wasmModule = await WebAssembly.instantiate(wasmBytes, {
        env: {
            memory: new WebAssembly.Memory({ initial: 256, maximum: 16384 }),
        },
    });

    return wrapWasmExports(wasmModule.instance.exports);
}

async function loadWasmReactNative(): Promise<SpartanWasm> {
    // React Native requires a native module bridge
    // This would be implemented via react-native-wasm or a custom native module
    try {
        const nativeModule = require("../native").SpartanNative;
        return nativeModule;
    } catch {
        throw new WasmError(
            "React Native native module not found. Install @l8zk/sdk-native for React Native support."
        );
    }
}

/**
 * Wrap raw WASM exports into a typed interface
 */
function wrapWasmExports(exports: WebAssembly.Exports): SpartanWasm {
    // This is a simplified wrapper - actual implementation would need
    // proper memory management and data marshalling
    return {
        setup_prepare: (r1csBytes: Uint8Array) => {
            const fn = exports.setup_prepare as Function;
            return fn(r1csBytes);
        },
        setup_show: (r1csBytes: Uint8Array) => {
            const fn = exports.setup_show as Function;
            return fn(r1csBytes);
        },
        prove_prepare: (pk: Uint8Array, witness: Uint8Array) => {
            const fn = exports.prove_prepare as Function;
            return fn(pk, witness);
        },
        prove_show: (pk: Uint8Array, witness: Uint8Array) => {
            const fn = exports.prove_show as Function;
            return fn(pk, witness);
        },
        reblind: (
            pk: Uint8Array,
            instance: Uint8Array,
            witness: Uint8Array,
            blinds: Uint8Array
        ) => {
            const fn = exports.reblind as Function;
            return fn(pk, instance, witness, blinds);
        },
        verify: (proof: Uint8Array, vk: Uint8Array) => {
            const fn = exports.verify as Function;
            return fn(proof, vk);
        },
        generate_blinds: (count: number) => {
            const fn = exports.generate_blinds as Function;
            return fn(count);
        },
    };
}

/**
 * Check if WASM is loaded
 */
export function isWasmLoaded(): boolean {
    return wasmModule !== null;
}

/**
 * Get the loaded WASM module (throws if not loaded)
 */
export function getWasm(): SpartanWasm {
    if (!wasmModule) {
        throw new WasmError("WASM module not loaded. Call loadWasm() first.");
    }
    return wasmModule;
}
