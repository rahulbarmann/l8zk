/**
 * Native Module Interface for React Native
 * This module provides the bridge to native Spartan prover implementations
 *
 * For React Native support, install @l8zk/sdk-native which provides
 * native implementations for iOS (Swift) and Android (Kotlin/Rust)
 */

import type { SpartanWasm, ProveResult } from "../prover/wasm-loader";
import { WasmError } from "../errors";

/**
 * Native Spartan module interface
 * Implemented by @l8zk/sdk-native package
 */
export interface SpartanNativeModule {
    setupPrepare(r1csBytes: number[]): Promise<{ pk: number[]; vk: number[] }>;
    setupShow(r1csBytes: number[]): Promise<{ pk: number[]; vk: number[] }>;
    provePrepare(pk: number[], witness: number[]): Promise<NativeProveResult>;
    proveShow(pk: number[], witness: number[]): Promise<NativeProveResult>;
    reblind(
        pk: number[],
        instance: number[],
        witness: number[],
        blinds: number[]
    ): Promise<NativeProveResult>;
    verify(proof: number[], vk: number[]): Promise<boolean>;
    generateBlinds(count: number): Promise<number[]>;
}

interface NativeProveResult {
    proof: number[];
    instance: number[];
    witness: number[];
    sharedCommitment: number[];
}

let nativeModule: SpartanNativeModule | null = null;

/**
 * Load the native module
 */
export function loadNativeModule(): SpartanNativeModule {
    if (nativeModule) return nativeModule;

    try {
        // Try to load from react-native NativeModules
        const { NativeModules } = require("react-native");

        if (!NativeModules.SpartanModule) {
            throw new Error("SpartanModule not found");
        }

        nativeModule = NativeModules.SpartanModule as SpartanNativeModule;
        return nativeModule;
    } catch (error) {
        throw new WasmError(
            "Native Spartan module not available. Install @l8zk/sdk-native for React Native support.",
            error as Error
        );
    }
}

/**
 * Wrap native module as SpartanWasm interface
 */
export function createNativeWasmAdapter(): SpartanWasm {
    const native = loadNativeModule();

    const toUint8Array = (arr: number[]): Uint8Array => new Uint8Array(arr);
    const fromUint8Array = (arr: Uint8Array): number[] => Array.from(arr);

    return {
        setup_prepare: (r1csBytes: Uint8Array) => {
            // Native setup is async, but we need sync interface
            // This is handled by pre-loading keys
            throw new WasmError("Use async native setup methods directly");
        },

        setup_show: (r1csBytes: Uint8Array) => {
            throw new WasmError("Use async native setup methods directly");
        },

        prove_prepare: (pk: Uint8Array, witness: Uint8Array): ProveResult => {
            // Sync wrapper - actual implementation uses async
            throw new WasmError("Use async native prove methods");
        },

        prove_show: (pk: Uint8Array, witness: Uint8Array): ProveResult => {
            throw new WasmError("Use async native prove methods");
        },

        reblind: (
            pk: Uint8Array,
            instance: Uint8Array,
            witness: Uint8Array,
            blinds: Uint8Array
        ): ProveResult => {
            throw new WasmError("Use async native reblind method");
        },

        verify: (proof: Uint8Array, vk: Uint8Array): boolean => {
            throw new WasmError("Use async native verify method");
        },

        generate_blinds: (count: number): Uint8Array => {
            throw new WasmError("Use async native generateBlinds method");
        },
    };
}

/**
 * Async native prover for React Native
 */
export class NativeSpartanProver {
    private native: SpartanNativeModule;

    constructor() {
        this.native = loadNativeModule();
    }

    async setupPrepare(
        r1csBytes: Uint8Array
    ): Promise<{ pk: Uint8Array; vk: Uint8Array }> {
        const result = await this.native.setupPrepare(Array.from(r1csBytes));
        return {
            pk: new Uint8Array(result.pk),
            vk: new Uint8Array(result.vk),
        };
    }

    async setupShow(
        r1csBytes: Uint8Array
    ): Promise<{ pk: Uint8Array; vk: Uint8Array }> {
        const result = await this.native.setupShow(Array.from(r1csBytes));
        return {
            pk: new Uint8Array(result.pk),
            vk: new Uint8Array(result.vk),
        };
    }

    async provePrepare(
        pk: Uint8Array,
        witness: Uint8Array
    ): Promise<ProveResult> {
        const result = await this.native.provePrepare(
            Array.from(pk),
            Array.from(witness)
        );
        return {
            proof: new Uint8Array(result.proof),
            instance: new Uint8Array(result.instance),
            witness: new Uint8Array(result.witness),
            sharedCommitment: new Uint8Array(result.sharedCommitment),
        };
    }

    async proveShow(pk: Uint8Array, witness: Uint8Array): Promise<ProveResult> {
        const result = await this.native.proveShow(
            Array.from(pk),
            Array.from(witness)
        );
        return {
            proof: new Uint8Array(result.proof),
            instance: new Uint8Array(result.instance),
            witness: new Uint8Array(result.witness),
            sharedCommitment: new Uint8Array(result.sharedCommitment),
        };
    }

    async reblind(
        pk: Uint8Array,
        instance: Uint8Array,
        witness: Uint8Array,
        blinds: Uint8Array
    ): Promise<ProveResult> {
        const result = await this.native.reblind(
            Array.from(pk),
            Array.from(instance),
            Array.from(witness),
            Array.from(blinds)
        );
        return {
            proof: new Uint8Array(result.proof),
            instance: new Uint8Array(result.instance),
            witness: new Uint8Array(result.witness),
            sharedCommitment: new Uint8Array(result.sharedCommitment),
        };
    }

    async verify(proof: Uint8Array, vk: Uint8Array): Promise<boolean> {
        return this.native.verify(Array.from(proof), Array.from(vk));
    }

    async generateBlinds(count: number): Promise<Uint8Array> {
        const result = await this.native.generateBlinds(count);
        return new Uint8Array(result);
    }
}

/**
 * Check if running in React Native
 */
export function isReactNative(): boolean {
    return (
        typeof navigator !== "undefined" && navigator.product === "ReactNative"
    );
}
