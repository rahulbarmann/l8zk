/**
 * Unified Prover Backend
 * Automatically selects native (Node.js) or WASM (browser/RN) backend
 */

import {
    isNodeJS,
    isNativeAvailable,
    initNativeBackend,
} from "./native-backend";
import { loadWasm, isWasmLoaded } from "./wasm-loader";
import { ConfigError } from "../errors";

export type BackendType = "native" | "wasm" | "none";

let selectedBackend: BackendType = "none";
let backendInitialized = false;

/**
 * Detect and initialize the best available backend
 */
export async function initBackend(
    preferred?: BackendType
): Promise<BackendType> {
    if (backendInitialized && selectedBackend !== "none") {
        return selectedBackend;
    }

    // If preferred backend specified, try that first
    if (preferred === "native") {
        if (isNodeJS() && isNativeAvailable()) {
            selectedBackend = "native";
            backendInitialized = true;
            return selectedBackend;
        }
        throw new ConfigError("Native backend requested but not available");
    }

    if (preferred === "wasm") {
        try {
            await loadWasm();
            selectedBackend = "wasm";
            backendInitialized = true;
            return selectedBackend;
        } catch {
            throw new ConfigError("WASM backend requested but failed to load");
        }
    }

    // Auto-detect: prefer native in Node.js, WASM elsewhere
    if (isNodeJS()) {
        const nativeResult = initNativeBackend();
        if (nativeResult.available) {
            selectedBackend = "native";
            backendInitialized = true;
            return selectedBackend;
        }
    }

    // Try WASM
    try {
        await loadWasm();
        selectedBackend = "wasm";
        backendInitialized = true;
        return selectedBackend;
    } catch {
        // WASM not available
    }

    // Check native as fallback even in non-Node environments
    if (isNativeAvailable()) {
        selectedBackend = "native";
        backendInitialized = true;
        return selectedBackend;
    }

    selectedBackend = "none";
    backendInitialized = true;
    return selectedBackend;
}

/**
 * Get the current backend type
 */
export function getBackendType(): BackendType {
    return selectedBackend;
}

/**
 * Check if any backend is available
 */
export function isBackendAvailable(): boolean {
    return selectedBackend !== "none";
}

/**
 * Reset backend selection (for testing)
 */
export function resetBackend(): void {
    selectedBackend = "none";
    backendInitialized = false;
}

/**
 * Get backend status information
 */
export function getBackendStatus(): {
    selected: BackendType;
    nativeAvailable: boolean;
    wasmLoaded: boolean;
    isNode: boolean;
} {
    return {
        selected: selectedBackend,
        nativeAvailable: isNativeAvailable(),
        wasmLoaded: isWasmLoaded(),
        isNode: isNodeJS(),
    };
}
