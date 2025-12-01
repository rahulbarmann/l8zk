/**
 * L8ZK SDK Error Classes
 * Provides clear, actionable error messages for developers
 */

/** Base error class for all OpenAC errors */
export class OpenACError extends Error {
    constructor(
        message: string,
        public readonly code: string,
        public readonly cause?: Error
    ) {
        super(message);
        this.name = "OpenACError";
        Object.setPrototypeOf(this, OpenACError.prototype);
    }
}

/** Credential parsing or validation errors */
export class CredentialError extends OpenACError {
    constructor(message: string, cause?: Error) {
        super(message, "CREDENTIAL_ERROR", cause);
        this.name = "CredentialError";
        Object.setPrototypeOf(this, CredentialError.prototype);
    }
}

/** Proof generation errors */
export class ProofError extends OpenACError {
    constructor(message: string, cause?: Error) {
        super(message, "PROOF_ERROR", cause);
        this.name = "ProofError";
        Object.setPrototypeOf(this, ProofError.prototype);
    }
}

/** Verification errors */
export class VerificationError extends OpenACError {
    constructor(message: string, cause?: Error) {
        super(message, "VERIFICATION_ERROR", cause);
        this.name = "VerificationError";
        Object.setPrototypeOf(this, VerificationError.prototype);
    }
}

/** Storage errors */
export class StorageError extends OpenACError {
    constructor(message: string, cause?: Error) {
        super(message, "STORAGE_ERROR", cause);
        this.name = "StorageError";
        Object.setPrototypeOf(this, StorageError.prototype);
    }
}

/** Configuration errors */
export class ConfigError extends OpenACError {
    constructor(message: string, cause?: Error) {
        super(message, "CONFIG_ERROR", cause);
        this.name = "ConfigError";
        Object.setPrototypeOf(this, ConfigError.prototype);
    }
}

/** Policy validation errors */
export class PolicyError extends OpenACError {
    constructor(message: string, cause?: Error) {
        super(message, "POLICY_ERROR", cause);
        this.name = "PolicyError";
        Object.setPrototypeOf(this, PolicyError.prototype);
    }
}

/** Device binding errors */
export class DeviceBindingError extends OpenACError {
    constructor(message: string, cause?: Error) {
        super(message, "DEVICE_BINDING_ERROR", cause);
        this.name = "DeviceBindingError";
        Object.setPrototypeOf(this, DeviceBindingError.prototype);
    }
}

/** WASM module loading errors */
export class WasmError extends OpenACError {
    constructor(message: string, cause?: Error) {
        super(message, "WASM_ERROR", cause);
        this.name = "WasmError";
        Object.setPrototypeOf(this, WasmError.prototype);
    }
}
