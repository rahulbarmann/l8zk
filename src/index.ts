/**
 * L8ZK SDK
 * Privacy-preserving verifiable credentials using zero-knowledge proofs
 *
 * @packageDocumentation
 */

// Main class
export { OpenAC } from "./openac";

// Types
export type {
  // Core types
  CredentialFormat,
  ECPublicKey,
  ECPrivateKey,
  DeviceBindingConfig,
  PrepareOptions,
  ShowOptions,
  CredentialHandle,
  CredentialMetadata,
  Proof,
  SerializedProof,
  VerificationResult,
  VerifyOptions,

  // Policy types
  Policy,
  PredicateCondition,
  PredicateOperator,

  // Configuration
  OpenACConfig,
  StorageAdapter,
  CircuitParams,
} from "./types";

// Constants
export { DEFAULT_CIRCUIT_PARAMS } from "./types";

// Errors
export {
  OpenACError,
  CredentialError,
  ProofError,
  VerificationError,
  StorageError,
  ConfigError,
  PolicyError,
  DeviceBindingError,
  WasmError,
} from "./errors";

// Storage adapters (for custom implementations)
export {
  IndexedDBAdapter,
  MemoryAdapter,
  AsyncStorageAdapter,
  createDefaultAdapter,
} from "./storage";

// Utilities (for advanced usage)
export {
  // Base64
  base64Encode,
  base64Decode,
  base64UrlEncode,
  base64UrlDecode,
  base64ToBigInt,
  bigIntToBase64Url,

  // Crypto
  generateKeyPair,
  sign,
  verify,
  sha256Hash,
  randomBytes,
} from "./utils";

// Credential parsing (for advanced usage)
export {
  parseSDJWT,
  extractMetadata,
  type ParsedSDJWT,
  type SDJWTHeader,
  type SDJWTPayload,
  type SDJWTDisclosure,
} from "./credential";

// Prover utilities (for advanced usage)
export {
  loadWasm,
  isWasmLoaded,
  serializeProof,
  deserializeProof,
  // Backend selection
  initBackend,
  getBackendType,
  getBackendStatus,
  isNativeAvailable,
  isNodeJS,
  type BackendType,
} from "./prover";

// Circom artifact management
export {
  isCircomCached,
  ensureCircomArtifacts,
  getCircomCachePath,
  type DownloadProgress,
  type ProgressCallback,
} from "./utils/circom-downloader";
