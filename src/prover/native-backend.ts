/**
 * Native Node.js Backend
 * Spawns the Rust ecdsa-spartan2 binary for proving/verification
 * Provides lightning-fast server-side operations
 */

import { spawn, execSync } from "child_process";
import { existsSync, mkdirSync, writeFileSync, readFileSync, unlinkSync } from "fs";
import { join, resolve } from "path";
import { tmpdir, homedir } from "os";
import { randomBytes } from "crypto";
import type { ProveResult } from "./wasm-loader";
import { ProofError, ConfigError } from "../errors";
import {
  isCircomCached,
  getCircomCachePath,
  getWorkingDir,
  ensureCircomArtifacts,
  type ProgressCallback,
} from "../utils/circom-downloader";

/** Path to the ecdsa-spartan2 binary */
let binaryPath: string | null = null;

/** Path to the circom directory */
let circomPath: string | null = null;

/** Check if we're running in Node.js */
export function isNodeJS(): boolean {
  return (
    typeof process !== "undefined" && process.versions != null && process.versions.node != null
  );
}

/** Get platform-specific package name */
function getPlatformPackage(): string {
  const platform = process.platform;
  const arch = process.arch;
  return `@l8zk/sdk-${platform}-${arch}`;
}

/** Find the ecdsa-spartan2 binary */
function findBinary(): string | null {
  const platform = process.platform;
  const arch = process.arch;
  const binaryName = platform === "win32" ? "ecdsa-spartan2.exe" : "ecdsa-spartan2";
  const platformPkg = `@l8zk/sdk-${platform}-${arch}`;

  const possiblePaths = [
    // 1. Platform package in cwd's node_modules (postinstall runs here, has +x)
    resolve(process.cwd(), "node_modules", platformPkg, "bin", binaryName),
    // 2. Platform-specific npm package via require.resolve (may be nested without +x)
    (() => {
      try {
        const pkgPath = require.resolve(`${platformPkg}/package.json`);
        return resolve(pkgPath, "..", "bin", binaryName);
      } catch {
        return null;
      }
    })(),
    // 3. Nested submodule structure (wallet-unit-poc/wallet-unit-poc/ecdsa-spartan2)
    resolve(
      process.cwd(),
      "wallet-unit-poc/wallet-unit-poc/ecdsa-spartan2/target/release",
      binaryName
    ),
    // 4. Direct submodule structure (wallet-unit-poc/ecdsa-spartan2)
    resolve(process.cwd(), "wallet-unit-poc/ecdsa-spartan2/target/release", binaryName),
    // 5. Relative to __dirname (when running from dist/)
    resolve(
      __dirname,
      "../../wallet-unit-poc/wallet-unit-poc/ecdsa-spartan2/target/release",
      binaryName
    ),
    resolve(__dirname, "../../wallet-unit-poc/ecdsa-spartan2/target/release", binaryName),
    resolve(__dirname, "../../../wallet-unit-poc/ecdsa-spartan2/target/release", binaryName),
    // 6. In PATH
    "ecdsa-spartan2",
  ].filter(Boolean) as string[];

  for (const p of possiblePaths) {
    try {
      if (p === "ecdsa-spartan2") {
        // Check if in PATH
        execSync(platform === "win32" ? "where ecdsa-spartan2" : "which ecdsa-spartan2", {
          stdio: "ignore",
        });
        return p;
      } else if (existsSync(p)) {
        return p;
      }
    } catch {
      continue;
    }
  }

  return null;
}

/** Find the circom directory */
function findCircomDir(): string | null {
  const possiblePaths = [
    // 1. Cached circom artifacts (downloaded on first use)
    getCircomCachePath(),
    // 2. Local development paths
    resolve(process.cwd(), "wallet-unit-poc/wallet-unit-poc/circom"),
    resolve(process.cwd(), "wallet-unit-poc/circom"),
    resolve(process.cwd(), "../wallet-unit-poc/circom"),
    resolve(__dirname, "../../wallet-unit-poc/wallet-unit-poc/circom"),
    resolve(__dirname, "../../wallet-unit-poc/circom"),
    resolve(__dirname, "../../../wallet-unit-poc/circom"),
  ];

  for (const p of possiblePaths) {
    // Check for build artifacts (r1cs files)
    if (existsSync(join(p, "build", "jwt", "jwt_js", "jwt.r1cs"))) {
      return p;
    }
    // Fallback to circuits.json for dev environments
    if (existsSync(join(p, "circuits.json"))) {
      return p;
    }
  }

  return null;
}

/** Check if circom artifacts are available (either cached or local) */
export function hasCircomArtifacts(): boolean {
  return isCircomCached() || findCircomDir() !== null;
}

/** Ensure circom artifacts are available, downloading if needed */
export async function ensureCircom(onProgress?: ProgressCallback): Promise<string> {
  // First check local paths (dev environment)
  const localPath = findCircomDir();
  if (localPath && existsSync(join(localPath, "build", "jwt", "jwt_js", "jwt.r1cs"))) {
    circomPath = localPath;
    return localPath;
  }

  // Download if not available
  await ensureCircomArtifacts(onProgress);
  // Return working directory where binary should run (../circom/build exists from there)
  circomPath = getWorkingDir();
  return circomPath;
}

/** Initialize the native backend */
export function initNativeBackend(options?: { binaryPath?: string; circomPath?: string }): {
  available: boolean;
  binaryPath: string | null;
  circomPath: string | null;
} {
  binaryPath = options?.binaryPath || findBinary();
  circomPath = options?.circomPath || findCircomDir();

  return {
    available: binaryPath !== null,
    binaryPath,
    circomPath,
  };
}

/** Check if native backend is available */
export function isNativeAvailable(): boolean {
  if (binaryPath === null) {
    const result = initNativeBackend();
    return result.available;
  }
  return binaryPath !== null;
}

/** Get the binary path or throw */
function getBinaryPath(): string {
  if (!binaryPath) {
    const result = initNativeBackend();
    if (!result.available) {
      throw new ConfigError(
        "Native backend not available. Build the Rust binary with: " +
          "cd wallet-unit-poc/ecdsa-spartan2 && cargo build --release"
      );
    }
  }
  return binaryPath!;
}

/** Create a temporary directory for this operation */
function createTempDir(): string {
  const dir = join(tmpdir(), `l8zk-${randomBytes(8).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

/** Run the Rust binary with arguments */
async function runBinary(
  args: string[],
  cwd?: string
): Promise<{ stdout: string; stderr: string; code: number }> {
  const binary = getBinaryPath();

  return new Promise((resolve, reject) => {
    const proc = spawn(binary, args, {
      cwd: cwd || circomPath || process.cwd(),
      env: { ...process.env, RUST_LOG: "error" },
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      resolve({ stdout, stderr, code: code || 0 });
    });

    proc.on("error", (err) => {
      reject(new ProofError(`Failed to run native binary: ${err.message}`));
    });
  });
}

/** Native backend interface matching SpartanWasm */
export interface NativeBackend {
  setupPrepare(inputPath: string): Promise<{ pkPath: string; vkPath: string }>;
  setupShow(inputPath: string): Promise<{ pkPath: string; vkPath: string }>;
  provePrepare(inputPath: string): Promise<NativeProveResult>;
  proveShow(inputPath: string): Promise<NativeProveResult>;
  reblind(circuit: "prepare" | "show"): Promise<NativeProveResult>;
  verify(circuit: "prepare" | "show"): Promise<boolean>;
  generateBlinds(): Promise<string>;
}

export interface NativeProveResult {
  proofPath: string;
  instancePath: string;
  witnessPath: string;
}

/**
 * Setup keys for the prepare circuit
 */
export async function nativeSetupPrepare(
  inputPath?: string
): Promise<{ pkPath: string; vkPath: string }> {
  const args = ["prepare", "setup"];
  if (inputPath) {
    args.push("--input", inputPath);
  }

  const result = await runBinary(args);

  if (result.code !== 0) {
    throw new ProofError(`Setup failed: ${result.stderr}`);
  }

  return {
    pkPath: "keys/prepare_proving.key",
    vkPath: "keys/prepare_verifying.key",
  };
}

/**
 * Setup keys for the show circuit
 */
export async function nativeSetupShow(
  inputPath?: string
): Promise<{ pkPath: string; vkPath: string }> {
  const args = ["show", "setup"];
  if (inputPath) {
    args.push("--input", inputPath);
  }

  const result = await runBinary(args);

  if (result.code !== 0) {
    throw new ProofError(`Setup failed: ${result.stderr}`);
  }

  return {
    pkPath: "keys/show_proving.key",
    vkPath: "keys/show_verifying.key",
  };
}

/**
 * Generate shared blinds for linking proofs
 */
export async function nativeGenerateBlinds(): Promise<string> {
  const result = await runBinary(["generate_shared_blinds"]);

  if (result.code !== 0) {
    throw new ProofError(`Generate blinds failed: ${result.stderr}`);
  }

  return "keys/shared_blinds.bin";
}

/**
 * Prove the prepare circuit
 */
export async function nativeProvePrepare(inputPath?: string): Promise<NativeProveResult> {
  const args = ["prepare", "prove"];
  if (inputPath) {
    args.push("--input", inputPath);
  }

  const result = await runBinary(args);

  if (result.code !== 0) {
    throw new ProofError(`Prove failed: ${result.stderr}`);
  }

  return {
    proofPath: "keys/prepare_proof.bin",
    instancePath: "keys/prepare_instance.bin",
    witnessPath: "keys/prepare_witness.bin",
  };
}

/**
 * Prove the show circuit
 */
export async function nativeProveShow(inputPath?: string): Promise<NativeProveResult> {
  const args = ["show", "prove"];
  if (inputPath) {
    args.push("--input", inputPath);
  }

  const result = await runBinary(args);

  if (result.code !== 0) {
    throw new ProofError(`Prove failed: ${result.stderr}`);
  }

  return {
    proofPath: "keys/show_proof.bin",
    instancePath: "keys/show_instance.bin",
    witnessPath: "keys/show_witness.bin",
  };
}

/**
 * Reblind a proof for unlinkability
 */
export async function nativeReblind(circuit: "prepare" | "show"): Promise<NativeProveResult> {
  const result = await runBinary([circuit, "reblind"]);

  if (result.code !== 0) {
    throw new ProofError(`Reblind failed: ${result.stderr}`);
  }

  return {
    proofPath: `keys/${circuit}_proof.bin`,
    instancePath: `keys/${circuit}_instance.bin`,
    witnessPath: `keys/${circuit}_witness.bin`,
  };
}

/**
 * Verify a proof
 */
export async function nativeVerify(circuit: "prepare" | "show"): Promise<boolean> {
  const result = await runBinary([circuit, "verify"]);

  if (result.code !== 0) {
    // Check if it's a verification failure vs an error
    if (result.stderr.includes("verify errored") || result.stderr.includes("verification failed")) {
      return false;
    }
    throw new ProofError(`Verify failed: ${result.stderr}`);
  }

  return result.stdout.includes("successful") || result.code === 0;
}

/**
 * Run the full benchmark pipeline
 */
export async function nativeBenchmark(inputPath?: string): Promise<{
  prepareSetupMs: number;
  showSetupMs: number;
  prepareProveMs: number;
  showProveMs: number;
  prepareVerifyMs: number;
  showVerifyMs: number;
}> {
  const args = ["benchmark"];
  if (inputPath) {
    args.push("--input", inputPath);
  }

  const result = await runBinary(args);

  if (result.code !== 0) {
    throw new ProofError(`Benchmark failed: ${result.stderr}`);
  }

  // Parse timing from output
  const parseTime = (label: string): number => {
    const match = result.stdout.match(new RegExp(`${label}:\\s*(\\d+)\\s*ms`));
    return match ? parseInt(match[1], 10) : 0;
  };

  return {
    prepareSetupMs: parseTime("Prepare Setup") || parseTime("Prepare setup"),
    showSetupMs: parseTime("Show Setup") || parseTime("Show setup"),
    prepareProveMs: parseTime("Prove Prepare") || parseTime("Prepare proof"),
    showProveMs: parseTime("Prove Show") || parseTime("Show proof"),
    prepareVerifyMs: parseTime("Verify Prepare") || parseTime("Prepare proof verified"),
    showVerifyMs: parseTime("Verify Show") || parseTime("Show proof verified"),
  };
}

/**
 * Write input JSON for the circuit
 */
export function writeCircuitInput(
  inputData: Record<string, unknown>,
  circuit: "jwt" | "show"
): string {
  if (!circomPath) {
    initNativeBackend();
  }

  const inputDir = circomPath
    ? join(circomPath, "inputs", circuit)
    : join(tmpdir(), "l8zk-inputs", circuit);

  mkdirSync(inputDir, { recursive: true });

  const inputPath = join(inputDir, `generated_${Date.now()}.json`);
  writeFileSync(inputPath, JSON.stringify(inputData, null, 2));

  return inputPath;
}

/**
 * Read proof bytes from file
 */
export function readProofFile(proofPath: string): Uint8Array {
  const fullPath = circomPath ? join(circomPath, "..", "ecdsa-spartan2", proofPath) : proofPath;

  if (!existsSync(fullPath)) {
    throw new ProofError(`Proof file not found: ${fullPath}`);
  }

  return new Uint8Array(readFileSync(fullPath));
}

/**
 * Clean up temporary files
 */
export function cleanupTempFiles(paths: string[]): void {
  for (const p of paths) {
    try {
      if (existsSync(p)) {
        unlinkSync(p);
      }
    } catch {
      // Ignore cleanup errors
    }
  }
}
