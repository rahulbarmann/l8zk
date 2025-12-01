/**
 * Circom Artifacts Downloader
 * Downloads and caches circom build files on first use
 */

import { existsSync, mkdirSync, createWriteStream, unlinkSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { execSync } from "child_process";

const CIRCOM_ARTIFACTS_URL =
  "https://github.com/rahulbarmann/l8zk/releases/download/circom-build-v1/circom-build-v3.tar.gz";

// Structure: ~/.l8zk/circom/build/... (artifacts)
//            ~/.l8zk/ecdsa-spartan2/ (working dir for binary)
// Binary runs from ecdsa-spartan2/ and looks for ../circom/build/
const CACHE_BASE = join(homedir(), ".l8zk");
const CACHE_DIR = join(CACHE_BASE, "circom");
const WORKING_DIR = join(CACHE_BASE, "ecdsa-spartan2");
const MARKER_FILE = join(CACHE_DIR, ".downloaded");

export interface DownloadProgress {
  phase: "downloading" | "extracting" | "complete";
  percent?: number;
  message: string;
}

export type ProgressCallback = (progress: DownloadProgress) => void;

/**
 * Check if circom artifacts are already cached
 */
export function isCircomCached(): boolean {
  return (
    existsSync(MARKER_FILE) && existsSync(join(CACHE_DIR, "build", "jwt", "jwt_js", "jwt.r1cs"))
  );
}

/**
 * Get the path to cached circom directory
 */
export function getCircomCachePath(): string {
  return CACHE_DIR;
}

/**
 * Get the working directory for the binary (where ../circom/build exists)
 */
export function getWorkingDir(): string {
  return WORKING_DIR;
}

/**
 * Download and extract circom artifacts
 */
export async function downloadCircomArtifacts(onProgress?: ProgressCallback): Promise<string> {
  if (isCircomCached()) {
    onProgress?.({ phase: "complete", message: "Circom artifacts already cached" });
    return CACHE_DIR;
  }

  // Create cache directory
  mkdirSync(CACHE_DIR, { recursive: true });

  const tarPath = join(CACHE_DIR, "circom-build.tar.gz");

  try {
    // Download
    onProgress?.({
      phase: "downloading",
      percent: 0,
      message: "Downloading circom artifacts (~33MB)...",
    });

    await downloadFile(CIRCOM_ARTIFACTS_URL, tarPath, (percent) => {
      onProgress?.({
        phase: "downloading",
        percent,
        message: `Downloading circom artifacts... ${percent}%`,
      });
    });

    // Extract
    onProgress?.({
      phase: "extracting",
      message: "Extracting circom artifacts...",
    });

    execSync(`tar -xzf "${tarPath}" -C "${CACHE_DIR}"`, { stdio: "ignore" });

    // Cleanup tar file
    unlinkSync(tarPath);

    // Create working directory for binary (binary looks for ../circom/build/)
    mkdirSync(WORKING_DIR, { recursive: true });

    // Create marker file
    execSync(`touch "${MARKER_FILE}"`);

    onProgress?.({
      phase: "complete",
      message: "Circom artifacts ready",
    });

    return CACHE_DIR;
  } catch (error) {
    // Cleanup on failure
    try {
      if (existsSync(tarPath)) unlinkSync(tarPath);
    } catch {
      // ignore cleanup errors
    }
    throw new Error(`Failed to download circom artifacts: ${(error as Error).message}`);
  }
}

/**
 * Download a file with progress tracking
 */
async function downloadFile(
  url: string,
  destPath: string,
  onProgress?: (percent: number) => void
): Promise<void> {
  // Use native fetch in Node 18+
  const response = await fetch(url, { redirect: "follow" });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const contentLength = response.headers.get("content-length");
  const totalBytes = contentLength ? parseInt(contentLength, 10) : 0;

  const fileStream = createWriteStream(destPath);
  const reader = response.body?.getReader();

  if (!reader) {
    throw new Error("Failed to get response reader");
  }

  let downloadedBytes = 0;
  let lastReportedPercent = 0;
  let done = false;

  while (!done) {
    const result = await reader.read();
    done = result.done;

    if (result.value) {
      fileStream.write(Buffer.from(result.value));
      downloadedBytes += result.value.length;

      if (totalBytes > 0) {
        const percent = Math.floor((downloadedBytes / totalBytes) * 100);
        if (percent > lastReportedPercent) {
          lastReportedPercent = percent;
          onProgress?.(percent);
        }
      }
    }
  }

  fileStream.end();

  return new Promise((resolve, reject) => {
    fileStream.on("finish", resolve);
    fileStream.on("error", reject);
  });
}

/**
 * Ensure circom artifacts are available, downloading if needed
 */
export async function ensureCircomArtifacts(onProgress?: ProgressCallback): Promise<string> {
  if (isCircomCached()) {
    return CACHE_DIR;
  }

  return downloadCircomArtifacts(onProgress);
}
