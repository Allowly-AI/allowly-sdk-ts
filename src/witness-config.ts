import { ECDH, createHash } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

interface InstalledWitnessConfig {
  version: 1;
  workspaceId: string;
  nativeBinaryPath: string;
  trustedNotaryKeyPath: string;
  fingerprintSha256: string;
  trustedWitnessCaPath?: string;
  witnessCaFingerprintSha256?: string;
}

/** @internal The CLI writes this public, workspace-scoped trust configuration. */
export async function loadInstalledWitnessConfig(workspaceId: string): Promise<InstalledWitnessConfig> {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(workspaceId)) {
    throw new Error("invalid witness workspace ID");
  }
  const base = process.env.ALLOWLY_CONFIG_DIR ?? join(homedir(), ".allowly");
  const path = join(base, "witness", workspaceId, "config.json");
  let contents: string;
  try {
    contents = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`witness setup is missing for workspace ${workspaceId}; run \`allowly setup witness\``);
    }
    throw new Error("installed witness config could not be read");
  }
  let raw: unknown;
  try {
    raw = JSON.parse(contents);
  } catch {
    throw new Error("installed witness config is invalid");
  }
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("installed witness config is invalid");
  }
  const config = raw as Partial<InstalledWitnessConfig>;
  if (config.version !== 1 || config.workspaceId !== workspaceId
      || typeof config.nativeBinaryPath !== "string" || !isAbsolute(config.nativeBinaryPath)
      || typeof config.trustedNotaryKeyPath !== "string" || !isAbsolute(config.trustedNotaryKeyPath)
      || typeof config.fingerprintSha256 !== "string"
      || !/^[0-9a-f]{64}$/.test(config.fingerprintSha256)
      || ((config.trustedWitnessCaPath === undefined) !== (config.witnessCaFingerprintSha256 === undefined))
      || (config.trustedWitnessCaPath !== undefined && !isAbsolute(config.trustedWitnessCaPath))
      || (config.witnessCaFingerprintSha256 !== undefined
        && !/^[0-9a-f]{64}$/.test(config.witnessCaFingerprintSha256))) {
    throw new Error("installed witness config is invalid");
  }
  await access(config.nativeBinaryPath, constants.X_OK);
  const keyBytes = await readFile(config.trustedNotaryKeyPath);
  let key: unknown;
  try {
    key = JSON.parse(keyBytes.toString("utf8"));
  } catch {
    throw new Error("installed witness public key is invalid");
  }
  if (key === null || typeof key !== "object" || Array.isArray(key)
      || (key as { alg?: unknown }).alg !== 2
      || !Array.isArray((key as { data?: unknown }).data)
      || !(key as { data: unknown[] }).data.every((part) => Number.isInteger(part) && (part as number) >= 0 && (part as number) <= 255)) {
    throw new Error("installed witness public key is invalid");
  }
  let compressed: Buffer;
  try {
    compressed = ECDH.convertKey(
      Buffer.from((key as { data: number[] }).data),
      "prime256v1", undefined, undefined, "compressed",
    ) as Buffer;
  } catch {
    throw new Error("installed witness public key is invalid");
  }
  const fingerprint = createHash("sha256").update(compressed).digest("hex");
  if (fingerprint !== config.fingerprintSha256) {
    throw new Error("installed witness public key does not match its pinned fingerprint");
  }
  if (config.trustedWitnessCaPath !== undefined) {
    const caBytes = await readFile(config.trustedWitnessCaPath);
    if (caBytes.length < 1 || caBytes.length > 32 * 1024
        || createHash("sha256").update(caBytes).digest("hex") !== config.witnessCaFingerprintSha256) {
      throw new Error("installed witness CA does not match its pinned fingerprint");
    }
  }
  return config as InstalledWitnessConfig;
}
