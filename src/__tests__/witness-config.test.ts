import { createECDH, createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";

import { loadInstalledWitnessConfig } from "../witness-config.js";

const previous = process.env.ALLOWLY_CONFIG_DIR;
const directories: string[] = [];

afterEach(async () => {
  if (previous === undefined) delete process.env.ALLOWLY_CONFIG_DIR;
  else process.env.ALLOWLY_CONFIG_DIR = previous;
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

it("accepts only the requested workspace and pinned P-256 key", async () => {
  const directory = await mkdtemp(join(tmpdir(), "allowly-sdk-witness-config-"));
  directories.push(directory);
  process.env.ALLOWLY_CONFIG_DIR = directory;
  const workspaceDirectory = join(directory, "witness", "ws_expected");
  await mkdir(workspaceDirectory, { recursive: true });
  const helper = join(directory, "helper");
  await writeFile(helper, "#!/bin/sh\nexit 0\n");
  await chmod(helper, 0o700);
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const point = ecdh.getPublicKey(undefined, "compressed");
  const keyPath = join(workspaceDirectory, "key.json");
  await writeFile(keyPath, JSON.stringify({ alg: 2, data: [...point] }));
  const fingerprintSha256 = createHash("sha256").update(point).digest("hex");
  const configPath = join(workspaceDirectory, "config.json");
  const config = {
    version: 1,
    workspaceId: "ws_expected",
    nativeBinaryPath: helper,
    trustedNotaryKeyPath: keyPath,
    fingerprintSha256,
  };
  await writeFile(configPath, JSON.stringify(config));
  await expect(loadInstalledWitnessConfig("ws_expected")).resolves.toEqual(config);
  await expect(loadInstalledWitnessConfig("ws_other")).rejects.toThrow("run `allowly setup witness`");

  await writeFile(configPath, JSON.stringify({ ...config, fingerprintSha256: "0".repeat(64) }));
  await expect(loadInstalledWitnessConfig("ws_expected")).rejects.toThrow("does not match its pinned fingerprint");
});
