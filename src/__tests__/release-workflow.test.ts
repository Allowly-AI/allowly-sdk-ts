import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const workflow = readFileSync(new URL("../../.github/workflows/publish.yml", import.meta.url), "utf8");
const script = (step: string) => {
  const body = workflow.split(`      - name: ${step}\n`)[1]?.split("\n      - ")[0];
  const source = body?.split("<<'NODE'\n")[1]?.split("\n          NODE")[0];
  if (!source) throw new Error(`Missing publication check: ${step}`);
  return source.replace(/^          /gm, "");
};

function check(step: string, dependency: string, version = "5.0.0", fault = "") {
  const directory = mkdtempSync(join(tmpdir(), "allowly-sdk-publication-"));
  const packageJson = { dependencies: { "@allowly/verifier": dependency } };
  const lock = { packages: {
    "": { dependencies: { "@allowly/verifier": dependency } },
    "node_modules/@allowly/verifier": {
      version,
      resolved: `https://registry.npmjs.org/@allowly/verifier/-/verifier-${version}.tgz`,
      integrity: "sha512-test-registry-integrity",
    },
  } };
  if (fault === "link") Object.assign(lock.packages["node_modules/@allowly/verifier"], { link: true });
  if (fault === "tarball") lock.packages["node_modules/@allowly/verifier"].resolved = "https://example.com/verifier.tgz";
  if (fault === "integrity") lock.packages["node_modules/@allowly/verifier"].integrity = "";
  if (fault === "version") lock.packages["node_modules/@allowly/verifier"].version = "4.3.1";
  if (fault === "root") lock.packages[""].dependencies["@allowly/verifier"] = "^4.3.1";
  writeFileSync(join(directory, "package.json"), JSON.stringify(packageJson));
  writeFileSync(join(directory, "package-lock.json"), JSON.stringify(lock));
  try {
    return spawnSync(process.execPath, ["--input-type=module", "-e", script(step)], {
      cwd: directory, encoding: "utf8", env: { ...process.env, ALLOWLY_VERIFIER_RELEASE: version },
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe("publication dependency gate", () => {
  it("derives the public verifier release from its maintained dependency", () => {
    expect(check("Require public verifier release", "^5.0.0").stdout.trim()).toBe("5.0.0");
    expect(check("Require public verifier release", "5.0.1", "5.0.1").stdout.trim()).toBe("5.0.1");
    expect(check("Require public verifier release", "file:../allowly-receipt-format/verifiers/typescript").status).not.toBe(0);
  });

  it("accepts matching registry locks without a hard-coded wire-4 release", () => {
    const result = check("Require registry-backed verifier lock", "^5.0.0");
    expect(result.status, result.stderr).toBe(0);
    const next = check("Require registry-backed verifier lock", "5.0.1", "5.0.1");
    expect(next.status, next.stderr).toBe(0);
    expect(check("Require registry-backed verifier lock", "file:../allowly-receipt-format/verifiers/typescript").status).not.toBe(0);
  });

  it.each(["link", "tarball", "integrity", "version", "root"])("rejects a %s lock instead of publishing it", (fault) => {
    expect(check("Require registry-backed verifier lock", "^5.0.0", "5.0.0", fault).status).not.toBe(0);
  });
});
