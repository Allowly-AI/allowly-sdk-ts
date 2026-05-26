import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearKeysDocCache,
  fetchKeysDoc,
  loadKeysFromJson,
  VerificationError,
} from "../verify.js";

const VALID_DOC = {
  workspace_id: "ws_1",
  keys: [
    {
      key_id: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
      alg: "Ed25519",
      public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      active_from: "2026-01-01T00:00:00Z",
      active_until: null,
    },
  ],
};

describe("fetchKeysDoc", () => {
  beforeEach(() => {
    clearKeysDocCache();
  });

  it("rejects non-https base URLs", async () => {
    await expect(fetchKeysDoc("ws_1", { baseUrl: "http://localhost:8000" })).rejects.toThrow(
      "HTTPS",
    );
  });

  it("caches documents for five minutes by default", async () => {
    const fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(VALID_DOC),
    });
    const first = await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com" });
    const second = await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com" });

    expect(first).toEqual(VALID_DOC);
    expect(second).toEqual(VALID_DOC);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("zero cacheTtlMs bypasses stale cache", async () => {
    const fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(VALID_DOC),
    });
    await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com", cacheTtlMs: 300_000 });
    await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com", cacheTtlMs: 0 });

    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("returned doc is isolated from the cache", async () => {
    const fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(VALID_DOC),
    });
    const first = await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com" });
    first.keys.length = 0;

    const second = await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com" });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(second.keys).toHaveLength(1);
  });

  it("rejects hash-pin mismatches", async () => {
    const fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(VALID_DOC),
    });
    await expect(
      fetchKeysDoc("ws_1", {
        fetch,
        baseUrl: "https://api.example.com",
        expectedSha256: "deadbeef",
      }),
    ).rejects.toThrow("SHA-256");
  });
});

describe("loadKeysFromJson", () => {
  it("rejects malformed key documents", () => {
    expect(() =>
      loadKeysFromJson({
        workspace_id: "ws_1",
        keys: [{ ...VALID_DOC.keys[0], public_key: "not-base64url??" }],
      }),
    ).toThrow(VerificationError);
  });
});
