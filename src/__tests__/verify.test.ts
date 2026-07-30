import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  canonicalize,
  clearKeysDocCache,
  fetchKeysDoc,
  loadKeysFromJson,
  VerificationError,
  verifyReceipt,
} from "../verify.js";

const VALID_DOC = {
  workspace_id: "ws_1",
  keys: [
    {
      key_id: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
      alg: "Ed25519",
      public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      active_from: "2026-01-01T00:00:00.000Z",
      active_until: null,
    },
  ],
};

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function signedPolicyEvalReceipt() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const publicKeyRaw = new Uint8Array(publicDer).slice(-32);
  const keyId = "test-key/v1";
  const payload = {
    schema_version: "3",
    receipt_id: "rcp_policy_eval",
    workspace_id: "ws_1",
    issued_at: "2026-06-09T17:04:39.114Z",
    decision: "confirm",
    reason: "confirm_condition_matched",
    user_id: "cand_55ab2",
    agent_id: "scout_referrals",
    action: "hiring.publish_feedback",
    resource: "application:req_2207:cand_55ab2",
    context: {
      initiated_by: "agent",
      checks_failed: "pii_detected",
    },
    authorization_id: "auth_conditional",
    engine_version: "2026-06-01.2",
    alg: "Ed25519",
    key_id: keyId,
    policy_eval: {
      matched_condition: {
        field: "checks_failed",
        op: "in",
        value: ["pii_detected", "tone_flag"],
      },
      field_value: "pii_detected",
    },
  };
  const signature = sign(null, canonicalize(payload), privateKey);
  return {
    keysDoc: {
      workspace_id: "ws_1",
      keys: [
        {
          key_id: keyId,
          alg: "Ed25519",
          public_key: b64url(publicKeyRaw),
          active_from: "2026-01-01T00:00:00.000Z",
          active_until: null,
        },
      ],
    },
    receipt: {
      ...payload,
      signature: b64url(signature),
    },
  };
}

describe("fetchKeysDoc", () => {
  beforeEach(() => {
    clearKeysDocCache();
  });

  it("rejects non-https base URLs", async () => {
    await expect(fetchKeysDoc("ws_1", { baseUrl: "http://localhost:8000" })).rejects.toThrow(
      "HTTPS",
    );
  });

  it("allows explicit insecure local development and sends the edge token", async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse(VALID_DOC));

    await fetchKeysDoc("ws_1", {
      baseUrl: "http://localhost:8000",
      dangerouslyAllowInsecureBaseUrl: true,
      edgeToken: "local-edge-token",
      fetch,
    });

    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:8000/v1/workspaces/ws_1/keys",
      expect.objectContaining({
        redirect: "manual",
        headers: { "X-Allowly-Edge-Token": "local-edge-token" },
      }),
    );
  });

  it("rejects non-HTTP schemes even with insecure opt-in", async () => {
    await expect(fetchKeysDoc("ws_1", {
      baseUrl: "ftp://api.example.com",
      dangerouslyAllowInsecureBaseUrl: true,
    })).rejects.toThrow("HTTP or HTTPS");
  });

  it("requests manual redirect handling", async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse(VALID_DOC));

    await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com" });

    expect(fetch.mock.calls[0][1]).toMatchObject({ redirect: "manual" });
  });

  it("rejects a followed redirect even when the final response is HTTP 200", async () => {
    const response = jsonResponse(VALID_DOC);
    Object.defineProperty(response, "redirected", { value: true });

    await expect(fetchKeysDoc("ws_1", {
      fetch: vi.fn().mockResolvedValue(response),
      baseUrl: "https://api.example.com",
    })).rejects.toThrow("redirected");
  });

  it.each([201, 204, 206])("requires exact HTTP 200, not successful status %i", async (status) => {
    const response = status === 204
      ? new Response(null, { status })
      : new Response(JSON.stringify(VALID_DOC), { status });

    await expect(fetchKeysDoc("ws_1", {
      fetch: vi.fn().mockResolvedValue(response),
      baseUrl: "https://api.example.com",
    })).rejects.toThrow(`HTTP ${status}`);
  });

  it("caches documents for five minutes by default", async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse(VALID_DOC));
    const first = await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com" });
    const second = await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com" });

    expect(first).toEqual(VALID_DOC);
    expect(second).toEqual(VALID_DOC);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("zero cacheTtlMs bypasses stale cache", async () => {
    const fetch = vi.fn().mockImplementation(async () => jsonResponse(VALID_DOC));
    await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com", cacheTtlMs: 300_000 });
    await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com", cacheTtlMs: 0 });

    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("returned doc is isolated from the cache", async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse(VALID_DOC));
    const first = await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com" });
    first.keys.length = 0;

    const second = await fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com" });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(second.keys).toHaveLength(1);
  });

  it("rejects hash-pin mismatches", async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse(VALID_DOC));
    await expect(
      fetchKeysDoc("ws_1", {
        fetch,
        baseUrl: "https://api.example.com",
        expectedSha256: "deadbeef",
      }),
    ).rejects.toThrow("SHA-256");
  });

  it("hashes the downloaded bytes", async () => {
    const body = JSON.stringify(VALID_DOC);
    const fetch = vi.fn().mockResolvedValue(new Response(body, { status: 200 }));
    const expectedSha256 = createHash("sha256").update(Buffer.from(body)).digest("hex");

    await expect(fetchKeysDoc("ws_1", {
      fetch,
      baseUrl: "https://api.example.com",
      expectedSha256,
    })).resolves.toEqual(VALID_DOC);
  });

  it("encodes workspace IDs in the URL", async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ ...VALID_DOC, workspace_id: "ws/1" }));
    await fetchKeysDoc("ws/1", { fetch, baseUrl: "https://api.example.com" });
    expect(fetch.mock.calls[0][0]).toBe("https://api.example.com/v1/workspaces/ws%2F1/keys");
  });

  it("rejects workspace_id mismatches", async () => {
    const fetch = vi.fn().mockResolvedValue(jsonResponse({ ...VALID_DOC, workspace_id: "ws_other" }));

    await expect(
      fetchKeysDoc("ws_1", { fetch, baseUrl: "https://api.example.com" }),
    ).rejects.toThrow("workspace_id mismatch");
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

describe("verifyReceipt", () => {
  it("accepts a wire-3 receipt whose algorithm and key id are signed", async () => {
    const { keysDoc, receipt } = signedPolicyEvalReceipt();
    const keys = loadKeysFromJson(keysDoc);

    await expect(
      verifyReceipt(receipt, keys, {
        expectedWorkspaceId: "ws_1",
        now: new Date("2026-06-09T17:05:00Z"),
      }),
    ).resolves.toBeUndefined();
  });

  it("rejects policy_eval on event receipts", async () => {
    const { keysDoc, receipt } = signedPolicyEvalReceipt();
    const keys = loadKeysFromJson(keysDoc);
    const eventReceipt = {
      ...receipt,
      action: undefined,
      event: "authorization.create",
      decision: "authorization_granted",
      reason: "user_approved_via_customer_ui",
      resource: null,
    };
    delete eventReceipt.action;

    await expect(
      verifyReceipt(eventReceipt, keys, {
        expectedWorkspaceId: "ws_1",
        now: new Date("2026-06-09T17:05:00Z"),
      }),
    ).rejects.toThrow("policy_eval must be absent on event receipts");
  });

  it("rejects integers outside the safe range", async () => {
    const { keysDoc, receipt } = signedPolicyEvalReceipt();
    const keys = loadKeysFromJson(keysDoc);
    const badReceipt = {
      ...receipt,
      policy_eval: {
        matched_condition: {
          field: "transcript_completeness",
          op: "eq",
          value: Number.MAX_SAFE_INTEGER + 1,
        },
        field_value: 1,
      },
    };

    await expect(
      verifyReceipt(badReceipt, keys, {
        expectedWorkspaceId: "ws_1",
        now: new Date("2026-06-09T17:05:00Z"),
      }),
    ).rejects.toThrow("integer exceeds the safe range");
  });

  it("rejects timestamps without UTC millisecond precision", async () => {
    const { keysDoc, receipt } = signedPolicyEvalReceipt();
    const keys = loadKeysFromJson(keysDoc);
    const badKeys = {
      ...keysDoc,
      keys: [{ ...keysDoc.keys[0], active_from: "2026-01-01T00:00:00" }],
    };

    expect(() => loadKeysFromJson(badKeys)).toThrow("UTC millisecond precision");

    const badReceipt = { ...receipt, issued_at: "2026-06-09T17:04:39.114" };
    await expect(
      verifyReceipt(badReceipt, keys, {
        expectedWorkspaceId: "ws_1",
        now: new Date("2026-06-09T17:05:00Z"),
      }),
    ).rejects.toThrow("UTC millisecond precision");
  });

  it("rejects receipts from another workspace", async () => {
    const { keysDoc, receipt } = signedPolicyEvalReceipt();
    const keys = loadKeysFromJson(keysDoc);
    await expect(verifyReceipt(receipt, keys, {
      expectedWorkspaceId: "ws_other",
      now: new Date("2026-06-09T17:05:00Z"),
    })).rejects.toThrow("workspace_id");
  });
});
