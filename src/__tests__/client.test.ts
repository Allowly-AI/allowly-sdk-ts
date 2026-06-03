import { describe, it, expect, vi } from "vitest";
import { Allowly, AllowlyAPIError } from "../index.js";

const BASE = "https://api.example.com";
const CLIENT_OPTS = { apiKey: "test-key", baseUrl: BASE };

const PENDING_RECEIPT = {
  status: "pending",
  receipt_id: "rcp_abc",
  ready_at_estimate: "2026-04-21T14:32:18.482Z",
  url: `${BASE}/v1/receipts/rcp_abc`,
};

function makeFetch(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

function checkBody(scope: string, result: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return {
    authorization_id: "auth_1",
    user_id: "u1",
    agent_id: "a1",
    authorization_expires_at: "2026-12-31T00:00:00Z",
    policy_version: "2026-04-19.1",
    ...extra,
    results: { [scope]: result },
  };
}

// ---------------------------------------------------------------------------
// check()
// ---------------------------------------------------------------------------

describe("Allowly.check", () => {
  it("returns allow with pending receipt envelope", async () => {
    const fetch = makeFetch(200, checkBody("email.read", {
      decision: "allow",
      reason: "authorization_granted_scope_active",
      receipt: PENDING_RECEIPT,
    }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.check({ authorizationId: "auth_1", scopes: ["email.read"] });
    const scope = res.results["email.read"];

    expect(scope.decision).toBe("allow");
    expect(scope.isFallback).toBe(false);
    expect(scope.fallbackMode).toBeNull();
    expect(scope.budget).toBeNull();
    expect(scope.receipt?.status).toBe("pending");
    if (scope.receipt?.status === "pending") {
      expect(scope.receipt.receiptId).toBe("rcp_abc");
    }
    if (scope.decision === "allow") {
      expect(res.userId).toBe("u1");
      expect(res.authorizationId).toBe("auth_1");
    }
  });

  it("returns deny", async () => {
    const fetch = makeFetch(200, checkBody("email.send", {
      decision: "deny", reason: "authorization_not_found", receipt: PENDING_RECEIPT,
    }, { authorization_id: "auth_nope", user_id: null, agent_id: null, authorization_expires_at: null }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.check({ authorizationId: "auth_nope", scopes: ["email.send"] });
    expect(res.results["email.send"].decision).toBe("deny");
    expect(res.results["email.send"].reason).toBe("authorization_not_found");
  });

  it("returns confirm with nonce", async () => {
    const fetch = makeFetch(200, checkBody("email.send", {
      decision: "confirm", reason: "scope_requires_user_confirmation",
      confirm_nonce: "cnf_abc", confirm_expires_at: "2026-04-20T00:15:00Z",
      confirm_prompt_hint: "email.send",
      receipt: PENDING_RECEIPT,
    }, { authorization_id: "auth_2" }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.check({ authorizationId: "auth_2", scopes: ["email.send"] });
    const scope = res.results["email.send"];
    expect(scope.decision).toBe("confirm");
    if (scope.decision === "confirm") expect(scope.confirmNonce).toBe("cnf_abc");
  });

  it("throws AllowlyAPIError on 401", async () => {
    const fetch = makeFetch(401, { error: { code: "unauthorized", message: "Invalid or revoked API key" } });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    await expect(client.check({ authorizationId: "auth_1", scopes: ["x"] })).rejects.toThrow(AllowlyAPIError);
    await expect(client.check({ authorizationId: "auth_1", scopes: ["x"] })).rejects.toMatchObject({ status: 401, code: "unauthorized" });
  });

  it("sends correct Authorization header", async () => {
    const fetch = makeFetch(200, checkBody("x", { decision: "deny", reason: "authorization_not_found", receipt: PENDING_RECEIPT }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    await client.check({ authorizationId: "auth_1", scopes: ["x"] });
    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect((init as RequestInit).headers).toMatchObject({ Authorization: "Bearer test-key" });
  });

  it("does not send session_id", async () => {
    const fetch = makeFetch(200, checkBody("x", { decision: "deny", reason: "authorization_not_found", receipt: PENDING_RECEIPT }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    await client.check({ authorizationId: "auth_1", scopes: ["x"], estimatedCostMicros: 12345 });
    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body).not.toHaveProperty("session_id");
    expect(body.estimated_cost_micros).toBe(12345);
    expect(body.scopes).toEqual(["x"]);
  });

  it("parses budget results", async () => {
    const fetch = makeFetch(200, checkBody("llm.enrich", {
      decision: "allow",
      reason: "authorization_granted_scope_active",
      receipt: PENDING_RECEIPT,
      budget: {
        limit_micros: 1_000_000,
        spent_micros: 100_000,
        estimated_cost_micros: 25_000,
        spent_after_micros: 125_000,
      },
    }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.check({
      authorizationId: "auth_1",
      scopes: ["llm.enrich"],
      estimatedCostMicros: 25_000,
    });
    expect(res.results["llm.enrich"].budget).toEqual({
      limitMicros: 1_000_000,
      spentMicros: 100_000,
      estimatedCostMicros: 25_000,
      spentAfterMicros: 125_000,
    });
  });

  it("returns fail_open fallback on timeout", async () => {
    const abortError = Object.assign(new Error("aborted"), { name: "AbortError" });
    const fetch = vi.fn().mockRejectedValue(abortError);
    const client = new Allowly({
      ...CLIENT_OPTS,
      fetch,
      checkTimeoutMs: 1,
      fallbackByScope: { "public.web.search": "fail_open" },
    });

    const res = await client.check({ authorizationId: "auth_1", scopes: ["public.web.search"] });
    const scope = res.results["public.web.search"];

    expect(scope.decision).toBe("allow");
    expect(scope.reason).toBe("fallback_open_timeout");
    expect(scope.isFallback).toBe(true);
    expect(scope.fallbackMode).toBe("fail_open");
    expect(scope.receipt).toBeNull();
    expect(scope.budget).toBeNull();
    expect(res.authorizationId).toBe("auth_1");
    expect(res.policyVersion).toBe("sdk_fallback");
  });

  it("uses default fail_closed fallback for unmapped timeout scope", async () => {
    const abortError = Object.assign(new Error("aborted"), { name: "AbortError" });
    const fetch = vi.fn().mockRejectedValue(abortError);
    const client = new Allowly({ ...CLIENT_OPTS, fetch, checkTimeoutMs: 1 });

    const res = await client.check({ authorizationId: "auth_1", scopes: ["email.send"] });
    const scope = res.results["email.send"];

    expect(scope.decision).toBe("deny");
    expect(scope.reason).toBe("fallback_closed_timeout");
    expect(scope.isFallback).toBe(true);
    expect(scope.fallbackMode).toBe("fail_closed");
    expect(scope.receipt).toBeNull();
  });

  it("returns fail_open fallback on connection error", async () => {
    const fetch = vi.fn().mockRejectedValue(new TypeError("offline"));
    const client = new Allowly({
      ...CLIENT_OPTS,
      fetch,
      fallbackByScope: { "public.web.search": "fail_open" },
    });

    const res = await client.check({ authorizationId: "auth_1", scopes: ["public.web.search"] });
    const scope = res.results["public.web.search"];

    expect(scope.decision).toBe("allow");
    expect(scope.reason).toBe("fallback_open_unreachable");
    expect(scope.isFallback).toBe(true);
    expect(scope.fallbackMode).toBe("fail_open");
    expect(scope.receipt).toBeNull();
  });

  it("returns fail_closed fallback on 5xx", async () => {
    const fetch = makeFetch(503, { error: { code: "unavailable", message: "try again" } });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });

    const res = await client.check({ authorizationId: "auth_1", scopes: ["email.send"] });
    const scope = res.results["email.send"];

    expect(scope.decision).toBe("deny");
    expect(scope.reason).toBe("fallback_closed_unreachable");
    expect(scope.isFallback).toBe(true);
    expect(scope.fallbackMode).toBe("fail_closed");
    expect(scope.receipt).toBeNull();
  });

  it("supports mixed fallback modes in one check", async () => {
    const fetch = vi.fn().mockRejectedValue(new TypeError("offline"));
    const client = new Allowly({
      ...CLIENT_OPTS,
      fetch,
      fallbackByScope: {
        "public.web.search": "fail_open",
        "email.send": "fail_closed",
      },
    });

    const res = await client.check({
      authorizationId: "auth_1",
      scopes: ["public.web.search", "email.send"],
    });

    expect(res.results["public.web.search"].decision).toBe("allow");
    expect(res.results["public.web.search"].reason).toBe("fallback_open_unreachable");
    expect(res.results["email.send"].decision).toBe("deny");
    expect(res.results["email.send"].reason).toBe("fallback_closed_unreachable");
  });

  it("does not fallback on 429", async () => {
    const fetch = makeFetch(429, { error: { code: "quota_exceeded", message: "quota exceeded" } });
    const client = new Allowly({
      ...CLIENT_OPTS,
      fetch,
      fallbackByScope: { "public.web.search": "fail_open" },
    });

    await expect(client.check({ authorizationId: "auth_1", scopes: ["public.web.search"] }))
      .rejects.toMatchObject({ status: 429, code: "quota_exceeded" });
  });

  it("does not cache fallback results", async () => {
    const fetch = vi.fn().mockRejectedValue(new TypeError("offline"));
    const client = new Allowly({
      ...CLIENT_OPTS,
      fetch,
      fallbackByScope: { "public.web.search": "fail_open" },
    });

    await client.check({ authorizationId: "auth_1", scopes: ["public.web.search"] });
    await client.check({ authorizationId: "auth_1", scopes: ["public.web.search"] });

    expect(fetch).toHaveBeenCalledTimes(2);
  });
});

// ---------------------------------------------------------------------------
// authorizations.create()
// ---------------------------------------------------------------------------

describe("Allowly.authorizations.create", () => {
  it("returns AuthorizationCreateResponse with receipt envelope", async () => {
    const fetch = makeFetch(201, {
      authorization_id: "auth_new",
      created_at: "2026-04-20T00:00:00Z",
      expires_at: "2026-12-31T00:00:00Z",
      receipt: PENDING_RECEIPT,
    });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.authorizations.create({
      userId: "u1", agentId: "a1",
      scopes: [{ name: "email.read" }],
      expiresAt: "2026-12-31T00:00:00Z",
    });
    expect(res.authorizationId).toBe("auth_new");
    expect(res.receipt.status).toBe("pending");
    expect(res.receipt.receiptId).toBe("rcp_abc");
  });

  it("sends and parses budget fields", async () => {
    const fetch = makeFetch(201, {
      authorization_id: "auth_budget",
      created_at: "2026-04-20T00:00:00Z",
      expires_at: "2026-12-31T00:00:00Z",
      budget_limit_micros: 50_000_000,
      budget_spent_micros: 0,
      receipt: PENDING_RECEIPT,
    });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.authorizations.create({
      userId: "u1",
      agentId: "a1",
      scopes: ["llm.enrich"],
      budgetLimitMicros: 50_000_000,
    });

    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.budget_limit_micros).toBe(50_000_000);
    expect(res.authorizationId).toBe("auth_budget");
    expect(res.budgetLimitMicros).toBe(50_000_000);
    expect(res.budgetSpentMicros).toBe(0);
  });

  it("does not send session_id", async () => {
    const fetch = makeFetch(201, {
      authorization_id: "auth_new", created_at: "2026-04-20T00:00:00Z",
      expires_at: "2026-12-31T00:00:00Z", receipt: PENDING_RECEIPT,
    });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    await client.authorizations.create({
      userId: "u1", agentId: "a1", scopes: ["email.read"], expiresAt: "2026-12-31T00:00:00Z",
    });
    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body).not.toHaveProperty("session_id");
  });

  it("does not use fallback behavior", async () => {
    const fetch = makeFetch(503, { error: { code: "unavailable", message: "try again" } });
    const client = new Allowly({
      ...CLIENT_OPTS,
      fetch,
      fallbackByScope: { "email.read": "fail_open" },
    });

    await expect(client.authorizations.create({
      userId: "u1",
      agentId: "a1",
      scopes: ["email.read"],
    })).rejects.toMatchObject({ status: 503, code: "unavailable" });
  });
});

// ---------------------------------------------------------------------------
// authorizations.revoke()
// ---------------------------------------------------------------------------

describe("Allowly.authorizations.revoke", () => {
  it("returns AuthorizationRevokeResponse with receipt", async () => {
    const fetch = makeFetch(200, {
      authorization_id: "auth_123", revoked_at: "2026-05-01T09:00:00Z", receipt: PENDING_RECEIPT,
    });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.authorizations.revoke("auth_123", { revokedBy: "user" });
    expect(res.authorizationId).toBe("auth_123");
    expect(res.revokedAt).toBe("2026-05-01T09:00:00Z");
    expect(res.receipt.status).toBe("pending");
  });
});

// ---------------------------------------------------------------------------
// confirmations.approve()
// ---------------------------------------------------------------------------

describe("Allowly.confirmations", () => {
  it("approves a confirmation", async () => {
    const fetch = makeFetch(200, { decision: "approved", authorization_id: "auth_xyz", expires_at: "2026-04-20T00:01:00Z" });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.confirmations.approve("nonce123", { approved: true });
    expect(res.decision).toBe("approved");
    expect(res.authorizationId).toBe("auth_xyz");
  });

  it("handles denied_by_user", async () => {
    const fetch = makeFetch(200, { decision: "denied_by_user" });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.confirmations.approve("nonce123", { approved: false });
    expect(res.decision).toBe("denied_by_user");
  });
});

// ---------------------------------------------------------------------------
// receipts.get()
// ---------------------------------------------------------------------------

describe("Allowly.receipts.get", () => {
  it("returns pending envelope", async () => {
    const fetch = makeFetch(200, PENDING_RECEIPT);
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const r = await client.receipts.get("rcp_abc");
    expect(r.status).toBe("pending");
    if (r.status === "pending") expect(r.receiptId).toBe("rcp_abc");
  });

  it("returns signed envelope", async () => {
    const signedReceipt = { version: "1.0", receipt_id: "rcp_abc", decision: "allow", signature: { alg: "Ed25519", key_id: "k", value: "sig" } };
    const fetch = makeFetch(200, { status: "signed", receipt: signedReceipt });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const r = await client.receipts.get("rcp_abc");
    expect(r.status).toBe("signed");
    if (r.status === "signed") expect(r.receipt).toEqual(signedReceipt);
  });
});

// ---------------------------------------------------------------------------
// receipts.fetchSigned()
// ---------------------------------------------------------------------------

describe("Allowly.receipts.fetchSigned", () => {
  it("polls until signed and returns receipt dict", async () => {
    const signedReceipt = { version: "1.0", receipt_id: "rcp_abc" };
    let call = 0;
    const fetch = vi.fn().mockImplementation(async () => {
      call++;
      const body = call < 2
        ? PENDING_RECEIPT
        : { status: "signed", receipt: signedReceipt };
      return { ok: true, status: 200, json: async () => body };
    });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const result = await client.receipts.fetchSigned("rcp_abc", { pollInterval: 0.001, timeout: 5 });
    expect(result).toEqual(signedReceipt);
    expect(call).toBe(2);
  });

  it("throws on timeout", async () => {
    const fetch = makeFetch(200, PENDING_RECEIPT);
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    await expect(
      client.receipts.fetchSigned("rcp_abc", { pollInterval: 0.001, timeout: 0.005 })
    ).rejects.toThrow("not signed after");
  });
});
