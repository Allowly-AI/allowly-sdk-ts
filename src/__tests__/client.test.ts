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

function checkBody(action: string, result: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return {
    authorization_id: "auth_1",
    user_id: "u1",
    agent_id: "a1",
    authorization_expires_at: "2026-12-31T00:00:00Z",
    engine_version: "2026-04-19.1",
    ...extra,
    results: { [action]: result },
  };
}

describe("Allowly.check", () => {
  it("rejects insecure base URLs by default", () => {
    expect(() => new Allowly({ apiKey: "test-key", baseUrl: "http://api.example.com" }))
      .toThrow("HTTPS");
  });

  it("allows insecure base URLs only with explicit opt-in", () => {
    expect(() =>
      new Allowly({
        apiKey: "test-key",
        baseUrl: "http://localhost:8000",
        dangerouslyAllowInsecureBaseUrl: true,
      }),
    ).not.toThrow();
  });

  it("returns allow with pending receipt envelope", async () => {
    const fetch = makeFetch(200, checkBody("email.read", {
      decision: "allow",
      reason: "authorization_granted_action_active",
      receipt: PENDING_RECEIPT,
    }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.check({ authorizationId: "auth_1", actions: ["email.read"] });
    const action = res.results["email.read"];

    expect(action.decision).toBe("allow");
    expect(action.isFallback).toBe(false);
    expect(action.fallbackMode).toBeNull();
    expect(action.budget).toBeNull();
    expect(action.policyEval).toBeNull();
    expect(action.receipt?.status).toBe("pending");
    if (action.receipt?.status === "pending") {
      expect(action.receipt.receiptId).toBe("rcp_abc");
    }
    if (action.decision === "allow") {
      expect(res.userId).toBe("u1");
      expect(res.authorizationId).toBe("auth_1");
    }
  });

  it("returns deny", async () => {
    const fetch = makeFetch(200, checkBody("email.send", {
      decision: "deny",
      reason: "authorization_superseded",
      superseded_by: "auth_new",
      receipt: PENDING_RECEIPT,
    }, { authorization_id: "auth_nope", user_id: null, agent_id: null, authorization_expires_at: null }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.check({ authorizationId: "auth_nope", actions: ["email.send"] });
    const action = res.results["email.send"];
    expect(action.decision).toBe("deny");
    expect(action.reason).toBe("authorization_superseded");
    if (action.decision === "deny") expect(action.supersededBy).toBe("auth_new");
  });

  it("returns confirm with nonce", async () => {
    const fetch = makeFetch(200, checkBody("email.send", {
      decision: "confirm", reason: "action_requires_user_confirmation",
      confirm_nonce: "cnf_abc", confirm_expires_at: "2026-04-20T00:15:00Z",
      confirm_prompt_hint: "email.send",
      receipt: PENDING_RECEIPT,
    }, { authorization_id: "auth_2" }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.check({ authorizationId: "auth_2", actions: ["email.send"] });
    const action = res.results["email.send"];
    expect(action.decision).toBe("confirm");
    if (action.decision === "confirm") expect(action.confirmNonce).toBe("cnf_abc");
  });

  it("parses policy_eval evidence on conditional decisions", async () => {
    const fetch = makeFetch(200, checkBody("hiring.publish_feedback", {
      decision: "confirm",
      reason: "condition_requires_user_confirmation",
      confirm_nonce: "cnf_policy",
      confirm_expires_at: "2026-04-20T00:15:00Z",
      confirm_prompt_hint: "hiring.publish_feedback",
      policy_eval: {
        matched_condition: {
          field: "checks_failed",
          op: "in",
          value: ["pii_detected", "tone_flag"],
        },
        field_value: "pii_detected",
      },
      receipt: PENDING_RECEIPT,
    }, { authorization_id: "auth_policy" }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });

    const res = await client.check({ authorizationId: "auth_policy", actions: ["hiring.publish_feedback"] });
    const action = res.results["hiring.publish_feedback"];

    expect(action.decision).toBe("confirm");
    expect(action.policyEval).toEqual({
      matchedCondition: {
        field: "checks_failed",
        op: "in",
        value: ["pii_detected", "tone_flag"],
      },
      fieldValue: "pii_detected",
    });
  });

  it("returns escalate with escalation metadata", async () => {
    const fetch = makeFetch(200, checkBody("candidate.delete", {
      decision: "escalate",
      reason: "escalation_required",
      escalation_id: "esc_abc",
      escalation_to: "compliance",
      escalation_expires_at: "2026-04-21T17:00:00Z",
      escalation: {
        escalation_id: "esc_abc",
        status: "pending",
        escalation_to: "compliance",
        expires_at: "2026-04-21T17:00:00Z",
      },
      receipt: PENDING_RECEIPT,
    }, { authorization_id: "auth_esc" }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.check({ authorizationId: "auth_esc", actions: ["candidate.delete"] });
    const action = res.results["candidate.delete"];
    expect(action.decision).toBe("escalate");
    if (action.decision === "escalate") {
      expect(action.escalationId).toBe("esc_abc");
      expect(action.escalationTo).toBe("compliance");
      expect(action.escalation?.status).toBe("pending");
    }
  });

  it("throws AllowlyAPIError on 401", async () => {
    const fetch = makeFetch(401, { error: { code: "unauthorized", message: "Invalid or revoked API key" } });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    await expect(client.check({ authorizationId: "auth_1", actions: ["x"] })).rejects.toThrow(AllowlyAPIError);
    await expect(client.check({ authorizationId: "auth_1", actions: ["x"] })).rejects.toMatchObject({ status: 401, code: "unauthorized" });
  });

  it("sends correct Authorization header", async () => {
    const fetch = makeFetch(200, checkBody("x", { decision: "deny", reason: "authorization_not_found", receipt: PENDING_RECEIPT }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    await client.check({ authorizationId: "auth_1", actions: ["x"] });
    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect((init as RequestInit).headers).toMatchObject({ Authorization: "Bearer test-key" });
  });

  it("does not send session_id", async () => {
    const fetch = makeFetch(200, checkBody("x", { decision: "deny", reason: "authorization_not_found", receipt: PENDING_RECEIPT }));
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    await client.check({ authorizationId: "auth_1", actions: ["x"], estimatedCostMicros: 12345 });
    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body).not.toHaveProperty("session_id");
    expect(body.estimated_cost_micros).toBe(12345);
    expect(body.actions).toEqual(["x"]);
  });

  it("parses budget results", async () => {
    const fetch = makeFetch(200, checkBody("llm.enrich", {
      decision: "allow",
      reason: "authorization_granted_action_active",
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
      actions: ["llm.enrich"],
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
      fallbackByAction: { "public.web.search": "fail_open" },
    });

    const res = await client.check({ authorizationId: "auth_1", actions: ["public.web.search"] });
    const action = res.results["public.web.search"];

    expect(action.decision).toBe("allow");
    expect(action.reason).toBe("fallback_open_timeout");
    expect(action.isFallback).toBe(true);
    expect(action.fallbackMode).toBe("fail_open");
    expect(action.receipt).toBeNull();
    expect(action.budget).toBeNull();
    expect(res.authorizationId).toBe("auth_1");
    expect(res.engineVersion).toBe("sdk_fallback");
  });

  it("uses default fail_closed fallback for unmapped timeout action", async () => {
    const abortError = Object.assign(new Error("aborted"), { name: "AbortError" });
    const fetch = vi.fn().mockRejectedValue(abortError);
    const client = new Allowly({ ...CLIENT_OPTS, fetch, checkTimeoutMs: 1 });

    const res = await client.check({ authorizationId: "auth_1", actions: ["email.send"] });
    const action = res.results["email.send"];

    expect(action.decision).toBe("deny");
    expect(action.reason).toBe("fallback_closed_timeout");
    expect(action.isFallback).toBe(true);
    expect(action.fallbackMode).toBe("fail_closed");
    expect(action.receipt).toBeNull();
  });

  it("returns fail_open fallback on connection error", async () => {
    const fetch = vi.fn().mockRejectedValue(new TypeError("offline"));
    const client = new Allowly({
      ...CLIENT_OPTS,
      fetch,
      fallbackByAction: { "public.web.search": "fail_open" },
    });

    const res = await client.check({ authorizationId: "auth_1", actions: ["public.web.search"] });
    const action = res.results["public.web.search"];

    expect(action.decision).toBe("allow");
    expect(action.reason).toBe("fallback_open_unreachable");
    expect(action.isFallback).toBe(true);
    expect(action.fallbackMode).toBe("fail_open");
    expect(action.receipt).toBeNull();
  });

  it("returns fail_closed fallback on 5xx", async () => {
    const fetch = makeFetch(503, { error: { code: "unavailable", message: "try again" } });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });

    const res = await client.check({ authorizationId: "auth_1", actions: ["email.send"] });
    const action = res.results["email.send"];

    expect(action.decision).toBe("deny");
    expect(action.reason).toBe("fallback_closed_unreachable");
    expect(action.isFallback).toBe(true);
    expect(action.fallbackMode).toBe("fail_closed");
    expect(action.receipt).toBeNull();
  });

  it("supports mixed fallback modes in one check", async () => {
    const fetch = vi.fn().mockRejectedValue(new TypeError("offline"));
    const client = new Allowly({
      ...CLIENT_OPTS,
      fetch,
      fallbackByAction: {
        "public.web.search": "fail_open",
        "email.send": "fail_closed",
      },
    });

    const res = await client.check({
      authorizationId: "auth_1",
      actions: ["public.web.search", "email.send"],
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
      fallbackByAction: { "public.web.search": "fail_open" },
    });

    await expect(client.check({ authorizationId: "auth_1", actions: ["public.web.search"] }))
      .rejects.toMatchObject({ status: 429, code: "quota_exceeded" });
  });

  it("does not cache fallback results", async () => {
    const fetch = vi.fn().mockRejectedValue(new TypeError("offline"));
    const client = new Allowly({
      ...CLIENT_OPTS,
      fetch,
      fallbackByAction: { "public.web.search": "fail_open" },
    });

    await client.check({ authorizationId: "auth_1", actions: ["public.web.search"] });
    await client.check({ authorizationId: "auth_1", actions: ["public.web.search"] });

    expect(fetch).toHaveBeenCalledTimes(2);
  });
});

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
      actions: [{ name: "email.read" }],
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
      actions: ["llm.enrich"],
      budgetLimitMicros: 50_000_000,
    });

    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.budget_limit_micros).toBe(50_000_000);
    expect(res.authorizationId).toBe("auth_budget");
    expect(res.budgetLimitMicros).toBe(50_000_000);
    expect(res.budgetSpentMicros).toBe(0);
  });

  it("sends and parses escalation fields", async () => {
    const fetch = makeFetch(201, {
      authorization_id: "auth_esc",
      created_at: "2026-04-20T00:00:00Z",
      expires_at: "2026-12-31T00:00:00Z",
      requires_escalation_for: ["candidate.delete"],
      escalation_targets: { "candidate.delete": "compliance" },
      receipt: PENDING_RECEIPT,
    });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.authorizations.create({
      userId: "u1",
      agentId: "a1",
      actions: ["candidate.delete"],
      requiresEscalationFor: ["candidate.delete"],
      escalationTargets: { "candidate.delete": "compliance" },
    });

    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.requires_escalation_for).toEqual(["candidate.delete"]);
    expect(body.escalation_targets).toEqual({ "candidate.delete": "compliance" });
    expect(res.requiresEscalationFor).toEqual(["candidate.delete"]);
    expect(res.escalationTargets).toEqual({ "candidate.delete": "compliance" });
  });

  it("sends supersession lineage on create", async () => {
    const fetch = makeFetch(201, {
      authorization_id: "auth_new",
      created_at: "2026-04-20T00:00:00Z",
      expires_at: "2026-12-31T00:00:00Z",
      receipt: PENDING_RECEIPT,
    });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });

    await client.authorizations.create({
      userId: "u1",
      agentId: "a1",
      actions: ["email.read"],
      replaces: "auth_prev",
    });

    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.replaces).toBe("auth_prev");
  });

  it("does not send session_id", async () => {
    const fetch = makeFetch(201, {
      authorization_id: "auth_new", created_at: "2026-04-20T00:00:00Z",
      expires_at: "2026-12-31T00:00:00Z", receipt: PENDING_RECEIPT,
    });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    await client.authorizations.create({
      userId: "u1", agentId: "a1", actions: ["email.read"], expiresAt: "2026-12-31T00:00:00Z",
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
      fallbackByAction: { "email.read": "fail_open" },
    });

    await expect(client.authorizations.create({
      userId: "u1",
      agentId: "a1",
      actions: ["email.read"],
    })).rejects.toMatchObject({ status: 503, code: "unavailable" });
  });
});

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

  it("sends supersededBy on revoke", async () => {
    const fetch = makeFetch(200, {
      authorization_id: "auth_123", revoked_at: "2026-05-01T09:00:00Z", receipt: PENDING_RECEIPT,
    });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });

    await client.authorizations.revoke("auth_123", { supersededBy: "auth_456" });

    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.superseded_by).toBe("auth_456");
  });
});

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

describe("Allowly.escalations", () => {
  it("approves an escalation", async () => {
    const fetch = makeFetch(200, {
      escalation_id: "esc_abc",
      status: "approved",
      resolved_by: "compliance:1",
      resolved_at: "2026-04-21T16:15:00Z",
      receipt: PENDING_RECEIPT,
    });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.escalations.approve("esc_abc", { resolvedBy: "compliance:1", note: "ok" });

    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body).toEqual({ resolution: "approved", resolved_by: "compliance:1", note: "ok" });
    expect(res.escalationId).toBe("esc_abc");
    expect(res.status).toBe("approved");
    expect(res.receipt?.status).toBe("pending");
  });

  it("handles idempotent reject without a new receipt", async () => {
    const fetch = makeFetch(200, {
      escalation_id: "esc_abc",
      status: "rejected",
      resolved_by: "compliance:1",
      resolved_at: "2026-04-21T16:15:00Z",
      receipt: null,
    });
    const client = new Allowly({ ...CLIENT_OPTS, fetch });
    const res = await client.escalations.reject("esc_abc", { resolvedBy: "compliance:1" });
    expect(res.status).toBe("rejected");
    expect(res.receipt).toBeNull();
  });
});

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
