import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { Allowly, AllowlyAPIError, AllowlyProtocolError, AllowlyTransportError } from "../index.js";

const BASE = "https://api.example.com";
const REQUEST = "Reply to ticket:one with a refund of 0 dollars.";
const OPTIONS = { agentName: "Support agent", request: REQUEST, idempotencyKey: "initial" };
function response() {
  return {
    authorization_id: "auth_resolved", engine_version: "sha256:" + "a".repeat(64),
    results: { "ticket.reply": { decision: "allow", reason: "authorization_granted_action_active",
      receipt: { status: "pending", receipt_id: "rcp_one", ready_at_estimate: null, url: BASE + "/v1/receipts/rcp_one" } } },
    parse: { id: "parse_one", agent_name: "Support agent",
      policy_ref: { policy_id: "support", policy_version: 1, definition_sha256: "b".repeat(64) },
      parsed_request: { actions: ["ticket.reply"], resource: "ticket:one", context: { amount_micros: 0 } },
      request_sha256: createHash("sha256").update(REQUEST).digest("hex"),
      model: "gemini-3.5-flash", model_version: "version-one", expires_at: "2026-11-01T00:00:00Z" },
  };
}
function http(status: number, value: unknown) {
  return { ok: status >= 200 && status < 300, status, redirected: false,
    headers: new Headers({ "X-Allowly-Billing-Warning": "near_quota" }), json: async () => value };
}
function client(fetch: typeof globalThis.fetch, extra = {}) {
  return new Allowly({ apiKey: "key", baseUrl: BASE, fetch, fallbackByAction: { "ticket.reply": "fail_open" }, ...extra });
}

describe("text checks", () => {
  it("checks then resumes the identical parsed payload with cost zero and fresh idempotency", async () => {
    const fetch = vi.fn().mockResolvedValue(http(200, response())), api = client(fetch);
    const timeout = vi.spyOn(AbortSignal, "timeout");
    try {
      const initial = await api.checkTextByAgent({ ...OPTIONS, estimatedCostMicros: 0, sessionId: "session-one", clientTimestamp: new Date("2026-10-31T00:00:00Z") });
      const resumed = await api.recheckTextByAgent({ agentName: OPTIONS.agentName, parseId: initial.parse.id, idempotencyKey: "resume" });
      expect(initial.parse.parsedRequest).toEqual(response().parse.parsed_request);
      expect(resumed.parse).toEqual(initial.parse);
      expect(resumed.results["ticket.reply"].decision).toBe("allow");
      expect(initial.billingWarning).toBe("near_quota");
      expect(fetch.mock.calls.map(call => call[0])).toEqual([BASE + "/v1/agent-check/text", BASE + "/v1/agent-check/text/parse_one"]);
      expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ agent_name: "Support agent", request: REQUEST,
        session_id: "session-one", estimated_cost_micros: 0, client_timestamp: "2026-10-31T00:00:00.000Z" });
      expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({ agent_name: "Support agent" });
      expect(fetch.mock.calls[0][1].headers).toEqual({ Authorization: "Bearer key", "Content-Type": "application/json", "Idempotency-Key": "initial" });
      expect(fetch.mock.calls[1][1].headers["Idempotency-Key"]).toBe("resume");
      expect(timeout).toHaveBeenCalledWith(35_000);
      expect(timeout).toHaveBeenCalledWith(1000);
    } finally { timeout.mockRestore(); }
  });

  it("honors an explicit shorter initial timeout", async () => {
    const timeout = vi.spyOn(AbortSignal, "timeout");
    try {
      await client(vi.fn().mockResolvedValue(http(200, response()))).checkTextByAgent({ ...OPTIONS, timeoutMs: 500 });
      expect(timeout).toHaveBeenCalledWith(500);
    } finally { timeout.mockRestore(); }
  });

  it.each<Array<(value: any) => void>[number]>([
    p => delete p.parse, p => p.parse.extra = true, p => p.parse.agent_name = "Other agent",
    p => p.parse.request_sha256 = "c".repeat(64), p => p.parse.expires_at = "2026-02-30T00:00:00Z",
    p => p.parse.model_version = null, p => p.parse.policy_ref.definition_sha256 = "bad",
    p => p.parse.parsed_request.actions = ["ticket.reply", "customer.delete"],
    p => { p.parse.parsed_request.actions = ["ticket.reply", "customer.delete"]; p.results["customer.delete"] = p.results["ticket.reply"]; },
    p => p.parse.parsed_request.resource = null,
    p => p.parse.parsed_request.context.amount_micros = 2 ** 53,
    p => p.parse.parsed_request.context = { text: "x".repeat(4096) },
    p => p.parse.parsed_request.context = { nested: { value: 1 } },
    p => p.parse.parsed_request.context = { nested: [[1]] },
    p => p.parse.parsed_request.context = { text: "unsafe\0text" },
    p => p.parse.parsed_request.context = Object.fromEntries(Array.from({ length: 24 }, (_, i) => [String(i), i])),
    p => p.parse.parsed_request.extra = true, p => p.authorization_id = " auth_other",
    p => p.results["customer.delete"] = p.results["ticket.reply"],
    p => p.results["ticket.reply"].decision = "maybe", p => p.results["ticket.reply"].receipt = { status: "unknown" },
  ])("rejects an unbound or malformed response without availability fallback %#", async edit => {
    const payload = response(); edit(payload);
    await expect(client(vi.fn().mockResolvedValue(http(200, payload))).checkTextByAgent(OPTIONS)).rejects.toBeInstanceOf(AllowlyProtocolError);
  });

  it("rejects a different saved parse ID", async () => {
    await expect(client(vi.fn().mockResolvedValue(http(200, response()))).recheckTextByAgent({ agentName: OPTIONS.agentName, parseId: "parse_other", idempotencyKey: "resume" })).rejects.toBeInstanceOf(AllowlyProtocolError);
  });

  it.each([[422, "text_parse_incomplete"], [429, "text_parse_quota_exceeded"],
    [503, "text_parser_busy"], [503, "text_parser_unavailable"]] as const)("propagates HTTP %i %s once from both routes", async (status, code) => {
    const fetch = vi.fn().mockResolvedValue(http(status, { error: { code, message: "Check stopped", fields: [{ field: "amount_micros", message: "required" }] } }));
    const api = client(fetch);
    await expect(api.checkTextByAgent(OPTIONS)).rejects.toMatchObject({ name: "AllowlyAPIError", status, code, retryAfterSeconds: undefined,
      fields: [{ field: "amount_micros", message: "required" }] });
    expect(fetch).toHaveBeenCalledTimes(1);
    const recheck = api.recheckTextByAgent({ agentName: OPTIONS.agentName, parseId: "parse_one", idempotencyKey: "resume" });
    await expect(recheck).rejects.toBeInstanceOf(AllowlyAPIError);
    await expect(recheck).rejects.toMatchObject({
      name: "AllowlyAPIError", status, code, retryAfterSeconds: undefined,
    });
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls.map(call => [call[0], call[1].method])).toEqual([
      [BASE + "/v1/agent-check/text", "POST"], [BASE + "/v1/agent-check/text/parse_one", "POST"],
    ]);
  });

  it.each(["initial", "recheck"])("never falls back on transport or invokes identity on %s", async method => {
    const fetch = vi.fn().mockRejectedValue(new TypeError("offline"));
    const call = (api: Allowly) => method === "initial" ? api.checkTextByAgent(OPTIONS)
      : api.recheckTextByAgent({ agentName: OPTIONS.agentName, parseId: "parse_one", idempotencyKey: "resume" });
    await expect(call(client(fetch))).rejects.toBeInstanceOf(AllowlyTransportError);
    const supplier = vi.fn().mockReturnValue("identity");
    await expect(call(client(fetch, { agentTokenSupplier: supplier }))).rejects.toThrow("configured agent identity");
    expect(supplier).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([" ", "🙂".repeat(4097), "unsafe\0text"])("rejects blank or excessive UTF-8 input", async request => {
    const fetch = vi.fn();
    await expect(client(fetch).checkTextByAgent({ ...OPTIONS, request })).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
});
