import { describe, expect, it, vi } from "vitest";
import { Allowly, AllowlyProtocolError } from "../index.js";
import type { ConfirmationStatusResponse, EscalationStatusResponse } from "../index.js";

const common = { authorization_id: "auth_test", action: "github.read", resource: "github:test",
  status: "pending", expires_at: "2099-01-01T00:00:00Z", resolved_at: null,
  source_receipt_id: "rcp_check", resolution_receipt_id: null, authority_status: "none" };
function client(value: unknown) {
  const fetch = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => new Response(JSON.stringify(value), { status: 200 }));
  return { api: new Allowly({ apiKey: "test", fetch }), fetch };
}

describe("review status helpers", () => {
  it("reads opaque confirmation status without exposing a nonce or creating an action", async () => {
    const { api, fetch } = client({ ...common, confirmation_id: "cnf_test", child_authorization_id: null,
      authority_expires_at: null, confirm_nonce: "must-not-be-returned" });
    const value: ConfirmationStatusResponse = await api.confirmations.getStatus("cnf_test");
    expect(value).toMatchObject({ confirmationId: "cnf_test", status: "pending", authorityStatus: "none",
      sourceReceiptId: "rcp_check", childAuthorizationId: null });
    expect(JSON.stringify(value)).not.toContain("must-not-be-returned");
    expect(fetch.mock.calls[0]?.[0]).toBe("https://api.allowly.ai/v1/confirmations/cnf_test/status");
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({ method: "GET" });
  });
  it("reads available and consumed escalation authority separately from recorded approval", async () => {
    for (const authority_status of ["available", "consumed"] as const) {
      const { api } = client({ ...common, escalation_id: "esc_test", status: "approved", authority_status,
        resolved_at: "2026-10-09T12:00:00Z", resolution_receipt_id: "rcp_resolution", consumed_at:
          authority_status === "consumed" ? "2026-10-09T12:01:00Z" : null });
      const value: EscalationStatusResponse = await api.escalations.getStatus("esc_test");
      expect(value.status).toBe("approved");
      expect(value.authorityStatus).toBe(authority_status);
    }
  });
  it("keeps older nullable source/resolution references", async () => {
    const { api } = client({ ...common, escalation_id: "esc_test", source_receipt_id: null, consumed_at: null });
    expect((await api.escalations.getStatus("esc_test")).sourceReceiptId).toBeNull();
  });
  it("refuses nonce paths before making a request", async () => {
    const { api, fetch } = client({});
    await expect(api.confirmations.getStatus("private-nonce")).rejects.toThrow("opaque review ID");
    await expect(api.escalations.getStatus("esc_test/other")).rejects.toThrow("opaque review ID");
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each([{ confirmation_id: "cnf_other" }, { status: "future" }, { authority_status: "consumed" },
    { status: "rejected", authority_status: "available" }, { authority_status: "available" },
    { expires_at: "2026-10-09T12:00:00" }, { resource: undefined }, { source_receipt_id: undefined },
    { status: "approved", authority_status: "available", child_authorization_id: null },
    { resolved_at: "2026-10-09T12:00:00Z" }])("fails closed on malformed status %j", async (change) => {
    const { api } = client({ ...common, confirmation_id: "cnf_test", child_authorization_id: null,
      authority_expires_at: null, ...change });
    await expect(api.confirmations.getStatus("cnf_test")).rejects.toBeInstanceOf(AllowlyProtocolError);
  });
});

describe("readiness", () => {
  it("returns readiness only for the explicit runtime ready state", async () => {
    expect(await client({ status: "ready", database: "ok" }).api.readiness()).toBe(true);
    expect(await client({ status: "degraded" }).api.readiness()).toBe(false);
    await expect(client({ status: true }).api.readiness()).rejects.toBeInstanceOf(AllowlyProtocolError);
    await expect(client([]).api.readiness()).rejects.toBeInstanceOf(AllowlyProtocolError);
  });
});
