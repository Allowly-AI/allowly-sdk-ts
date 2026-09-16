import { describe, expect, it, vi } from "vitest";
import {
  AllowlyAPIError,
  AllowlyProtocolError,
  SealWebhookClient,
} from "../index.js";

const BASE = "https://api.example.com";
const TOKEN = "seal_w1_s001_test-token";
const WEBHOOK_URL = `${BASE}/v1/seal/webhooks?token=${TOKEN}`;

function delivery(overrides: Record<string, unknown> = {}) {
  return {
    attempt_id: "swd_attempt",
    workspace_id: "ws_test",
    status: "signing",
    received_at: "2026-09-13T12:00:00Z",
    updated_at: "2026-09-13T12:00:01Z",
    profile: "allowly.seal.jcs-sha256.v1",
    record_sha256: "a".repeat(64),
    metadata: null,
    receipt_id: "rcp_test",
    error_code: null,
    status_url: `${BASE}/v1/seal/webhooks/deliveries/swd_attempt?token=${TOKEN}`,
    receipt_url: `${BASE}/v1/seal/webhooks/receipts/rcp_test?token=${TOKEN}`,
    keys_url: `${BASE}/v1/seal/webhooks/keys?token=${TOKEN}`,
    receipt: null,
    ...overrides,
  };
}

function response(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers });
}

describe("SealWebhookClient", () => {
  it("posts exact JSON with idempotency and no API key", async () => {
    const details = {
      type: "invoice",
      reference: "INV-1042",
      statement: "Approved for payment",
    };
    const fetch = vi.fn().mockResolvedValue(response(202, delivery({ metadata: details })));
    const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });
    const raw = '{"event":"created","amount":1.00}';

    const result = await webhook.send(raw, {
      idempotencyKey: "sender-event-7",
      type: "invoice",
      reference: "INV-1042",
      statement: "Approved for payment",
    });

    expect(result).toMatchObject({
      attemptId: "swd_attempt",
      status: "signing",
      metadata: details,
    });
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(WEBHOOK_URL);
    expect(init.body).toBe(raw);
    expect(init.headers).toEqual({
      "Content-Type": "application/json",
      "Idempotency-Key": "sender-event-7",
      "Allowly-Seal-Type": "invoice",
      "Allowly-Seal-Reference": "INV-1042",
      "Allowly-Seal-Statement": "Approved for payment",
    });
    expect(JSON.stringify(init.headers)).not.toContain("Authorization");
    expect(init.redirect).toBe("manual");
  });

  it.each([" leading", "trailing ", "café", "inside\tgap", "x".repeat(257)])(
    "rejects an invalid detail header value %s",
    async (reference) => {
      const fetch = vi.fn();
      const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });

      await expect(webhook.send("{}", { reference })).rejects.toThrow();
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it("fetches scoped status, receipt, and keys from the private URL", async () => {
    const signedReceipt = {
      schema_version: "4",
      receipt_id: "rcp_test",
      workspace_id: "ws_test",
    };
    const fetch = vi.fn()
      .mockResolvedValueOnce(response(200, delivery()))
      .mockResolvedValueOnce(response(200, delivery({
        status: "sealed",
        receipt: signedReceipt,
      })))
      .mockResolvedValueOnce(response(200, { workspace_id: "ws_test", keys: [] }));
    const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });

    await expect(webhook.getDelivery("swd_attempt"))
      .resolves.toMatchObject({ status: "signing" });
    await expect(webhook.getReceipt("rcp_test"))
      .resolves.toMatchObject({ status: "sealed", receipt: signedReceipt });
    await expect(webhook.getKeys())
      .resolves.toEqual({ workspace_id: "ws_test", keys: [] });

    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      `${BASE}/v1/seal/webhooks/deliveries/swd_attempt?token=${TOKEN}`,
      `${BASE}/v1/seal/webhooks/receipts/rcp_test?token=${TOKEN}`,
      `${BASE}/v1/seal/webhooks/keys?token=${TOKEN}`,
    ]);
    for (const [, init] of fetch.mock.calls) {
      expect(JSON.stringify((init as RequestInit).headers ?? {})).not.toContain("Authorization");
    }
  });

  it("keeps API errors typed without including the private token", async () => {
    const fetch = vi.fn().mockResolvedValue(response(429, {
      error: { code: "tier_rate_limit_exceeded", message: "Retry later" },
    }, { "Retry-After": "2" }));
    const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });

    const error = await webhook.send("{}").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AllowlyAPIError);
    expect(error).toMatchObject({ code: "tier_rate_limit_exceeded", retryAfterSeconds: 2 });
    expect(String(error)).not.toContain(TOKEN);
  });

  it("does not expose the private URL from a transport failure", async () => {
    const fetch = vi.fn().mockRejectedValue(new Error(`failed ${WEBHOOK_URL}`));
    const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });

    const error = await webhook.send("{}").catch((caught: unknown) => caught);
    expect(String(error)).not.toContain(TOKEN);
    expect(JSON.stringify(error)).not.toContain(TOKEN);
  });

  it("rejects a signed receipt with mismatched bindings", async () => {
    const fetch = vi.fn().mockResolvedValue(response(200, delivery({
      status: "sealed",
      receipt: {
        schema_version: "4",
        receipt_id: "rcp_other",
        workspace_id: "ws_test",
      },
    })));
    const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });

    await expect(webhook.getReceipt("rcp_test"))
      .rejects.toThrow(AllowlyProtocolError);
  });

  it("rejects an unknown delivery status", async () => {
    const fetch = vi.fn().mockResolvedValue(response(202, delivery({ status: "unknown" })));
    const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });

    await expect(webhook.send("{}"))
      .rejects.toThrow("unknown SEAL webhook status");
  });

  it("defaults missing metadata from older runtimes to null", async () => {
    const body = delivery();
    delete (body as Record<string, unknown>).metadata;
    const fetch = vi.fn().mockResolvedValue(response(202, body));
    const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });

    await expect(webhook.send("{}"))
      .resolves.toMatchObject({ metadata: null });
  });

  it.each(["missing", "null"])(
    "uses signed receipt metadata when top-level metadata is %s",
    async (topLevel) => {
      const signedMetadata = {
        type: "invoice",
        reference: "INV-1042",
        statement: "Approved for payment",
      };
      const body = delivery({
        status: "sealed",
        receipt: {
          schema_version: "4",
          receipt_id: "rcp_test",
          workspace_id: "ws_test",
          context: { seal_metadata: signedMetadata },
        },
      });
      if (topLevel === "missing") delete (body as Record<string, unknown>).metadata;
      else body.metadata = null;
      const fetch = vi.fn().mockResolvedValue(response(200, body));
      const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });

      await expect(webhook.getReceipt("rcp_test"))
        .resolves.toMatchObject({ metadata: signedMetadata });
    },
  );

  it("rejects top-level metadata that conflicts with the signed receipt", async () => {
    const fetch = vi.fn().mockResolvedValue(response(200, delivery({
      status: "sealed",
      metadata: { reference: "UNSIGNED" },
      receipt: {
        schema_version: "4",
        receipt_id: "rcp_test",
        workspace_id: "ws_test",
        context: { seal_metadata: { reference: "SIGNED" } },
      },
    })));
    const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });

    await expect(webhook.getReceipt("rcp_test"))
      .rejects.toThrow(/metadata does not match the signed receipt/);
  });

  it("rejects malformed metadata inside the signed receipt", async () => {
    const fetch = vi.fn().mockResolvedValue(response(200, delivery({
      status: "sealed",
      receipt: {
        schema_version: "4",
        receipt_id: "rcp_test",
        workspace_id: "ws_test",
        context: { seal_metadata: { reference: 42 } },
      },
    })));
    const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });

    await expect(webhook.getReceipt("rcp_test"))
      .rejects.toThrow(/signed SEAL receipt metadata/);
  });

  it.each([
    [["not-an-object"]],
    [{ reference: 42 }],
  ])("rejects malformed present metadata %j", async (metadata) => {
    const fetch = vi.fn().mockResolvedValue(response(202, delivery({ metadata })));
    const webhook = new SealWebhookClient(WEBHOOK_URL, { fetch });

    await expect(webhook.send("{}"))
      .rejects.toThrow(/metadata/);
  });

  it.each([
    ["http://api.example.com/v1/seal/webhooks?token=x", "HTTPS"],
    ["https://api.example.com/v1/seal?token=x", "webhook endpoint"],
    ["https://api.example.com/v1/seal/webhooks", "exactly one"],
    ["https://api.example.com/v1/seal/webhooks?token=x&other=y", "exactly one"],
  ])("rejects invalid private URL %s", (url, message) => {
    expect(() => new SealWebhookClient(url)).toThrow(message);
  });

  it("allows local HTTP only with explicit opt-in", () => {
    expect(() => new SealWebhookClient(
      "http://localhost:8085/v1/seal/webhooks?token=local",
      { dangerouslyAllowInsecureUrl: true },
    )).not.toThrow();
  });
});
