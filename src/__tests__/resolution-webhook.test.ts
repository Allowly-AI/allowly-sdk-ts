import { createHmac } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { Allowly, AllowlyProtocolError, verifyResolutionWebhook } from "../index.js";

const KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const SECRET = `whsec_${KEY.toString("base64")}`;
const NOW = 1700000000;
const BASE = "https://api.example.com/v1/setup/resolution-webhook";
const RAW = Buffer.from('{"id":"evt_1","type":"confirmation.resolved","timestamp":"2023-11-14T22:13:00Z","workspace_id":"ws_test","data":{"prompt_id":"cnf_1","status":"approved","source_receipt_id":null,"resolution_receipt_id":"rcp_1"}}');
// Independently calculated with openssl dgst -sha256 -mac HMAC.
const GOLDEN_SIGNATURE = "ccj9r4381eeqEORTlD4qdKOXeGA63FYeGAv62T9IPOI=";

function headers(raw: Uint8Array = RAW, eventId = "evt_1", timestamp = String(NOW)) {
  const signature = createHmac("sha256", KEY).update(`${eventId}.${timestamp}.`).update(raw).digest("base64");
  return { "webhook-id": eventId, "webhook-timestamp": timestamp, "webhook-signature": `v1,${signature}` };
}

function verify(raw: Uint8Array = RAW, signedHeaders: Record<string, string> | Headers = headers(raw), options = {}) {
  return verifyResolutionWebhook(raw, signedHeaders, { signingSecret: SECRET, expectedWorkspaceId: "ws_test", now: NOW, ...options });
}

describe("verifyResolutionWebhook", () => {
  it("uses the cross-SDK golden signature and returns typed fields", () => {
    expect(headers()["webhook-signature"]).toBe(`v1,${GOLDEN_SIGNATURE}`);
    const event = verify(RAW, new Headers(headers()));
    expect(event).toEqual({
      id: "evt_1", type: "confirmation.resolved", timestamp: "2023-11-14T22:13:00Z", workspaceId: "ws_test",
      data: { promptId: "cnf_1", status: "approved", sourceReceiptId: null, resolutionReceiptId: "rcp_1" },
    });
    const offset = Buffer.concat([Buffer.from("xx"), RAW, Buffer.from("xx")]).subarray(2, RAW.length + 2);
    expect(verify(offset)).toEqual(event);
  });

  it.each(["confirmation", "escalation"])("accepts both choices for %s", (kind) => {
    for (const status of ["approved", "rejected"]) {
      const body = JSON.parse(RAW.toString());
      body.type = `${kind}.resolved`;
      Object.assign(body.data, { prompt_id: kind === "confirmation" ? "cnf_1" : "esc_1", status, source_receipt_id: "rcp_source" });
      const raw = Buffer.from(JSON.stringify(body, null, 2));
      expect(verify(raw)).toMatchObject({ type: `${kind}.resolved`, data: { status, sourceReceiptId: "rcp_source" } });
    }
  });

  it.each([-300, 0, 300])("accepts the exact timestamp boundary %s and stable retry bytes", (offset) => {
    expect(verify(RAW, headers(RAW, "evt_1", String(NOW + offset))))
      .toEqual(verify(RAW, headers(RAW, "evt_1", String(NOW + 10)), { now: NOW + 10 }));
  });

  it.each([-301, 301])("rejects stale or future attempt %s", (offset) => {
    expect(() => verify(RAW, headers(RAW, "evt_1", String(NOW + offset)))).toThrow("tolerance");
  });

  it("verifies every v1 entry and ignores unknown schemes", () => {
    const signed = headers();
    signed["webhook-signature"] = `v2,unknown v1,${Buffer.alloc(32, 120).toString("base64")} ${signed["webhook-signature"]}`;
    expect(verify(RAW, signed).id).toBe("evt_1");
  });

  it.each([
    "", SECRET.slice(6), SECRET.replace(/=$/, ""), SECRET + "=", "whsec_" + "_".repeat(43) + "=",
    "whsec_" + Buffer.alloc(31, 120).toString("base64"), SECRET.slice(0, -2) + "9=",
  ])("rejects noncanonical or wrong length keys", (signingSecret) => {
    expect(() => verify(RAW, headers(), { signingSecret })).toThrow(AllowlyProtocolError);
  });

  it.each([
    { "webhook-id": "evt_other" }, { "webhook-id": "evt_1.x" }, { "webhook-id": "evt_" + "x".repeat(129) },
    { "webhook-timestamp": "01700000000" }, { "webhook-timestamp": "1700000000.0" },
    { "webhook-signature": "v1," + "A".repeat(44) }, { "webhook-signature": "v2,unknown" },
    { "webhook-signature": "v1," + GOLDEN_SIGNATURE.replace(/=$/, "") },
    { "webhook-signature": "v1," + GOLDEN_SIGNATURE.slice(0, -2) + "J=" },
    { "webhook-signature": "v1," + GOLDEN_SIGNATURE + ",extra" },
    { "webhook-signature": Array(9).fill("v1," + GOLDEN_SIGNATURE).join(" ") },
    { "webhook-signature": "x".repeat(1025) }, { "webhook-timestamp": "1700000000\n" },
  ])("rejects invalid or tampered headers", (changes) => {
    expect(() => verify(RAW, { ...headers(), ...changes })).toThrow(AllowlyProtocolError);
  });

  it.each(["webhook-id", "webhook-timestamp", "webhook-signature"])("rejects missing or ambiguous %s", (key) => {
    const signed: Record<string, string> = headers();
    const value = signed[key];
    delete signed[key];
    expect(() => verify(RAW, signed)).toThrow(AllowlyProtocolError);
    signed[key] = value;
    signed[key.toUpperCase()] = value;
    expect(() => verify(RAW, signed)).toThrow(AllowlyProtocolError);
  });

  it("authenticates before JSON parsing", () => {
    const parse = vi.spyOn(JSON, "parse");
    try {
      expect(() => verify(Buffer.from("not JSON"), headers())).toThrow("signature");
      expect(parse).not.toHaveBeenCalled();
    } finally {
      parse.mockRestore();
    }
  });

  it.each([Buffer.concat([RAW, Buffer.from(" ")]), Buffer.from(RAW.toString().replace("approved", "rejected"))])
    ("rejects changed raw bytes", (raw) => expect(() => verify(raw, headers())).toThrow("signature"));

  it.each([
    Buffer.from("[]"), Buffer.from("{"), Buffer.from([255]), Buffer.concat([Buffer.from([239, 187, 191]), RAW]),
    Buffer.from(RAW.toString().replace('"id":"evt_1"', '"id":"evt_other","id":"evt_1"')),
    Buffer.from(RAW.toString().replace('"id":"evt_1"', '"\\u0069d":"evt_other","id":"evt_1"')),
    Buffer.from(RAW.toString().replace('"source_receipt_id":null', '"source_receipt_id":null,"source_receipt_id":"rcp_other"')),
    Buffer.from(RAW.toString().replace("null", "NaN")),
  ])("rejects authenticated malformed JSON", (raw) => expect(() => verify(raw)).toThrow(AllowlyProtocolError));

  it.each([
    ["id", "evt_other"], ["type", "confirmation.created"], ["workspace_id", "ws_other"],
    ["timestamp", "2023-02-30T22:13:00Z"], ["timestamp", "2023-11-14T22:13:00"], ["data", null], ["resource", "private"],
  ])("rejects authenticated invalid event %s", (field, value) => {
    const body = JSON.parse(RAW.toString());
    body[field as string] = value;
    expect(() => verify(Buffer.from(JSON.stringify(body)))).toThrow(AllowlyProtocolError);
  });

  it.each([
    ["prompt_id", "esc_1"], ["status", "pending"], ["source_receipt_id", "auth_1"], ["source_receipt_id", false],
    ["resolution_receipt_id", null], ["resolution_receipt_id", "rcp_"], ["nonce", "private"],
  ])("rejects authenticated invalid data %s", (field, value) => {
    const body = JSON.parse(RAW.toString());
    body.data[field as string] = value;
    expect(() => verify(Buffer.from(JSON.stringify(body)))).toThrow(AllowlyProtocolError);
  });

  it.each(["prompt_id", "status", "source_receipt_id", "resolution_receipt_id"])("requires explicit data field %s", (field) => {
    const body = JSON.parse(RAW.toString());
    delete body.data[field];
    expect(() => verify(Buffer.from(JSON.stringify(body)))).toThrow(AllowlyProtocolError);
  });

  it.each(["{}", Buffer.alloc(0), Buffer.alloc(16 * 1024 + 1)])("bounds raw bodies", (raw) => {
    expect(() => verify(raw as Uint8Array, headers())).toThrow(AllowlyProtocolError);
  });

  it("accepts the exact body limit and eight signature entries", () => {
    const raw = Buffer.concat([RAW, Buffer.alloc(16 * 1024 - RAW.length, 32)]);
    const signed = headers(raw);
    signed["webhook-signature"] = "v2,unknown ".repeat(7) + signed["webhook-signature"];
    expect(verify(raw, signed).id).toBe("evt_1");
  });

  it.each([{ expectedWorkspaceId: "ws_other" }, { expectedWorkspaceId: "" }, { now: NaN }])
    ("requires trusted workspace and finite clock", (options) => expect(() => verify(RAW, headers(), options)).toThrow(AllowlyProtocolError));

  it("preserves JSON punctuation inside a trusted workspace ID", () => {
    const body = JSON.parse(RAW.toString());
    body.workspace_id = 'ws_,"id":{},[]\\value';
    const raw = Buffer.from(JSON.stringify(body));
    expect(verify(raw, headers(raw), { expectedWorkspaceId: body.workspace_id }).workspaceId).toBe(body.workspace_id);
  });
});

function config(overrides: Record<string, unknown> = {}) {
  return {
    workspace_id: "ws_test", endpoint_id: "rwh_1", url: "https://customer.example/callback",
    enabled: true, credential_version: 1, created_at: "2023-11-14T22:13:00Z", updated_at: "2023-11-14T22:13:00Z", ...overrides,
  } as Record<string, unknown>;
}

function fetchBody(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status }));
}

function delivery(overrides: Record<string, unknown> = {}) {
  return {
    event_id: "evt_1", event_type: "confirmation.resolved", status: "pending", attempts: 0,
    created_at: "2023-11-14T22:13:00Z", delivered_at: null, last_error: null, ...overrides,
  } as Record<string, unknown>;
}

describe("resolutionWebhook setup resource", () => {
  it("uses the exact methods, setup credential, and typed results", async () => {
    const fetch = vi.fn();
    for (const body of [config(), config({ signing_secret: SECRET }), config({ credential_version: 2, signing_secret: SECRET }), config({ enabled: false }), { items: [{
      event_id: "evt_1", event_type: "confirmation.resolved", status: "failed", attempts: 1,
      created_at: "2023-11-14T22:13:00Z", delivered_at: null, last_error: "endpoint_gone",
    }] }]) fetch.mockResolvedValueOnce(new Response(JSON.stringify(body)));
    const client = new Allowly({ apiKey: "setup-key", baseUrl: "https://api.example.com", fetch });
    expect(await client.resolutionWebhook.get()).toMatchObject({ workspaceId: "ws_test" });
    expect(await client.resolutionWebhook.configure("https://customer.example/callback")).toMatchObject({ signingSecret: SECRET });
    expect(await client.resolutionWebhook.rotate()).toMatchObject({ credentialVersion: 2 });
    expect(await client.resolutionWebhook.disable()).toMatchObject({ enabled: false });
    expect((await client.resolutionWebhook.deliveries()).items[0]).toMatchObject({ lastError: "endpoint_gone" });
    expect(fetch.mock.calls.map(([url, request]) => [url, request.method])).toEqual([
      [BASE, "GET"], [BASE, "PUT"], [BASE + "/rotate", "POST"], [BASE, "DELETE"], [BASE + "/deliveries", "GET"],
    ]);
    expect(fetch.mock.calls[1][1].body).toBe(JSON.stringify({ url: "https://customer.example/callback" }));
    for (const [, request] of fetch.mock.calls) expect(request.headers.Authorization).toBe("Bearer setup-key");
  });

  it("returns an explicit disabled null config for a missing endpoint", async () => {
    const fetch = fetchBody(config({ endpoint_id: null, url: null, enabled: false, credential_version: null, created_at: null, updated_at: null }));
    const client = new Allowly({ apiKey: "setup-key", baseUrl: "https://api.example.com", fetch });
    expect(await client.resolutionWebhook.get()).toMatchObject({ endpointId: null, credentialVersion: null, enabled: false });
  });

  it.each(Object.keys(config()))("requires every config field: %s", async (field) => {
    const body = config();
    delete body[field];
    await expect(new Allowly({ apiKey: "setup-key", fetch: fetchBody(body) }).resolutionWebhook.get()).rejects.toThrow(AllowlyProtocolError);
  });

  it.each([{ enabled: 1 }, { credential_version: true }, { credential_version: 0 }, { created_at: "invalid" }, { url: null }, { signing_secret: SECRET }])
    ("rejects malformed or secret bearing config GET", async (overrides) => {
      await expect(new Allowly({ apiKey: "setup-key", fetch: fetchBody(config(overrides)) }).resolutionWebhook.get()).rejects.toThrow(AllowlyProtocolError);
    });

  it.each([403, 404, 429, 503])("never retries or falls back on setup error %s", async (status) => {
    const fetch = fetchBody({ error: { code: "resolution_webhook_not_configured", message: "Unavailable" } }, status);
    await expect(new Allowly({ apiKey: "setup-key", fetch }).resolutionWebhook.rotate()).rejects.toMatchObject({ status });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it.each([null, "wrong-profile", SECRET.replace(/=$/, ""), false])("requires a valid current signing secret", async (secret) => {
    const body = config(secret === null ? {} : { signing_secret: secret });
    await expect(new Allowly({ apiKey: "setup-key", fetch: fetchBody(body) }).resolutionWebhook.configure("https://customer.example/callback"))
      .rejects.toThrow(AllowlyProtocolError);
  });

  it.each(["pending", "delivered", "failed", "cancelled"])("accepts bounded delivery history with %s status", async (status) => {
    const item = delivery({ status, delivered_at: status === "delivered" ? "2023-11-14T22:14:00Z" : null });
    const result = await new Allowly({ apiKey: "setup-key", fetch: fetchBody({ items: Array(20).fill(item) }) }).resolutionWebhook.deliveries();
    expect(result.items).toHaveLength(20);
    expect(result.items[0].status).toBe(status);
  });

  it.each([
    { items: false }, { items: Array(21).fill(delivery()) },
    { items: [delivery({ attempts: true })] }, { items: [delivery({ event_type: "unknown" })] },
    { items: [delivery({ last_error: "https://private.example/secret" })] },
    { items: [delivery({ status: "delivered" })] }, { items: [delivery({ delivered_at: "2023-11-14T22:14:00Z" })] },
    { items: [delivery({ url: "https://private.example/" })] },
    ...Object.keys(delivery()).map((missing) => ({ items: [Object.fromEntries(Object.entries(delivery()).filter(([key]) => key !== missing))] })),
  ])("rejects malformed or private delivery metadata", async (body) => {
    await expect(new Allowly({ apiKey: "setup-key", fetch: fetchBody(body) }).resolutionWebhook.deliveries()).rejects.toThrow(AllowlyProtocolError);
  });
});

