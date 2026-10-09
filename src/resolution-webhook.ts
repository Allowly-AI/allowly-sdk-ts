import { createHmac, timingSafeEqual } from "node:crypto";
import { AllowlyProtocolError } from "./error.js";
import type { Allowly } from "./client.js";
import type {
  ResolutionWebhookConfig, ResolutionWebhookDeliveries, ResolutionWebhookDelivery,
  ResolutionWebhookEvent, ResolutionWebhookEventType, ResolutionWebhookSecret,
  ResolutionWebhookVerificationOptions,
} from "./types.js";

const PATH = "/v1/setup/resolution-webhook";
const ERROR_CODES = new Set([
  "unsafe_url", "dns_error", "timeout", "transport_error", "request_too_large",
  "response_too_large", "invalid_headers", "http_error", "expired", "attempts_exhausted",
  "endpoint_disabled", "endpoint_changed", "endpoint_gone", "workspace_closed",
]);

function base64Bytes32(value: string): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    throw new AllowlyProtocolError("webhook key or signature must be canonical 32-byte base64");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== 32 || decoded.toString("base64") !== value) {
    throw new AllowlyProtocolError("webhook key or signature must be canonical 32-byte base64");
  }
  return decoded;
}

function signingKey(secret: string): Buffer {
  if (typeof secret !== "string" || !secret.startsWith("whsec_")) {
    throw new AllowlyProtocolError("signingSecret must use the whsec_ profile");
  }
  return base64Bytes32(secret.slice(6));
}

/** Authenticate exact UTF-8 bytes before parsing. `now` uses Unix seconds.
 * Persist event IDs to prevent duplicate processing. This notification is not
 * execution permission or a portable signed receipt. Read current status, then
 * use native Continue for the saved Execute or a fresh Check for standalone Check. */
export function verifyResolutionWebhook(
  rawBody: Uint8Array,
  headers: Record<string, string> | Headers,
  options: ResolutionWebhookVerificationOptions,
): ResolutionWebhookEvent {
  if (!(rawBody instanceof Uint8Array) || rawBody.byteLength === 0 || rawBody.byteLength > 16 * 1024) {
    throw new AllowlyProtocolError("rawBody must be bytes of at most 16 KiB");
  }
  if (!options || typeof options.expectedWorkspaceId !== "string" || !options.expectedWorkspaceId) {
    throw new AllowlyProtocolError("expectedWorkspaceId must come from trusted configuration");
  }
  const key = signingKey(options.signingSecret);
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
    throw new AllowlyProtocolError("webhook headers must be a mapping");
  }
  const signedHeaders: Record<string, string> = {};
  const entries = headers instanceof Headers ? [...headers.entries()] : Object.entries(headers);
  for (const [name, value] of entries) {
    const normalized = name.toLowerCase();
    if (!["webhook-id", "webhook-timestamp", "webhook-signature"].includes(normalized)) continue;
    if (signedHeaders[normalized] !== undefined || typeof value !== "string" || !value) {
      throw new AllowlyProtocolError("webhook headers must be unique non-empty strings");
    }
    const limit = normalized === "webhook-signature" ? 1024 : 128;
    if (value.length > limit || /[^\x20-\x7E]/.test(value)) {
      throw new AllowlyProtocolError("webhook header exceeds its bounds or contains invalid characters");
    }
    signedHeaders[normalized] = value;
  }
  if (Object.keys(signedHeaders).length !== 3) throw new AllowlyProtocolError("missing webhook signature headers");
  const eventId = signedHeaders["webhook-id"];
  const timestamp = signedHeaders["webhook-timestamp"];
  if (!/^evt_[A-Za-z0-9_-]+$/.test(eventId) || !/^(?:0|[1-9][0-9]{0,11})$/.test(timestamp)) {
    throw new AllowlyProtocolError("invalid webhook ID or timestamp");
  }
  const now = options.now ?? Date.now() / 1000;
  if (typeof now !== "number" || !Number.isFinite(now)) throw new AllowlyProtocolError("now must be finite Unix seconds");
  if (Math.abs(now - Number(timestamp)) > 300) {
    throw new AllowlyProtocolError("webhook timestamp is outside the 300-second tolerance");
  }
  const signatures = signedHeaders["webhook-signature"].trim().split(/ +/);
  if (signatures.length < 1 || signatures.length > 8) throw new AllowlyProtocolError("webhook signature count exceeds its bounds");
  const expected = createHmac("sha256", key).update(`${eventId}.${timestamp}.`, "ascii").update(rawBody).digest();
  let verified = false;
  for (const signature of signatures) {
    const parts = signature.split(",");
    if (parts.length !== 2 || !/^[A-Za-z0-9]+$/.test(parts[0]) || !parts[1]) {
      throw new AllowlyProtocolError("malformed webhook signature header");
    }
    if (parts[0] === "v1") verified = timingSafeEqual(expected, base64Bytes32(parts[1])) || verified;
  }
  if (!verified) throw new AllowlyProtocolError("webhook signature did not verify");
  let value: unknown;
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(rawBody);
    value = JSON.parse(text);
    rejectDuplicateFields(text);
  } catch {
    throw new AllowlyProtocolError("webhook payload must be valid UTF-8 JSON with unique fields");
  }
  const body = record(value, ["id", "type", "timestamp", "workspace_id", "data"]);
  if (body.id !== eventId || body.workspace_id !== options.expectedWorkspaceId) {
    throw new AllowlyProtocolError("webhook event or workspace ID does not match");
  }
  const type = eventType(body, "type");
  const data = record(body.data, ["prompt_id", "status", "source_receipt_id", "resolution_receipt_id"]);
  const promptId = identifier(data, "prompt_id", type === "confirmation.resolved" ? "cnf_" : "esc_");
  const status = string(data, "status");
  if (status !== "approved" && status !== "rejected") throw new AllowlyProtocolError("webhook status must be approved or rejected");
  const sourceReceiptId = nullableString(data, "source_receipt_id");
  if (sourceReceiptId !== null) identifier(data, "source_receipt_id", "rcp_");
  return {
    id: eventId, type, timestamp: isoTimestamp(body, "timestamp"), workspaceId: options.expectedWorkspaceId,
    data: { promptId, status, sourceReceiptId, resolutionReceiptId: identifier(data, "resolution_receipt_id", "rcp_") },
  };
}

function rejectDuplicateFields(text: string): void {
  // Native JSON parsing already checked syntax. Scan only object field names.
  const stack: Array<{ keys: Set<string>; expectingKey: boolean } | null> = [];
  for (const match of text.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\],]/g)) {
    const token = match[0];
    const object = stack[stack.length - 1];
    if (token === "{") stack.push({ keys: new Set(), expectingKey: true });
    else if (token === "[") stack.push(null);
    else if (token === "}" || token === "]") stack.pop();
    else if (token === "," && object) object.expectingKey = true;
    else if (token.startsWith('"') && object?.expectingKey) {
      const key = JSON.parse(token) as string;
      if (object.keys.has(key)) throw new AllowlyProtocolError("duplicate webhook field");
      object.keys.add(key);
      object.expectingKey = false;
    }
  }
}

function record(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).length !== keys.length || keys.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) {
    throw new AllowlyProtocolError("webhook object fields do not match the contract");
  }
  return value as Record<string, unknown>;
}

function string(raw: Record<string, unknown>, key: string): string {
  const value = raw[key];
  if (typeof value !== "string" || !value || value.length > 2048) throw new AllowlyProtocolError(`webhook ${key} must be a bounded non-empty string`);
  return value;
}

function nullableString(raw: Record<string, unknown>, key: string): string | null {
  if (!Object.prototype.hasOwnProperty.call(raw, key)) throw new AllowlyProtocolError(`webhook ${key} must be present`);
  return raw[key] === null ? null : string(raw, key);
}

function identifier(raw: Record<string, unknown>, key: string, prefix: string): string {
  const value = string(raw, key);
  if (value.length > 128 || !value.startsWith(prefix) || !/^[A-Za-z0-9_-]+$/.test(value.slice(prefix.length))) {
    throw new AllowlyProtocolError(`webhook ${key} has an invalid ID prefix or format`);
  }
  return value;
}

function isoTimestamp(raw: Record<string, unknown>, key: string): string {
  const value = string(raw, key);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value);
  if (match) {
    const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
    if (year >= 1 && month >= 1 && month <= 12 && day >= 1 && day <= new Date(Date.UTC(year, month, 0)).getUTCDate()
        && hour <= 23 && minute <= 59 && second <= 59 && Number(match[7] ?? 0) <= 23 && Number(match[8] ?? 0) <= 59
        && Number.isFinite(Date.parse(value))) return value;
  }
  throw new AllowlyProtocolError(`webhook ${key} must be a valid timezone-aware timestamp`);
}

function nullableTimestamp(raw: Record<string, unknown>, key: string): string | null {
  return nullableString(raw, key) === null ? null : isoTimestamp(raw, key);
}

function eventType(raw: Record<string, unknown>, key: string): ResolutionWebhookEventType {
  const value = string(raw, key);
  if (value !== "confirmation.resolved" && value !== "escalation.resolved") throw new AllowlyProtocolError("unknown resolution webhook event type");
  return value;
}

/** Setup/CLI credentials only. Runtime keys cannot manage this endpoint. */
export class ResolutionWebhookResource {
  constructor(private readonly client: Allowly) {}

  async get(): Promise<ResolutionWebhookConfig> {
    return parseConfig(await this.client.request("GET", PATH));
  }

  async configure(url: string): Promise<ResolutionWebhookSecret> {
    return parseSecret(await this.client.request("PUT", PATH, { url }));
  }

  async rotate(): Promise<ResolutionWebhookSecret> {
    return parseSecret(await this.client.request("POST", `${PATH}/rotate`));
  }

  async disable(): Promise<ResolutionWebhookConfig> {
    return parseConfig(await this.client.request("DELETE", PATH));
  }

  async deliveries(): Promise<ResolutionWebhookDeliveries> {
    const raw = record(await this.client.request("GET", `${PATH}/deliveries`), ["items"]);
    if (!Array.isArray(raw.items) || raw.items.length > 20) throw new AllowlyProtocolError("webhook deliveries must contain at most 20 items");
    return { items: raw.items.map(parseDelivery) };
  }
}

function parseConfig(value: unknown): ResolutionWebhookConfig {
  const raw = record(value, ["workspace_id", "endpoint_id", "url", "enabled", "credential_version", "created_at", "updated_at"]);
  if (typeof raw.enabled !== "boolean") throw new AllowlyProtocolError("webhook enabled must be a boolean");
  const version = raw.credential_version;
  if (version !== null && (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1)) {
    throw new AllowlyProtocolError("webhook credential_version must be a positive integer or null");
  }
  const config = {
    workspaceId: string(raw, "workspace_id"), endpointId: nullableString(raw, "endpoint_id"),
    url: nullableString(raw, "url"), enabled: raw.enabled, credentialVersion: version,
    createdAt: nullableTimestamp(raw, "created_at"), updatedAt: nullableTimestamp(raw, "updated_at"),
  };
  const fields = [config.url, version, config.createdAt, config.updatedAt];
  if (config.endpointId === null) {
    if (config.enabled || fields.some((field) => field !== null)) throw new AllowlyProtocolError("missing webhook endpoint must have a disabled null configuration");
  } else if (fields.some((field) => field === null)) {
    throw new AllowlyProtocolError("configured webhook endpoint must include its URL, version and timestamps");
  }
  return config;
}

function parseSecret(value: unknown): ResolutionWebhookSecret {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new AllowlyProtocolError("webhook signing_secret must be present");
  const raw = value as Record<string, unknown>;
  const secret = string(raw, "signing_secret");
  signingKey(secret);
  const { signing_secret: omitted, ...configFields } = raw;
  const config = parseConfig(configFields);
  if (config.endpointId === null) throw new AllowlyProtocolError("webhook signing_secret requires a configured endpoint");
  return { ...config, signingSecret: secret };
}

function parseDelivery(value: unknown): ResolutionWebhookDelivery {
  const raw = record(value, ["event_id", "event_type", "status", "attempts", "created_at", "delivered_at", "last_error"]);
  const status = string(raw, "status");
  if (status !== "pending" && status !== "delivered" && status !== "failed" && status !== "cancelled") throw new AllowlyProtocolError("unknown webhook delivery status");
  const attempts = raw.attempts;
  if (typeof attempts !== "number" || !Number.isSafeInteger(attempts) || attempts < 0) throw new AllowlyProtocolError("webhook attempts must be a non-negative integer");
  const lastError = nullableString(raw, "last_error");
  if (lastError !== null && !ERROR_CODES.has(lastError)) throw new AllowlyProtocolError("unknown webhook delivery error code");
  const deliveredAt = nullableTimestamp(raw, "delivered_at");
  if ((status === "delivered") !== (deliveredAt !== null)) throw new AllowlyProtocolError("webhook delivered_at does not match delivery status");
  return {
    eventId: identifier(raw, "event_id", "evt_"), eventType: eventType(raw, "event_type"), status, attempts,
    createdAt: isoTimestamp(raw, "created_at"), deliveredAt, lastError,
  };
}

