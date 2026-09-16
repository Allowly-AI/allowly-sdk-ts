import { AllowlyTransportError } from "./client.js";
import { AllowlyAPIError, AllowlyProtocolError } from "./error.js";
import type {
  AllowlyError,
  SealWebhookClientOptions,
  SealWebhookDelivery,
  SealWebhookStatus,
} from "./types.js";

const SEAL_PROFILE = "allowly.seal.jcs-sha256.v1";
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

/** Client for one private SEAL webhook URL. The URL is its only credential. */
export class SealWebhookClient {
  private readonly webhookUrl: string;
  private readonly origin: string;
  private readonly query: string;
  private readonly _fetch: typeof globalThis.fetch;
  private readonly requestTimeoutMs: number;

  constructor(webhookUrl: string, options: SealWebhookClientOptions = {}) {
    const parsed = validateWebhookUrl(
      webhookUrl,
      options.dangerouslyAllowInsecureUrl ?? false,
    );
    this.origin = parsed.origin;
    this.query = parsed.search;
    this.webhookUrl = parsed.toString();
    this._fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    if (this.requestTimeoutMs <= 0) {
      throw new Error("requestTimeoutMs must be positive");
    }
  }

  async send(
    recordJson: string | Uint8Array,
    options: {
      idempotencyKey?: string;
      type?: string;
      reference?: string;
      statement?: string;
    } = {},
  ): Promise<SealWebhookDelivery> {
    if (typeof recordJson !== "string" && !(recordJson instanceof Uint8Array)) {
      throw new TypeError("recordJson must be a string or Uint8Array");
    }
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (options.idempotencyKey !== undefined) {
      headers["Idempotency-Key"] = options.idempotencyKey;
    }
    for (const [name, value] of [
      ["Type", options.type],
      ["Reference", options.reference],
      ["Statement", options.statement],
    ] as const) {
      if (value === undefined) continue;
      if (typeof value !== "string") {
        throw new TypeError(`${name.toLowerCase()} must be a string`);
      }
      if (/[^\x20-\x7E]/.test(value)) {
        throw new Error(`${name.toLowerCase()} must contain printable ASCII only`);
      }
      if (value.length > 256) {
        throw new Error(`${name.toLowerCase()} must be at most 256 characters`);
      }
      if (value.trim() !== value) {
        throw new Error(
          `${name.toLowerCase()} must not contain leading or trailing whitespace`,
        );
      }
      headers[`Allowly-Seal-${name}`] = value;
    }
    return parseDelivery(await this.request(this.webhookUrl, {
      method: "POST",
      headers,
      body: recordJson as BodyInit,
    }, new Set([200, 202])));
  }

  async getDelivery(attemptId: string): Promise<SealWebhookDelivery> {
    const delivery = parseDelivery(await this.request(
      this.url(`/v1/seal/webhooks/deliveries/${encodeURIComponent(attemptId)}`),
      { method: "GET" },
      new Set([200]),
    ));
    if (delivery.attemptId !== attemptId) {
      throw new AllowlyProtocolError(
        "SEAL webhook response attempt_id does not match the request",
      );
    }
    return delivery;
  }

  async getReceipt(receiptId: string): Promise<SealWebhookDelivery> {
    const delivery = parseDelivery(await this.request(
      this.url(`/v1/seal/webhooks/receipts/${encodeURIComponent(receiptId)}`),
      { method: "GET" },
      new Set([200]),
    ));
    if (delivery.receiptId !== receiptId) {
      throw new AllowlyProtocolError(
        "SEAL webhook response receipt_id does not match the request",
      );
    }
    return delivery;
  }

  async getKeys(): Promise<Record<string, unknown>> {
    return requireRecord(await this.request(
      this.url("/v1/seal/webhooks/keys"),
      { method: "GET" },
      new Set([200]),
    ), "SEAL webhook keys response");
  }

  private url(path: string): string {
    return `${this.origin}${path}${this.query}`;
  }

  private async request(
    url: string,
    init: RequestInit,
    expectedStatuses: Set<number>,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await this._fetch(url, {
        ...init,
        redirect: "manual",
        signal: AbortSignal.timeout(this.requestTimeoutMs),
      });
    } catch {
      // Fetch errors may contain the credential-bearing URL.
      throw new AllowlyTransportError(new Error("SEAL webhook transport failed"));
    }
    if (response.redirected) {
      throw new AllowlyProtocolError("redirected responses are not allowed");
    }
    if (response.ok && !expectedStatuses.has(response.status)) {
      throw new AllowlyProtocolError(
        `unexpected successful HTTP status: ${response.status}`,
      );
    }
    let json: unknown = null;
    try {
      json = await response.json();
    } catch {
      if (response.ok) {
        throw new AllowlyProtocolError(
          "successful SEAL webhook response was not valid JSON",
        );
      }
    }
    if (!response.ok) {
      const rawError = json && typeof json === "object"
        ? (json as Record<string, unknown>).error
        : undefined;
      const error = rawError && typeof rawError === "object"
        ? rawError as Record<string, unknown>
        : typeof rawError === "string"
          ? { message: rawError }
          : {};
      const fields = Array.isArray(error.fields)
        ? error.fields.filter((field): field is { field: string; message: string } =>
            !!field && typeof field === "object"
            && typeof (field as Record<string, unknown>).field === "string"
            && typeof (field as Record<string, unknown>).message === "string")
        : undefined;
      const body: AllowlyError = {
        code: typeof error.code === "string" ? error.code : "error",
        message: typeof error.message === "string"
          ? error.message
          : response.statusText || "Unknown error",
        fields,
      };
      throw new AllowlyAPIError(
        response.status,
        body,
        parseRetryAfter(response.headers.get("Retry-After")),
      );
    }
    return json;
  }
}

function validateWebhookUrl(value: string, allowInsecure: boolean): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("webhookUrl must be a valid HTTP or HTTPS URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("webhookUrl must be a valid HTTP or HTTPS URL");
  }
  if (parsed.protocol !== "https:" && !allowInsecure) {
    throw new Error("webhookUrl must use HTTPS");
  }
  if (parsed.username || parsed.password || parsed.hash) {
    throw new Error("webhookUrl must not contain user info or a fragment");
  }
  if (parsed.pathname !== "/v1/seal/webhooks") {
    throw new Error("webhookUrl must use the SEAL webhook endpoint");
  }
  const entries = [...parsed.searchParams.entries()];
  if (entries.length !== 1 || entries[0][0] !== "token" || !entries[0][1]) {
    throw new Error("webhookUrl must contain exactly one non-empty token");
  }
  parsed.search = new URLSearchParams({ token: entries[0][1] }).toString();
  return parsed;
}

function parseDelivery(value: unknown): SealWebhookDelivery {
  const raw = requireRecord(value, "SEAL webhook delivery response");
  const status = requireString(raw, "status");
  if (!["received", "signing", "sealed", "rejected", "failed"].includes(status)) {
    throw new AllowlyProtocolError(`unknown SEAL webhook status: ${JSON.stringify(status)}`);
  }
  const profile = requireString(raw, "profile");
  if (profile !== SEAL_PROFILE) {
    throw new AllowlyProtocolError("SEAL webhook response has an unknown profile");
  }
  const workspaceId = requireString(raw, "workspace_id");
  const receiptId = optionalString(raw, "receipt_id");
  const receipt = optionalRecord(raw, "receipt");
  let metadata = optionalMetadata(raw.metadata, "SEAL webhook response metadata");
  if (receipt !== null) {
    if (receiptId === null || receipt.receipt_id !== receiptId) {
      throw new AllowlyProtocolError("SEAL webhook receipt_id binding does not match");
    }
    if (receipt.workspace_id !== workspaceId) {
      throw new AllowlyProtocolError("SEAL webhook workspace_id binding does not match");
    }
    const context = optionalRecord(receipt, "context");
    const signedMetadata = optionalMetadata(
      context?.seal_metadata,
      "signed SEAL receipt metadata",
    );
    if (metadata !== null && !sameMetadata(metadata, signedMetadata)) {
      throw new AllowlyProtocolError(
        "SEAL webhook response metadata does not match the signed receipt",
      );
    }
    metadata = signedMetadata;
  }
  return {
    attemptId: requireString(raw, "attempt_id"),
    workspaceId,
    status: status as SealWebhookStatus,
    receivedAt: requireString(raw, "received_at"),
    updatedAt: requireString(raw, "updated_at"),
    profile,
    recordSha256: optionalString(raw, "record_sha256"),
    metadata,
    receiptId,
    errorCode: optionalString(raw, "error_code"),
    statusUrl: requireString(raw, "status_url"),
    receiptUrl: optionalString(raw, "receipt_url"),
    keysUrl: requireString(raw, "keys_url"),
    receipt,
  };
}

function optionalMetadata(value: unknown, name: string): Record<string, string> | null {
  if (value === undefined || value === null) return null;
  const metadata = requireRecord(value, name);
  if (Object.values(metadata).some((item) => typeof item !== "string")) {
    throw new AllowlyProtocolError(`${name} must contain only string values`);
  }
  return metadata as Record<string, string>;
}

function sameMetadata(
  left: Record<string, string>,
  right: Record<string, string> | null,
): boolean {
  if (right === null) return false;
  const keys = Object.keys(left);
  return keys.length === Object.keys(right).length
    && keys.every((key) => left[key] === right[key]);
}

function requireRecord(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new AllowlyProtocolError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireString(raw: Record<string, unknown>, key: string): string {
  const value = raw[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new AllowlyProtocolError(
      `SEAL webhook response ${key} must be a non-empty string`,
    );
  }
  return value;
}

function optionalString(raw: Record<string, unknown>, key: string): string | null {
  const value = raw[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw new AllowlyProtocolError(
      `SEAL webhook response ${key} must be a string or null`,
    );
  }
  return value;
}

function optionalRecord(raw: Record<string, unknown>, key: string): Record<string, unknown> | null {
  const value = raw[key];
  return value === undefined || value === null
    ? null
    : requireRecord(value, `SEAL webhook response ${key}`);
}

function parseRetryAfter(value: string | null): number | undefined {
  if (value === null || value.trim() === "") return undefined;
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : undefined;
}
