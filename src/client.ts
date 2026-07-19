import { AllowlyAPIError, AllowlyProtocolError } from "./error.js";
import type {
  AllowlyOptions,
  CheckResponse,
  FallbackMode,
  AuthorizationCreateRequest,
  AuthorizationCreateResponse,
  AuthorizationRevokeResponse,
  ConfirmationApproveRequest,
  ConfirmationApproveResponse,
  BudgetInfo,
  BudgetSettlementResponse,
  EscalationInfo,
  PolicyConditionEvidence,
  PolicyEvalInfo,
  EscalationResolveRequest,
  EscalationResolveResponse,
  ReceiptEnvelope,
  ReceiptEnvelopePending,
} from "./types.js";

const DEFAULT_BASE_URL = "https://api.allowly.ai";
const DEFAULT_CHECK_TIMEOUT_MS = 1000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

class AllowlyTransportError extends Error {
  readonly cause: unknown;

  constructor(cause: unknown) {
    super("Allowly request failed");
    this.cause = cause;
  }
}

export class Allowly {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly _fetch: typeof globalThis.fetch;
  private readonly checkTimeoutMs: number;
  private readonly requestTimeoutMs: number;
  private readonly defaultFallback: FallbackMode;
  private readonly fallbackByAction: Record<string, FallbackMode>;

  readonly authorizations: AuthorizationsResource;
  readonly confirmations: ConfirmationsResource;
  readonly escalations: EscalationsResource;
  readonly receipts: ReceiptsResource;

  constructor(options: AllowlyOptions) {
    this.apiKey = options.apiKey;
    this.baseUrl = validateBaseUrl(
      options.baseUrl ?? DEFAULT_BASE_URL,
      options.dangerouslyAllowInsecureBaseUrl ?? false,
    );
    this._fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.checkTimeoutMs = options.checkTimeoutMs ?? DEFAULT_CHECK_TIMEOUT_MS;
    if (this.checkTimeoutMs <= 0) {
      throw new Error("checkTimeoutMs must be positive");
    }
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    if (this.requestTimeoutMs <= 0) {
      throw new Error("requestTimeoutMs must be positive");
    }
    this.defaultFallback = validateFallbackMode(options.defaultFallback ?? "fail_closed");
    this.fallbackByAction = Object.fromEntries(
      Object.entries(options.fallbackByAction ?? {}).map(([action, mode]) => [
        action,
        validateFallbackMode(mode),
      ])
    );

    this.authorizations = new AuthorizationsResource(this);
    this.confirmations = new ConfirmationsResource(this);
    this.escalations = new EscalationsResource(this);
    this.receipts = new ReceiptsResource(this);
  }

  /** @internal */
  async request<T>(
    method: string,
    path: string,
    body?: unknown,
    opts: { signal?: AbortSignal; headers?: Record<string, string> } = {}
  ): Promise<T> {
    const serializedBody = body !== undefined ? JSON.stringify(body) : undefined;
    let res: Response;
    try {
      res = await this._fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
          ...opts.headers,
        },
        body: serializedBody,
        signal: opts.signal ?? AbortSignal.timeout(this.requestTimeoutMs),
      });
    } catch (err) {
      if (isAbortError(err)) throw err;
      throw new AllowlyTransportError(err);
    }

    if (res.status === 204) return undefined as T;

    let json: unknown = null;
    try {
      json = await res.json();
    } catch (err) {
      if (res.ok) throw err;
    }

    if (!res.ok) {
      const err = (json as { error?: { code: string; message: string; fields?: Array<{ field: string; message: string }> } } | null)?.error;
      throw new AllowlyAPIError(res.status, err ?? { code: "error", message: res.statusText || "Unknown error" });
    }

    return json as T;
  }

  async check(req: {
    authorizationId: string;
    actions: string[];
    resource?: string;
    sessionId?: string;
    estimatedCostMicros?: number;
    context?: Record<string, unknown>;
    wait?: boolean;
    idempotencyKey?: string;
  }): Promise<CheckResponse> {
    const path = "/v1/check" + (req.wait ? "?wait=true" : "");
    const controller = new AbortController();
    const timeoutMs = req.wait ? Math.max(this.checkTimeoutMs, 6000) : this.checkTimeoutMs;
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const body = {
      authorization_id: req.authorizationId,
      actions: req.actions,
      resource: req.resource,
      session_id: req.sessionId,
      estimated_cost_micros: req.estimatedCostMicros,
      context: req.context ?? {},
    };
    try {
      const raw = await this.request<Record<string, unknown>>("POST", path, body, {
        signal: controller.signal,
        headers: req.idempotencyKey !== undefined ? { "Idempotency-Key": req.idempotencyKey } : undefined,
      });
      return parseCheckResponse(raw);
    } catch (err) {
      if (isAbortError(err)) {
        return this.fallbackCheckResponse(req.authorizationId, req.actions, "timeout");
      }
      if (err instanceof AllowlyAPIError) {
        if (err.status >= 500) {
          return this.fallbackCheckResponse(req.authorizationId, req.actions, "unreachable");
        }
        throw err;
      }
      if (err instanceof AllowlyTransportError) {
        return this.fallbackCheckResponse(req.authorizationId, req.actions, "unreachable");
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  async settleBudget(req: {
    checkReceiptId: string;
    actualCostMicros: number;
    idempotencyKey?: string;
  }): Promise<BudgetSettlementResponse> {
    const raw = await this.request<Record<string, unknown>>(
      "POST",
      "/v1/budget-settlements",
      {
        check_receipt_id: req.checkReceiptId,
        actual_cost_micros: req.actualCostMicros,
      },
      {
        headers: req.idempotencyKey !== undefined ? { "Idempotency-Key": req.idempotencyKey } : undefined,
      }
    );
    return parseBudgetSettlementResponse(raw);
  }

  private fallbackModeForAction(action: string): FallbackMode {
    return this.fallbackByAction[action] ?? this.defaultFallback;
  }

  private fallbackCheckResponse(
    authorizationId: string,
    actions: string[],
    failure: "timeout" | "unreachable"
  ): CheckResponse {
    return {
      authorizationId,
      userId: null,
      agentId: null,
      authorizationExpiresAt: null,
      engineVersion: "sdk_fallback",
      results: Object.fromEntries(
        actions.map((action) => {
          const fallbackMode = this.fallbackModeForAction(action);
          const opened = fallbackMode === "fail_open";
          return [
            action,
            {
              decision: opened ? "allow" : "deny",
              reason: `fallback_${opened ? "open" : "closed"}_${failure}`,
              receipt: null,
              isFallback: true,
              fallbackMode,
              budget: null,
              escalation: null,
              policyEval: null,
            },
          ];
        })
      ) as CheckResponse["results"],
    };
  }
}

class AuthorizationsResource {
  constructor(private readonly client: Allowly) {}

  async create(req: AuthorizationCreateRequest): Promise<AuthorizationCreateResponse> {
    const expiresAt = req.expiresAt instanceof Date ? req.expiresAt.toISOString() : req.expiresAt;
    const actions = req.actions?.map((s) =>
      typeof s === "string"
        ? { name: s, constraints: {} }
        : { name: s.name, constraints: s.constraints ?? {} }
    );
    const raw = await this.client.request<Record<string, unknown>>(
      "POST",
      "/v1/authorizations",
      {
        user_id: req.userId,
        agent_id: req.agentId,
        policy_id: req.policyId,
        actions,
        requires_confirm_for: req.requiresConfirmFor ?? [],
        requires_escalation_for: req.requiresEscalationFor ?? [],
        requires_deny_for: req.requiresDenyFor ?? [],
        escalation_targets: req.escalationTargets ?? {},
        budget_limit_micros: req.budgetLimitMicros,
        expires_at: expiresAt,
        replaces: req.replaces,
        metadata: req.metadata ?? {},
      },
      {
        headers: req.idempotencyKey !== undefined
          ? { "Idempotency-Key": req.idempotencyKey }
          : undefined,
      },
    );
    return {
      authorizationId: requireString(raw, "authorization_id"),
      policyId: optionalString(raw, "policy_id"),
      createdAt: requireString(raw, "created_at"),
      expiresAt: requireString(raw, "expires_at"),
      receipt: parsePendingEnvelope(raw.receipt),
      requiresEscalationFor: (raw.requires_escalation_for as string[] | undefined) ?? [],
      requiresDenyFor: (raw.requires_deny_for as string[] | undefined) ?? [],
      escalationTargets: (raw.escalation_targets as Record<string, string> | undefined) ?? {},
      budgetLimitMicros: optionalNumber(raw, "budget_limit_micros"),
      budgetSpentMicros: optionalNumber(raw, "budget_spent_micros"),
      replacedAuthorizationId: optionalString(raw, "replaced_authorization_id"),
      revocationReceipt: raw.revocation_receipt == null
        ? null
        : parsePendingEnvelope(raw.revocation_receipt),
    };
  }

  async revoke(
    authorizationId: string,
    opts: { revokedBy?: string; supersededBy?: string; notes?: string; idempotencyKey?: string } = {}
  ): Promise<AuthorizationRevokeResponse> {
    const body: Record<string, string> = {};
    if (opts.revokedBy) body.revoked_by = opts.revokedBy;
    if (opts.supersededBy) body.superseded_by = opts.supersededBy;
    if (opts.notes) body.notes = opts.notes;
    const raw = await this.client.request<Record<string, unknown>>(
      "DELETE",
      `/v1/authorizations/${authorizationId}`,
      Object.keys(body).length ? body : undefined,
      {
        headers: opts.idempotencyKey !== undefined
          ? { "Idempotency-Key": opts.idempotencyKey }
          : undefined,
      },
    );
    return {
      authorizationId: requireString(raw, "authorization_id"),
      revokedAt: requireString(raw, "revoked_at"),
      receipt: parsePendingEnvelope(raw.receipt),
      revokedConfirmations: (raw.revoked_confirmations as string[] | undefined) ?? [],
    };
  }
}

class ConfirmationsResource {
  constructor(private readonly client: Allowly) {}

  async approve(nonce: string, req: ConfirmationApproveRequest): Promise<ConfirmationApproveResponse> {
    const raw = await this.client.request<Record<string, unknown>>(
      "POST",
      `/v1/confirmations/${nonce}`,
      { approved: req.approved, ttl_seconds: req.ttlSeconds ?? 60 },
      {
        headers: req.idempotencyKey !== undefined
          ? { "Idempotency-Key": req.idempotencyKey }
          : undefined,
      },
    );
    const decision = requireString(raw, "decision");
    if (decision !== "approved" && decision !== "denied_by_user") {
      throw new AllowlyProtocolError(`unknown confirmation decision: ${JSON.stringify(decision)}`);
    }
    return {
      decision,
      authorizationId: raw.authorization_id == null
        ? undefined
        : requireString(raw, "authorization_id"),
      expiresAt: raw.expires_at == null ? undefined : requireString(raw, "expires_at"),
    };
  }
}

class EscalationsResource {
  constructor(private readonly client: Allowly) {}

  async resolve(escalationId: string, req: EscalationResolveRequest): Promise<EscalationResolveResponse> {
    const raw = await this.client.request<Record<string, unknown>>(
      "POST",
      `/v1/escalations/${escalationId}/resolve`,
      {
        resolution: req.resolution,
        resolved_by: req.resolvedBy,
        note: req.note ?? null,
      }
    );
    const status = requireString(raw, "status");
    if (status !== "approved" && status !== "rejected") {
      throw new AllowlyProtocolError(`unknown escalation status: ${JSON.stringify(status)}`);
    }
    return {
      escalationId: requireString(raw, "escalation_id"),
      status,
      resolvedBy: optionalString(raw, "resolved_by"),
      resolvedAt: optionalString(raw, "resolved_at"),
      receipt: raw.receipt ? parsePendingEnvelope(raw.receipt) : null,
    };
  }

  async approve(
    escalationId: string,
    req: Omit<EscalationResolveRequest, "resolution">
  ): Promise<EscalationResolveResponse> {
    return this.resolve(escalationId, { ...req, resolution: "approved" });
  }

  async reject(
    escalationId: string,
    req: Omit<EscalationResolveRequest, "resolution">
  ): Promise<EscalationResolveResponse> {
    return this.resolve(escalationId, { ...req, resolution: "rejected" });
  }
}

class ReceiptsResource {
  constructor(private readonly client: Allowly) {}

  async get(receiptId: string): Promise<ReceiptEnvelope> {
    return this.getWithSignal(receiptId);
  }

  private async getWithSignal(receiptId: string, signal?: AbortSignal): Promise<ReceiptEnvelope> {
    const raw = await this.client.request<Record<string, unknown>>(
      "GET",
      `/v1/receipts/${receiptId}`,
      undefined,
      { signal },
    );
    return parseReceiptEnvelope(raw);
  }

  async fetchSigned(
    receiptId: string,
    opts: { pollInterval?: number; timeout?: number } = {}
  ): Promise<Record<string, unknown>> {
    const pollInterval = (opts.pollInterval ?? 1) * 1000;
    const timeoutSeconds = opts.timeout ?? 30;
    if (pollInterval <= 0) throw new Error("pollInterval must be positive");
    if (timeoutSeconds <= 0) throw new Error("timeout must be positive");

    const timeoutMs = timeoutSeconds * 1000;
    const deadline = Date.now() + timeoutMs;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      while (Date.now() < deadline) {
        try {
          const envelope = await this.getWithSignal(receiptId, controller.signal);
          if (envelope.status === "signed") return envelope.receipt;
        } catch (err) {
          if (isAbortError(err)) break;
          throw err;
        }
        await sleep(Math.min(pollInterval, Math.max(0, deadline - Date.now())));
      }
    } finally {
      clearTimeout(timer);
    }
    throw new Error(`Receipt ${receiptId} not signed after ${timeoutSeconds}s`);
  }
}

function parsePendingEnvelope(value: unknown): ReceiptEnvelopePending {
  const raw = requireRecord(value, "pending receipt envelope");
  if (raw.status !== "pending") {
    throw new AllowlyProtocolError("receipt status must be 'pending'");
  }
  return {
    status: "pending",
    receiptId: optionalString(raw, "receipt_id"),
    readyAtEstimate: optionalString(raw, "ready_at_estimate"),
    url: optionalString(raw, "url"),
  };
}

function parseReceiptEnvelope(value: unknown): ReceiptEnvelope {
  const raw = requireRecord(value, "receipt envelope");
  if (raw.status === "signed") {
    return { status: "signed", receipt: requireRecord(raw.receipt, "signed receipt") };
  }
  if (raw.status === "pending") return parsePendingEnvelope(raw);
  throw new AllowlyProtocolError("receipt status must be 'pending' or 'signed'");
}

function parseCheckResponse(value: unknown): CheckResponse {
  // The API returns a map keyed by requested action. Preserve those keys so
  // callers can safely handle mixed allow/deny/confirm/escalate results in one check.
  const raw = requireRecord(value, "check response");
  const rawResults = requireRecord(raw.results, "check results");
  return {
    userId: optionalString(raw, "user_id"),
    agentId: optionalString(raw, "agent_id"),
    authorizationId: requireString(raw, "authorization_id"),
    authorizationExpiresAt: optionalString(raw, "authorization_expires_at"),
    engineVersion: requireString(raw, "engine_version"),
    results: Object.fromEntries(
      Object.entries(rawResults).map(([action, value]) => {
        const result = requireRecord(value, `check result ${JSON.stringify(action)}`);
        const decision = requireString(result, "decision");
        const base = {
          reason: requireString(result, "reason"),
          receipt: parseReceiptEnvelope(result.receipt),
          isFallback: Boolean(result.is_fallback ?? false),
          fallbackMode: (result.fallback_mode as FallbackMode | null | undefined) ?? null,
          budget: parseBudgetInfo(result.budget),
          escalation: parseEscalationInfo(result.escalation),
          policyEval: parsePolicyEval(result.policy_eval),
        };

        if (decision === "allow") return [action, { ...base, decision }];
        if (decision === "deny") {
          return [action, {
            ...base,
            decision,
            supersededBy: optionalString(result, "superseded_by"),
          }];
        }
        if (decision === "confirm") {
          return [action, {
            ...base,
            decision,
            confirmNonce: requireString(result, "confirm_nonce"),
            confirmExpiresAt: requireString(result, "confirm_expires_at"),
            confirmPromptHint: requireString(result, "confirm_prompt_hint"),
          }];
        }
        if (decision === "escalate") {
          return [action, {
            ...base,
            decision,
            escalationId: requireString(result, "escalation_id"),
            escalationTo: optionalString(result, "escalation_to"),
            escalationExpiresAt: optionalString(result, "escalation_expires_at"),
          }];
        }
        throw new AllowlyProtocolError(`unknown check decision: ${JSON.stringify(decision)}`);
      })
    ) as CheckResponse["results"],
  };
}

function requireRecord(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new AllowlyProtocolError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireString(raw: Record<string, unknown>, key: string): string {
  const value = raw[key];
  if (typeof value !== "string") {
    throw new AllowlyProtocolError(`${key} must be a string`);
  }
  return value;
}

function optionalString(raw: Record<string, unknown>, key: string): string | null {
  const value = raw[key];
  if (value == null) return null;
  if (typeof value !== "string") {
    throw new AllowlyProtocolError(`${key} must be a string or null`);
  }
  return value;
}

function optionalNumber(raw: Record<string, unknown>, key: string): number | null {
  const value = raw[key];
  if (value == null) return null;
  if (typeof value !== "number") {
    throw new AllowlyProtocolError(`${key} must be a number or null`);
  }
  return value;
}

function parseBudgetInfo(raw: unknown): BudgetInfo | null {
  if (!raw || typeof raw !== "object") return null;
  const budget = raw as Record<string, unknown>;
  return {
    limitMicros: budget.limit_micros as number,
    spentMicros: budget.spent_micros as number,
    estimatedCostMicros: budget.estimated_cost_micros as number,
    spentAfterMicros: (budget.spent_after_micros as number | undefined) ?? null,
  };
}

function parseBudgetSettlementResponse(raw: Record<string, unknown>): BudgetSettlementResponse {
  return {
    checkReceiptId: raw.check_receipt_id as string,
    authorizationId: raw.authorization_id as string,
    estimatedCostMicros: raw.estimated_cost_micros as number,
    actualCostMicros: raw.actual_cost_micros as number,
    deltaMicros: raw.delta_micros as number,
    spentBeforeMicros: raw.spent_before_micros as number,
    spentAfterMicros: raw.spent_after_micros as number,
    receipt: parseReceiptEnvelope(raw.receipt as Record<string, unknown>),
  };
}

function parseEscalationInfo(raw: unknown): EscalationInfo | null {
  if (!raw || typeof raw !== "object") return null;
  const escalation = raw as Record<string, unknown>;
  return {
    escalationId: escalation.escalation_id as string,
    status: escalation.status as string,
    escalationTo: (escalation.escalation_to as string | undefined) ?? null,
    expiresAt: (escalation.expires_at as string | undefined) ?? null,
  };
}

function parsePolicyEval(raw: unknown): PolicyEvalInfo | null {
  if (!raw || typeof raw !== "object") return null;
  const policyEval = raw as Record<string, unknown>;
  const matched = policyEval.matched_condition;
  return {
    matchedCondition:
      matched && typeof matched === "object"
        ? {
            field: (matched as Record<string, unknown>).field as string,
            op: (matched as Record<string, unknown>).op as string,
            value: (matched as Record<string, unknown>).value as PolicyConditionEvidence["value"],
          }
        : null,
    fieldValue: policyEval.field_value as PolicyEvalInfo["fieldValue"],
  };
}

function validateFallbackMode(mode: string): FallbackMode {
  if (mode !== "fail_open" && mode !== "fail_closed") {
    throw new Error("fallback mode must be 'fail_open' or 'fail_closed'");
  }
  return mode;
}

function validateBaseUrl(baseUrl: string, allowInsecure: boolean): string {
  const normalized = baseUrl.replace(/\/$/, "");
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("baseUrl must be a valid URL");
  }
  if (parsed.protocol !== "https:" && !allowInsecure) {
    throw new Error("baseUrl must use HTTPS");
  }
  return normalized;
}

function isAbortError(err: unknown): boolean {
  const name = (err as { name?: string } | null)?.name;
  return name === "AbortError" || name === "TimeoutError";
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
