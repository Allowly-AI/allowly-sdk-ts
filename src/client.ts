import { AllowlyAPIError } from "./error.js";
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
  EscalationInfo,
  PolicyConditionEvidence,
  PolicyEvalInfo,
  EscalationResolveRequest,
  EscalationResolveResponse,
  ReceiptEnvelope,
  ReceiptEnvelopePending,
  ReceiptEnvelopeSigned,
} from "./types.js";

const DEFAULT_BASE_URL = "https://api.allowly.ai";
const DEFAULT_CHECK_TIMEOUT_MS = 1000;

export class Allowly {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly _fetch: typeof globalThis.fetch;
  private readonly checkTimeoutMs: number;
  private readonly defaultFallback: FallbackMode;
  private readonly fallbackByScope: Record<string, FallbackMode>;

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
    this.defaultFallback = validateFallbackMode(options.defaultFallback ?? "fail_closed");
    this.fallbackByScope = Object.fromEntries(
      Object.entries(options.fallbackByScope ?? {}).map(([scope, mode]) => [
        scope,
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
    opts: { signal?: AbortSignal } = {}
  ): Promise<T> {
    const res = await this._fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: opts.signal,
    });

    if (res.status === 204) return undefined as T;

    const json = await res.json();

    if (!res.ok) {
      const err = (json as { error?: { code: string; message: string; fields?: Array<{ field: string; message: string }> } }).error;
      throw new AllowlyAPIError(res.status, err ?? { code: "error", message: "Unknown error" });
    }

    return json as T;
  }

  async check(req: {
    authorizationId: string;
    scopes: string[];
    resource?: string;
    sessionId?: string;
    estimatedCostMicros?: number;
    context?: Record<string, unknown>;
    wait?: boolean;
  }): Promise<CheckResponse> {
    const path = "/v1/check" + (req.wait ? "?wait=true" : "");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.checkTimeoutMs);
    const body = {
      authorization_id: req.authorizationId,
      scopes: req.scopes,
      resource: req.resource,
      session_id: req.sessionId,
      estimated_cost_micros: req.estimatedCostMicros,
      context: req.context ?? {},
    };
    try {
      const raw = await this.request<Record<string, unknown>>("POST", path, body, {
        signal: controller.signal,
      });
      return parseCheckResponse(raw);
    } catch (err) {
      if (isAbortError(err)) {
        return this.fallbackCheckResponse(req.authorizationId, req.scopes, "timeout");
      }
      if (err instanceof AllowlyAPIError) {
        if (err.status >= 500) {
          return this.fallbackCheckResponse(req.authorizationId, req.scopes, "unreachable");
        }
        throw err;
      }
      if (err instanceof TypeError) {
        return this.fallbackCheckResponse(req.authorizationId, req.scopes, "unreachable");
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  private fallbackModeForScope(scope: string): FallbackMode {
    return this.fallbackByScope[scope] ?? this.defaultFallback;
  }

  private fallbackCheckResponse(
    authorizationId: string,
    scopes: string[],
    failure: "timeout" | "unreachable"
  ): CheckResponse {
    return {
      authorizationId,
      userId: null,
      agentId: null,
      authorizationExpiresAt: null,
      policyVersion: "sdk_fallback",
      results: Object.fromEntries(
        scopes.map((scope) => {
          const fallbackMode = this.fallbackModeForScope(scope);
          const opened = fallbackMode === "fail_open";
          return [
            scope,
            {
              decision: opened ? "allow" : "deny",
              reason: `fallback_${opened ? "open" : "closed"}_${failure}`,
              receipt: null,
              isFallback: true,
              fallbackMode,
              budget: null,
              escalation: null,
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
    const scopes = req.scopes?.map((s) =>
      typeof s === "string"
        ? { name: s, constraints: {} }
        : { name: s.name, constraints: s.constraints ?? {} }
    );
    const raw = await this.client.request<Record<string, unknown>>("POST", "/v1/authorizations", {
      user_id: req.userId,
      agent_id: req.agentId,
      policy_id: req.policyId,
      scopes,
      requires_confirm_for: req.requiresConfirmFor ?? [],
      requires_escalation_for: req.requiresEscalationFor ?? [],
      escalation_targets: req.escalationTargets ?? {},
      budget_limit_micros: req.budgetLimitMicros,
      expires_at: expiresAt,
      replaces: req.replaces,
      metadata: req.metadata ?? {},
    });
    return {
      authorizationId: raw.authorization_id as string,
      policyId: raw.policy_id as string | undefined,
      createdAt: raw.created_at as string,
      expiresAt: raw.expires_at as string,
      receipt: parsePendingEnvelope(raw.receipt as Record<string, unknown>),
      requiresConfirmFor: (raw.requires_confirm_for as string[] | undefined) ?? [],
      requiresEscalationFor: (raw.requires_escalation_for as string[] | undefined) ?? [],
      escalationTargets: (raw.escalation_targets as Record<string, string> | undefined) ?? {},
      budgetLimitMicros: raw.budget_limit_micros as number | undefined,
      budgetSpentMicros: raw.budget_spent_micros as number | undefined,
    };
  }

  async revoke(
    authorizationId: string,
    opts: { revokedBy?: string; supersededBy?: string; notes?: string } = {}
  ): Promise<AuthorizationRevokeResponse> {
    const body: Record<string, string> = {};
    if (opts.revokedBy) body.revoked_by = opts.revokedBy;
    if (opts.supersededBy) body.superseded_by = opts.supersededBy;
    if (opts.notes) body.notes = opts.notes;
    const raw = await this.client.request<Record<string, unknown>>(
      "DELETE",
      `/v1/authorizations/${authorizationId}`,
      Object.keys(body).length ? body : undefined
    );
    return {
      authorizationId: raw.authorization_id as string,
      revokedAt: raw.revoked_at as string,
      receipt: parsePendingEnvelope(raw.receipt as Record<string, unknown>),
    };
  }
}

class ConfirmationsResource {
  constructor(private readonly client: Allowly) {}

  async approve(nonce: string, req: ConfirmationApproveRequest): Promise<ConfirmationApproveResponse> {
    const raw = await this.client.request<Record<string, unknown>>(
      "POST",
      `/v1/confirmations/${nonce}`,
      { approved: req.approved, ttl_seconds: req.ttlSeconds ?? 60 }
    );
    return {
      decision: raw.decision as "approved" | "denied_by_user",
      authorizationId: raw.authorization_id as string | undefined,
      expiresAt: raw.expires_at as string | undefined,
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
    return {
      escalationId: raw.escalation_id as string,
      status: raw.status as "approved" | "rejected",
      resolvedBy: raw.resolved_by as string | null | undefined,
      resolvedAt: raw.resolved_at as string | null | undefined,
      receipt: raw.receipt ? parsePendingEnvelope(raw.receipt as Record<string, unknown>) : null,
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
    const raw = await this.client.request<Record<string, unknown>>("GET", `/v1/receipts/${receiptId}`);
    return parseReceiptEnvelope(raw);
  }

  async fetchSigned(
    receiptId: string,
    opts: { pollInterval?: number; timeout?: number } = {}
  ): Promise<Record<string, unknown>> {
    const pollInterval = (opts.pollInterval ?? 1) * 1000;
    const deadline = Date.now() + (opts.timeout ?? 30) * 1000;

    while (Date.now() < deadline) {
      const envelope = await this.get(receiptId);
      if (envelope.status === "signed") return (envelope as ReceiptEnvelopeSigned).receipt;
      await sleep(pollInterval);
    }
    throw new Error(`Receipt ${receiptId} not signed after ${opts.timeout ?? 30}s`);
  }
}

function parsePendingEnvelope(raw: Record<string, unknown>): ReceiptEnvelopePending {
  return {
    status: "pending",
    receiptId: raw.receipt_id as string,
    readyAtEstimate: raw.ready_at_estimate as string,
    url: raw.url as string,
  };
}

function parseReceiptEnvelope(raw: Record<string, unknown>): ReceiptEnvelope {
  if (raw.status === "signed") {
    return { status: "signed", receipt: raw.receipt as Record<string, unknown> };
  }
  return parsePendingEnvelope(raw);
}

function parseCheckResponse(raw: Record<string, unknown>): CheckResponse {
  // The API returns a map keyed by requested scope. Preserve those keys so
  // callers can safely handle mixed allow/deny/confirm/escalate results in one check.
  return {
    userId: raw.user_id as string,
    agentId: raw.agent_id as string,
    authorizationId: raw.authorization_id as string,
    authorizationExpiresAt: raw.authorization_expires_at as string,
    policyVersion: raw.policy_version as string,
    results: Object.fromEntries(
      Object.entries(raw.results as Record<string, Record<string, unknown>>).map(([scope, result]) => [
        scope,
        {
          decision: result.decision,
          reason: result.reason,
          receipt: parseReceiptEnvelope(result.receipt as Record<string, unknown>),
          isFallback: Boolean(result.is_fallback ?? false),
          fallbackMode: (result.fallback_mode as FallbackMode | null | undefined) ?? null,
          budget: parseBudgetInfo(result.budget),
          escalation: parseEscalationInfo(result.escalation),
          policyEval: parsePolicyEval(result.policy_eval),
          confirmNonce: result.confirm_nonce,
          confirmExpiresAt: result.confirm_expires_at,
          confirmPromptHint: result.confirm_prompt_hint,
          escalationId: result.escalation_id,
          escalationTo: result.escalation_to,
          escalationExpiresAt: result.escalation_expires_at,
        },
      ])
    ) as CheckResponse["results"],
  };
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
  return (
    typeof err === "object" &&
    err !== null &&
    "name" in err &&
    (err as { name?: string }).name === "AbortError"
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
