import { AllowlyAPIError, AllowlyProtocolError } from "./error.js";
import { ResolutionWebhookResource } from "./resolution-webhook.js";
import {
  SEAL_ACTION,
  SEAL_AGENT_ID,
  SEAL_PROFILE,
  SEAL_USER_ID,
  hashSealJson,
  hashSealValue,
} from "./verify.js";
import type {
  AllowlyOptions,
  CustomExecutableCreateRequest,
  EnabledExecutableResponse,
  ExecutableEvidenceCapability,
  CheckResponse,
  FallbackMode,
  AuthorizationCreateRequest,
  AuthorizationCreateResponse,
  AuthorizationRevokeResponse,
  ConfirmationApproveRequest,
  ConfirmationApproveResponse,
  ConfirmationStatusResponse,
  EscalationStatusResponse,
  ConfirmationStatus,
  BudgetInfo,
  BudgetSettlementResponse,
  EscalationInfo,
  PolicyConditionEvidence,
  PolicyEvalInfo,
  EscalationResolveRequest,
  EscalationResolveResponse,
  EscalationStatus,
  PromptStatus,
  PrepareExecutionRequest,
  ContinueExecutionRequest,
  CustomerExecutionResponse,
  ClaimExecutionDispatchRequest,
  ClaimExecutionDispatchResponse,
  GetExecutionWitnessTokenRequest,
  ExecutionWitnessTokenResponse,
  ReportExecutionOutcomeRequest,
  CustomerHttpOptions,
  CustomerHttpExecutionResult,
  ResumeHttpExecutionRequest,
  OutcomeEvidence,
  ReceiptEnvelope,
  ReceiptEnvelopePending,
  ReceiptAcknowledgmentRequest,
  ReceiptAcknowledgmentResponse,
  SealRequest,
  SealResponse,
} from "./types.js";
import {
  executeHttp as executeCustomerHttp,
  continueHttpExecution as continueCustomerHttpExecution,
  resumeHttpExecution as resumeCustomerHttpExecution,
} from "./customer-execution.js";

const DEFAULT_BASE_URL = "https://api.allowly.ai";
const DEFAULT_CHECK_TIMEOUT_MS = 1000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

export class AllowlyTransportError extends Error {
  readonly cause: unknown;

  constructor(cause: unknown) {
    super("Allowly request failed");
    this.name = "AllowlyTransportError";
    this.cause = cause;
  }
}

export class Allowly {
  private readonly apiKey: string;
  private readonly agentToken: string | undefined;
  private readonly agentTokenSupplier: (() => string | Promise<string>) | undefined;
  private readonly edgeToken: string | undefined;
  private readonly baseUrl: string;
  private readonly _fetch: typeof globalThis.fetch;
  private readonly checkTimeoutMs: number;
  private readonly requestTimeoutMs: number;
  private readonly fallbackByAction: Record<string, FallbackMode>;

  readonly authorizations: AuthorizationsResource;
  readonly confirmations: ConfirmationsResource;
  readonly escalations: EscalationsResource;
  readonly receipts: ReceiptsResource;
  readonly resolutionWebhook: ResolutionWebhookResource;

  constructor(options: AllowlyOptions) {
    this.apiKey = options.apiKey;
    this.agentToken = options.agentToken;
    this.agentTokenSupplier = options.agentTokenSupplier;
    this.edgeToken = options.edgeToken;
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
    this.resolutionWebhook = new ResolutionWebhookResource(this);
  }

  /** Runtime readiness only; does not test policy or provider permission. */
  async readiness(): Promise<boolean> {
    const raw = requireRecord(await this.request<unknown>("GET", "/readyz"), "readiness response");
    return requireString(raw, "status") === "ready";
  }

  /** @internal */
  async request<T>(
    method: string,
    path: string,
    body?: unknown,
    opts: {
      signal?: AbortSignal;
      headers?: Record<string, string>;
      expectedStatus?: number | readonly number[];
    } = {}
  ): Promise<T> {
    const { data } = await this.requestWithHeaders<T>(method, path, body, opts);
    return data;
  }

  /** @internal */
  async requestWithHeaders<T>(
    method: string,
    path: string,
    body?: unknown,
    opts: {
      signal?: AbortSignal;
      headers?: Record<string, string>;
      expectedStatus?: number | readonly number[];
    } = {}
  ): Promise<{ data: T; headers: Headers }> {
    const serializedBody = body !== undefined ? JSON.stringify(body) : undefined;
    const requestAgentToken = opts.headers?.["X-Allowly-Agent-Token"];
    const sensitiveValues = [this.apiKey, this.edgeToken, requestAgentToken]
      .filter((value): value is string => typeof value === "string" && value.length > 0);
    const safeErrorText = (value: unknown, fallback: string): string => {
      let rendered = typeof value === "string" ? value : fallback;
      for (const sensitiveValue of sensitiveValues) {
        rendered = rendered.split(sensitiveValue).join("[REDACTED]");
      }
      return rendered;
    };
    let res: Response;
    try {
      res = await this._fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          ...(this.edgeToken !== undefined
            ? { "X-Allowly-Edge-Token": this.edgeToken }
            : {}),
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
          ...opts.headers,
        },
        body: serializedBody,
        redirect: "manual",
        signal: opts.signal ?? AbortSignal.timeout(this.requestTimeoutMs),
      });
    } catch (err) {
      if (isAbortError(err)) throw err;
      const safeCause = new Error(safeErrorText(
        err instanceof Error ? err.message : undefined,
        "Allowly transport failed",
      ));
      throw new AllowlyTransportError(safeCause);
    }

    if (res.redirected) throw new AllowlyProtocolError("redirected responses are not allowed");
    const expectedStatuses = Array.isArray(opts.expectedStatus)
      ? opts.expectedStatus
      : [opts.expectedStatus ?? 200];
    if (res.ok && !expectedStatuses.includes(res.status)) {
      throw new AllowlyProtocolError(
        `unexpected successful HTTP status: got ${res.status}, want ${expectedStatuses.join(" or ")}`,
      );
    }
    if (res.status === 204) return { data: undefined as T, headers: res.headers };

    let json: unknown = null;
    try {
      json = await res.json();
    } catch (err) {
      if (res.ok) throw new AllowlyProtocolError("successful response was not valid JSON");
    }

    if (!res.ok) {
      const retryAfterSeconds = parseRetryAfter(res.headers.get("Retry-After"));
      const rawError = json && typeof json === "object"
        ? (json as Record<string, unknown>).error
        : undefined;
      if (typeof rawError === "string") {
        throw new AllowlyAPIError(
          res.status,
          { code: "error", message: safeErrorText(rawError, "Unknown error") },
          retryAfterSeconds,
        );
      }
      const error = rawError && typeof rawError === "object"
        ? rawError as Record<string, unknown>
        : {};
      const fields = Array.isArray(error.fields)
        ? error.fields.filter((field): field is { field: string; message: string } =>
            !!field && typeof field === "object"
            && typeof (field as Record<string, unknown>).field === "string"
            && typeof (field as Record<string, unknown>).message === "string")
        : undefined;
      throw new AllowlyAPIError(res.status, {
        code: safeErrorText(error.code, "error"),
        message: safeErrorText(error.message, res.statusText || "Unknown error"),
        fields: fields?.map((field) => ({
          field: safeErrorText(field.field, ""),
          message: safeErrorText(field.message, ""),
        })),
      }, retryAfterSeconds);
    }

    return { data: json as T, headers: res.headers };
  }

  /** Create one immutable, customer-defined operation with a setup credential. */
  async createCustomExecutable(req: CustomExecutableCreateRequest): Promise<EnabledExecutableResponse> {
    const raw = await this.request<unknown>("POST", "/v1/setup/custom-executables", {
      name: req.name,
      url: req.url,
      method: req.method,
      request_content_type: req.requestContentType ?? null,
      required_headers: req.requiredHeaders ?? [],
    }, { expectedStatus: 201 });
    return parseCustomExecutableResponse(raw);
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
    clientTimestamp?: Date | string;
    agentToken?: string;
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
      ...(req.clientTimestamp !== undefined
        ? { client_timestamp: clientTimestamp(req.clientTimestamp) }
        : {}),
    };
    const identityHeaders = await this.identityHeaders(req.agentToken, req.idempotencyKey);
    const identityEnabled = identityHeaders?.["X-Allowly-Agent-Token"] !== undefined;
    try {
      const { data: raw, headers } = await this.requestWithHeaders<Record<string, unknown>>("POST", path, body, {
        signal: controller.signal,
        headers: identityHeaders,
      });
      const response = parseCheckResponse(raw, req.authorizationId, req.actions);
      const billingWarning = headers.get("X-Allowly-Billing-Warning");
      if (billingWarning !== null) response.billingWarning = billingWarning;
      return response;
    } catch (err) {
      if (isAbortError(err)) {
        return this.fallbackCheckResponse(req.authorizationId, req.actions, "timeout", identityEnabled);
      }
      if (err instanceof AllowlyAPIError) {
        if (err.code === "identity_verification_unavailable") throw err;
        if (err.status === 408) {
          return this.fallbackCheckResponse(req.authorizationId, req.actions, "timeout", identityEnabled);
        }
        if (err.status >= 500) {
          return this.fallbackCheckResponse(req.authorizationId, req.actions, "unreachable", identityEnabled);
        }
        throw err;
      }
      if (err instanceof AllowlyTransportError) {
        return this.fallbackCheckResponse(req.authorizationId, req.actions, "unreachable", identityEnabled);
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async identityHeaders(
    explicitAgentToken?: string,
    idempotencyKey?: string,
  ): Promise<Record<string, string> | undefined> {
    let token = explicitAgentToken;
    if (token === undefined && this.agentTokenSupplier !== undefined) {
      token = await this.agentTokenSupplier();
      if (typeof token !== "string" || token.trim().length === 0) {
        throw new Error("agent token supplier must return a non-empty string");
      }
    } else if (token === undefined) token = this.agentToken;
    const headers: Record<string, string> = {};
    if (token !== undefined) {
      if (typeof token !== "string" || token.trim().length === 0) {
        throw new Error("agent token must be a non-empty string");
      }
      headers["X-Allowly-Agent-Token"] = token;
    }
    if (idempotencyKey !== undefined) headers["Idempotency-Key"] = idempotencyKey;
    return Object.keys(headers).length > 0 ? headers : undefined;
  }

  async seal(
    recordJson: string | Uint8Array,
    req: SealRequest,
  ): Promise<SealResponse> {
    return this.sealDigest(hashSealJson(recordJson), req);
  }

  async sealValue(record: unknown, req: SealRequest): Promise<SealResponse> {
    return this.sealDigest(hashSealValue(record), req);
  }

  private async sealDigest(recordSha256: string, req: SealRequest): Promise<SealResponse> {
    if (typeof req.requestId !== "string" || req.requestId.length === 0) {
      throw new Error("requestId must be a non-empty string");
    }
    const pollInterval = req.pollInterval ?? 1;
    const timeout = req.timeout ?? 120;
    if (pollInterval <= 0) throw new Error("pollInterval must be positive");
    if (timeout <= 0) throw new Error("timeout must be positive");
    const metadata = validateSealMetadata(req.metadata);
    const body: Record<string, unknown> = {
      request_id: req.requestId,
      profile: SEAL_PROFILE,
      record_sha256: recordSha256,
    };
    if (metadata !== undefined) body.metadata = metadata;

    const raw = requireRecord(
      await this.request<unknown>("POST", "/v1/seal", body),
      "seal response",
    );
    if (requireString(raw, "request_id") !== req.requestId) {
      throw new AllowlyProtocolError("seal response request_id does not match the request");
    }
    if (requireString(raw, "profile") !== SEAL_PROFILE) {
      throw new AllowlyProtocolError("seal response profile does not match the request");
    }
    if (requireString(raw, "record_sha256") !== recordSha256) {
      throw new AllowlyProtocolError("seal response record_sha256 does not match the request");
    }
    const workspaceId = requireString(raw, "workspace_id");
    if (workspaceId.length === 0) {
      throw new AllowlyProtocolError("seal response workspace_id must be non-empty");
    }
    if (requireString(raw, "decision") !== "allow") {
      throw new AllowlyProtocolError("seal response decision must be 'allow'");
    }
    const reason = requireString(raw, "reason");
    const envelope = parseReceiptEnvelope(raw.receipt);
    const pendingReceiptId = envelope.status === "pending" ? envelope.receiptId : undefined;
    const receipt = envelope.status === "signed"
      ? envelope.receipt
      : await this.receipts.fetchSigned(envelope.receiptId, { pollInterval, timeout });
    validateSealReceipt(receipt, recordSha256, workspaceId, pendingReceiptId);
    return {
      requestId: req.requestId,
      workspaceId,
      profile: SEAL_PROFILE,
      recordSha256,
      decision: "allow",
      reason,
      receipt,
    };
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

  /** Prepare a customer-local HTTP execution without sending private bytes. */
  async prepareExecution(req: PrepareExecutionRequest): Promise<CustomerExecutionResponse> {
    const raw = await this.request<Record<string, unknown>>(
      "POST",
      "/v1/execute",
      serializeExecutionRequest(req),
      {
        headers: await this.identityHeaders(req.agentToken, req.idempotencyKey),
        expectedStatus: [200, 201],
      },
    );
    const response = parseCustomerExecutionResponse(raw);
    validateExecutionResponseScope(response, req);
    return response;
  }

  /** Continue a waiting operation; approval alone never sends private bytes. */
  async continueExecution(req: ContinueExecutionRequest): Promise<CustomerExecutionResponse> {
    const original = req.executionRequest;
    const raw = await this.request<Record<string, unknown>>(
      "POST",
      `/v1/executions/${encodeURIComponent(original.operationId)}/continue`,
      {
        execution_request: serializeExecutionRequest(original),
        review_id: req.reviewId,
        source_receipt_id: req.sourceReceiptId,
      },
      {
        headers: await this.identityHeaders(req.agentToken, req.idempotencyKey),
        expectedStatus: [200, 201],
      },
    );
    const response = parseCustomerExecutionResponse(raw);
    validateExecutionResponseScope(response, original);
    return response;
  }

  async claimExecutionDispatch(
    req: ClaimExecutionDispatchRequest,
  ): Promise<ClaimExecutionDispatchResponse> {
    const raw = await this.request<Record<string, unknown>>(
      "POST",
      `/v1/executions/${encodeURIComponent(req.operationId)}/dispatch`,
      { approval_sha256: req.approvalSha256 },
      { headers: await this.identityHeaders(req.agentToken) },
    );
    return parseDispatchResponse(raw, req.operationId, req.approvalSha256);
  }

  async getExecutionWitnessToken(
    req: GetExecutionWitnessTokenRequest,
  ): Promise<ExecutionWitnessTokenResponse> {
    const raw = await this.request<Record<string, unknown>>(
      "POST",
      `/v1/executions/${encodeURIComponent(req.operationId)}/witness-session-token`,
      { approval_sha256: req.approvalSha256 },
      { headers: await this.identityHeaders(req.agentToken) },
    );
    return parseWitnessTokenResponse(raw, req.approvalSha256);
  }

  async reportExecutionOutcome(
    req: ReportExecutionOutcomeRequest,
  ): Promise<CustomerExecutionResponse> {
    const raw = await this.request<Record<string, unknown>>(
      "POST",
      `/v1/executions/${encodeURIComponent(req.operationId)}/outcome`,
      {
        approval_sha256: req.approvalSha256,
        target_state: req.targetState,
        dispatch_started_at: clientTimestamp(req.dispatchStartedAt),
        completed_at: clientTimestamp(req.completedAt),
        ...(req.httpStatus !== undefined ? { http_status: req.httpStatus } : {}),
        ...(req.responseSha256 !== undefined ? { response_sha256: req.responseSha256 } : {}),
        ...(req.responseSize !== undefined ? { response_size: req.responseSize } : {}),
        ...(req.providerOperationId !== undefined
          ? { provider_operation_id: req.providerOperationId }
          : {}),
        ...(req.evidenceBundleSha256 !== undefined
          ? { evidence_bundle_sha256: req.evidenceBundleSha256 }
          : {}),
        ...(req.notaryAttestation !== undefined
          ? { notary_attestation: req.notaryAttestation }
          : {}),
      },
      {
        headers: await this.identityHeaders(req.agentToken, req.idempotencyKey),
        expectedStatus: [200, 201],
      },
    );
    const response = parseCustomerExecutionResponse(raw);
    if (response.operationId !== req.operationId
        || response.approvalSha256 !== req.approvalSha256) {
      throw new AllowlyProtocolError("customer execution outcome does not match the request");
    }
    return response;
  }

  async executeHttp(
    url: string | URL,
    options: CustomerHttpOptions,
  ): Promise<CustomerHttpExecutionResult> {
    return executeCustomerHttp(this, url, options);
  }

  async continueHttpExecution(
    url: string | URL,
    options: CustomerHttpOptions,
  ): Promise<CustomerHttpExecutionResult> {
    return continueCustomerHttpExecution(this, url, options);
  }

  async resumeHttpExecution(
    req: ResumeHttpExecutionRequest,
  ): Promise<CustomerHttpExecutionResult> {
    return resumeCustomerHttpExecution(this, req);
  }

  async getExecution(
    operationId: string,
    opts: { agentToken?: string } = {},
  ): Promise<CustomerExecutionResponse> {
    const raw = await this.request<Record<string, unknown>>(
      "GET",
      `/v1/executions/${encodeURIComponent(operationId)}`,
      undefined,
      { headers: await this.identityHeaders(opts.agentToken) },
    );
    const response = parseCustomerExecutionResponse(raw);
    if (response.operationId !== operationId) {
      throw new AllowlyProtocolError("execution response does not match the requested operation");
    }
    return response;
  }

  async acknowledgeReceipt(
    req: ReceiptAcknowledgmentRequest,
  ): Promise<ReceiptAcknowledgmentResponse> {
    const raw = await this.request<Record<string, unknown>>(
      "POST",
      `/v1/receipts/${encodeURIComponent(req.receiptId)}/acknowledgments`,
      {
        receipt_sha256: req.receiptSha256,
        client_timestamp: clientTimestamp(req.clientTimestamp),
      },
      {
        headers: await this.identityHeaders(req.agentToken, req.idempotencyKey),
        expectedStatus: [200, 201],
      },
    );
    const response = parseReceiptAcknowledgmentResponse(raw);
    if (response.receiptId !== req.receiptId) {
      throw new AllowlyProtocolError(
        "receipt acknowledgment response does not match the requested receipt",
      );
    }
    return response;
  }

  async getReceiptAcknowledgment(
    receiptId: string,
    acknowledgmentId: string,
    opts: { agentToken?: string } = {},
  ): Promise<ReceiptAcknowledgmentResponse> {
    const raw = await this.request<Record<string, unknown>>(
      "GET",
      `/v1/receipts/${encodeURIComponent(receiptId)}/acknowledgments/${encodeURIComponent(acknowledgmentId)}`,
      undefined,
      { headers: await this.identityHeaders(opts.agentToken) },
    );
    const response = parseReceiptAcknowledgmentResponse(raw);
    if (response.receiptId !== receiptId || response.acknowledgmentId !== acknowledgmentId) {
      throw new AllowlyProtocolError(
        "receipt acknowledgment response does not match the requested acknowledgment",
      );
    }
    return response;
  }

  private fallbackModeForAction(action: string): FallbackMode {
    return Object.prototype.hasOwnProperty.call(this.fallbackByAction, action)
      ? this.fallbackByAction[action]
      : "fail_closed";
  }

  private fallbackCheckResponse(
    authorizationId: string,
    actions: string[],
    failure: "timeout" | "unreachable",
    forceFailClosed = false,
  ): CheckResponse {
    return {
      authorizationId,
      userId: null,
      agentId: null,
      authorizationExpiresAt: null,
      engineVersion: "sdk_fallback",
      results: Object.fromEntries(
        actions.map((action) => {
          const fallbackMode = forceFailClosed
            ? "fail_closed"
            : this.fallbackModeForAction(action);
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
    if (req.policyId !== undefined) {
      const runtimeReq = req as unknown as Record<string, unknown>;
      const override = [
        ["requiresConfirmFor", runtimeReq.requiresConfirmFor],
        ["requiresEscalationFor", runtimeReq.requiresEscalationFor],
        ["requiresDenyFor", runtimeReq.requiresDenyFor],
        ["escalationTargets", runtimeReq.escalationTargets],
      ].find(([, value]) => value !== undefined);
      if (override) throw new Error(`policyId cannot be combined with ${override[0]}`);
    }
    const expiresAt = req.expiresAt instanceof Date ? req.expiresAt.toISOString() : req.expiresAt;
    const actions = req.actions?.map((s) =>
      typeof s === "string"
        ? { name: s, constraints: {} }
        : {
          name: s.name,
          constraints: s.constraints ?? {},
          ...(s.executableOperations !== undefined && s.executableOperations.length > 0
            ? {
              executable_operations: s.executableOperations.map((grant) => ({
                enabled_executable_id: grant.enabledExecutableId,
                provider_id: grant.providerId,
                operation_id: grant.operationId,
                catalog_revision: grant.catalogRevision,
                definition_fingerprint: grant.definitionFingerprint,
                minimum_evidence_mode: grant.minimumEvidenceMode,
              })),
            }
            : {}),
        }
    );
    const inlineDecisionOverrides = req.policyId === undefined
      ? {
          requires_confirm_for: req.requiresConfirmFor ?? [],
          requires_escalation_for: req.requiresEscalationFor ?? [],
          requires_deny_for: req.requiresDenyFor ?? [],
          escalation_targets: req.escalationTargets ?? {},
        }
      : {};
    const { data: raw, headers } = await this.client.requestWithHeaders<Record<string, unknown>>(
      "POST",
      "/v1/authorizations",
      {
        user_id: req.userId,
        agent_id: req.agentId,
        policy_id: req.policyId,
        actions,
        ...inlineDecisionOverrides,
        budget_limit_micros: req.budgetLimitMicros,
        expires_at: expiresAt,
        replaces: req.replaces,
        metadata: req.metadata ?? {},
      },
      {
        headers: req.idempotencyKey !== undefined
          ? { "Idempotency-Key": req.idempotencyKey }
          : undefined,
        expectedStatus: 201,
      },
    );
    const billingWarning = headers.get("X-Allowly-Billing-Warning");
    return {
      ...(billingWarning !== null ? { billingWarning } : {}),
      authorizationId: requireString(raw, "authorization_id"),
      policyId: optionalString(raw, "policy_id"),
      createdAt: requireString(raw, "created_at"),
      expiresAt: requireString(raw, "expires_at"),
      receipt: parsePendingEnvelope(raw.receipt),
      requiresConfirmFor: requireStringArray(raw, "requires_confirm_for"),
      requiresEscalationFor: requireStringArray(raw, "requires_escalation_for"),
      requiresDenyFor: requireStringArray(raw, "requires_deny_for"),
      escalationTargets: requireStringMap(raw, "escalation_targets"),
      budgetLimitMicros: optionalNumber(raw, "budget_limit_micros"),
      budgetSpentMicros: optionalNumber(raw, "budget_spent_micros"),
      replacedAuthorizationId: optionalString(raw, "replaced_authorization_id"),
      revocationReceipt: raw.revocation_receipt == null
        ? null
        : parsePendingEnvelope(raw.revocation_receipt),
      authorizationProvenance: raw.authorization_provenance == null
        ? null
        : requireRecord(raw.authorization_provenance, "authorization provenance"),
    };
  }

  async revoke(
    authorizationId: string,
    opts: { revokedBy?: string; notes?: string; idempotencyKey?: string } = {}
  ): Promise<AuthorizationRevokeResponse> {
    if ((opts as Record<string, unknown>).supersededBy !== undefined) {
      throw new Error(
        "supersededBy is not supported on revoke; create the successor with replaces instead",
      );
    }
    const body: Record<string, string> = {};
    if (opts.revokedBy) body.revoked_by = opts.revokedBy;
    if (opts.notes) body.notes = opts.notes;
    const raw = await this.client.request<Record<string, unknown>>(
      "DELETE",
      `/v1/authorizations/${encodeURIComponent(authorizationId)}`,
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
      revokedConfirmations: requireStringArray(raw, "revoked_confirmations"),
    };
  }
}

class ConfirmationsResource {
  constructor(private readonly client: Allowly) {}

  async getStatus(confirmationId: string): Promise<ConfirmationStatusResponse> {
    requirePromptId(confirmationId, "confirmation");
    return parseConfirmationStatus(await this.client.request<unknown>(
      "GET", `/v1/confirmations/${encodeURIComponent(confirmationId)}/status`,
    ), confirmationId);
  }

  /** Read an opaque cnf_ ID from check, never the approval nonce. */
  async get(confirmationId: string): Promise<ConfirmationStatus> {
    return this.getStatus(confirmationId);
  }

  async approve(nonce: string, req: ConfirmationApproveRequest): Promise<ConfirmationApproveResponse> {
    const raw = await this.client.request<Record<string, unknown>>(
      "POST",
      `/v1/confirmations/${encodeURIComponent(nonce)}`,
      { approved: req.approved, ttl_seconds: req.ttlSeconds ?? 60 },
      {
        headers: req.idempotencyKey !== undefined
          ? { "Idempotency-Key": req.idempotencyKey }
          : undefined,
      },
    );
    const decision = requireString(raw, "decision");
    if (decision !== "approved" && decision !== "not_approved" && decision !== "denied_by_user") {
      throw new AllowlyProtocolError(`unknown confirmation decision: ${JSON.stringify(decision)}`);
    }
    const receipt = raw.receipt === undefined || raw.receipt === null
      ? null
      : parsePendingEnvelope(raw.receipt);
    if (decision === "approved") {
      return {
        decision,
        authorizationId: requireString(raw, "authorization_id"),
        expiresAt: requireString(raw, "expires_at"),
        receipt,
      };
    }
    return {
      decision,
      authorizationId: requireNull(raw, "authorization_id"),
      expiresAt: requireNull(raw, "expires_at"),
      receipt,
    };
  }
}

class EscalationsResource {
  constructor(private readonly client: Allowly) {}

  async getStatus(escalationId: string): Promise<EscalationStatusResponse> {
    requirePromptId(escalationId, "escalation");
    return parseEscalationStatus(await this.client.request<unknown>(
      "GET", `/v1/escalations/${encodeURIComponent(escalationId)}`,
    ), escalationId);
  }

  /** Read the recorded choice and grant lifecycle; this does not authorize dispatch. */
  async get(escalationId: string): Promise<EscalationStatus> {
    return this.getStatus(escalationId);
  }

  async resolve(escalationId: string, req: EscalationResolveRequest): Promise<EscalationResolveResponse> {
    const raw = await this.client.request<Record<string, unknown>>(
      "POST",
      `/v1/escalations/${encodeURIComponent(escalationId)}/resolve`,
      {
        resolution: req.resolution,
        resolved_by: req.resolvedBy,
        note: req.note ?? null,
      },
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
      `/v1/receipts/${encodeURIComponent(receiptId)}`,
      undefined,
      { signal },
    );
    return parseReceiptEnvelope(raw);
  }

  async fetchSigned(
    receiptId: string,
    opts: {
      /** Polling interval in seconds. Defaults to 1. */
      pollInterval?: number;
      /** Total timeout in seconds. Defaults to 120. */
      timeout?: number;
    } = {}
  ): Promise<Record<string, unknown>> {
    const pollInterval = (opts.pollInterval ?? 1) * 1000;
    // Default timeout covers the signer's once-per-minute batch tick plus
    // scheduling/cold-start allowance; valid service behavior can take just
    // over a minute.
    const timeoutSeconds = opts.timeout ?? 120;
    if (pollInterval <= 0) throw new Error("pollInterval must be positive");
    if (timeoutSeconds <= 0) throw new Error("timeout must be positive");

    const timeoutMs = timeoutSeconds * 1000;
    const deadline = Date.now() + timeoutMs;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      while (Date.now() < deadline) {
        let delayMs = pollInterval;
        try {
          const envelope = await this.getWithSignal(receiptId, controller.signal);
          if (envelope.status === "signed" && Date.now() < deadline) {
            if (requireString(envelope.receipt, "receipt_id") !== receiptId) {
              throw new AllowlyProtocolError(
                "signed receipt_id does not match the requested receipt",
              );
            }
            return envelope.receipt;
          }
        } catch (err) {
          if (isAbortError(err)) break;
          if (err instanceof AllowlyTransportError) {
            // Retry transient transport failures within the same deadline.
          } else if (
            err instanceof AllowlyAPIError
            && (err.status === 408 || err.status === 429 || (err.status >= 500 && err.status <= 599))
          ) {
            if (err.status === 429 && err.retryAfterSeconds !== undefined) {
              delayMs = Math.max(delayMs, err.retryAfterSeconds * 1000);
            }
          } else {
            throw err;
          }
        }
        await sleep(Math.min(delayMs, Math.max(0, deadline - Date.now())));
      }
    } finally {
      clearTimeout(timer);
    }
    throw new Error(`Receipt ${receiptId} not signed after ${timeoutSeconds}s`);
  }
}

function parseCustomExecutableResponse(value: unknown): EnabledExecutableResponse {
  const raw = requireRecord(value, "enabled executable");
  const flag = (record: Record<string, unknown>, key: string): boolean => {
    if (typeof record[key] !== "boolean") throw new AllowlyProtocolError(`${key} must be a boolean`);
    return record[key];
  };
  const capability = (value: unknown, source: ExecutableEvidenceCapability["evidenceSource"]): ExecutableEvidenceCapability => {
    const record = requireRecord(value, "executable evidence capability");
    if (record.evidence_source !== source) throw new AllowlyProtocolError("invalid executable evidence source");
    return {
      available: flag(record, "available"),
      evidenceSource: source,
      profile: optionalString(record, "profile"),
      reason: optionalString(record, "reason"),
      apiRequestMatchVerification: optionalString(record, "api_request_match_verification"),
    };
  };
  if (raw.credential_location !== "customer_runtime" || raw.connection_status !== "not_verified") {
    throw new AllowlyProtocolError("invalid executable credential location or connection status");
  }
  if (!Array.isArray(raw.operations) || raw.operations.length !== 1 || raw.operation_count !== 1) {
    throw new AllowlyProtocolError("a custom executable must contain exactly one operation");
  }
  const providerId = requireString(raw, "provider_id");
  const operations = raw.operations.map((value) => {
    const operation = requireRecord(value, "executable operation");
    const capabilities = requireRecord(operation.capabilities, "executable capabilities");
    const fingerprint = requireString(operation, "definition_fingerprint");
    if (operation.provider_id !== providerId || !/^sha256:[0-9a-f]{64}$/.test(fingerprint)) {
      throw new AllowlyProtocolError("invalid executable operation identity or fingerprint");
    }
    return {
      providerId,
      operationId: requireString(operation, "operation_id"),
      label: requireString(operation, "label"),
      method: requireString(operation, "method"),
      path: requireString(operation, "path"),
      effect: requireString(operation, "effect"),
      requestContentType: optionalString(operation, "request_content_type"),
      requiredHeaders: requireStringArray(operation, "required_headers"),
      status: requireString(operation, "status"),
      definitionFingerprint: fingerprint,
      capabilities: {
        customerReportedReceipt: capability(capabilities.customer_reported_receipt, "customer_reported"),
        tlsWitness: capability(capabilities.tls_witness, "independent_allowly_witness"),
      },
      allowlyLiveTested: flag(operation, "allowly_live_tested"),
      tlsWitnessTested: flag(operation, "tls_witness_tested"),
    };
  });
  return {
    enabledExecutableId: requireString(raw, "enabled_executable_id"),
    providerId,
    providerName: requireString(raw, "provider_name"),
    category: requireString(raw, "category"),
    origin: requireString(raw, "origin"),
    catalogRevision: requireString(raw, "catalog_revision"),
    status: requireString(raw, "status"),
    credentialLocation: "customer_runtime",
    connectionStatus: "not_verified",
    allowlyLiveTested: flag(raw, "allowly_live_tested"),
    tlsWitnessTested: flag(raw, "tls_witness_tested"),
    operations,
    operationCount: 1,
    enabledAt: requireString(raw, "enabled_at"),
    disabledAt: optionalString(raw, "disabled_at"),
  };
}

function parsePendingEnvelope(value: unknown): ReceiptEnvelopePending {
  const raw = requireRecord(value, "pending receipt envelope");
  if (raw.status !== "pending") {
    throw new AllowlyProtocolError("receipt status must be 'pending'");
  }
  return {
    status: "pending",
    receiptId: requireString(raw, "receipt_id"),
    readyAtEstimate: optionalString(raw, "ready_at_estimate"),
    url: requireString(raw, "url"),
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

function validateSealMetadata(
  metadata: Record<string, string> | undefined,
): Record<string, string> | undefined {
  if (metadata === undefined) return undefined;
  if (
    typeof metadata !== "object"
    || metadata === null
    || Array.isArray(metadata)
    || Object.values(metadata).some((value) => typeof value !== "string")
  ) {
    throw new Error("metadata must be an object of string values");
  }
  return { ...metadata };
}

function parseCheckResponse(
  value: unknown,
  expectedAuthorizationId: string,
  expectedActions: string[],
): CheckResponse {
  // The API returns a map keyed by requested action. Preserve those keys so
  // callers can safely handle mixed allow/deny/confirm/escalate results in one check.
  const raw = requireRecord(value, "check response");
  const rawResults = requireRecord(raw.results, "check results");
  const authorizationId = requireString(raw, "authorization_id");
  if (authorizationId !== expectedAuthorizationId) {
    throw new AllowlyProtocolError(
      `authorization_id mismatch: got ${JSON.stringify(authorizationId)}, want ${JSON.stringify(expectedAuthorizationId)}`,
    );
  }
  const expectedActionSet = new Set(expectedActions);
  const returnedActions = Object.keys(rawResults);
  if (
    returnedActions.length !== expectedActionSet.size
    || returnedActions.some((action) => !expectedActionSet.has(action))
  ) {
    throw new AllowlyProtocolError("check results must exactly match the requested actions");
  }
  return {
    userId: optionalString(raw, "user_id"),
    agentId: optionalString(raw, "agent_id"),
    authorizationId,
    authorizationExpiresAt: optionalString(raw, "authorization_expires_at"),
    engineVersion: requireString(raw, "engine_version"),
    results: Object.fromEntries(
      Object.entries(rawResults).map(([action, value]) => {
        const result = requireRecord(value, `check result ${JSON.stringify(action)}`);
        const decision = requireString(result, "decision");
        const base = {
          reason: requireString(result, "reason"),
          receipt: parseReceiptEnvelope(result.receipt),
          isFallback: false,
          fallbackMode: null,
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
            confirmationId: optionalConfirmationId(result),
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

function optionalConfirmationId(raw: Record<string, unknown>): string | null {
  const value = optionalString(raw, "confirmation_id");
  if (value !== null && !/^cnf_[A-Za-z0-9_-]+$/.test(value)) {
    throw new AllowlyProtocolError("confirmation_id must be an opaque cnf_ ID");
  }
  return value;
}

function statusNullableString(raw: Record<string, unknown>, key: string): string | null {
  if (!Object.prototype.hasOwnProperty.call(raw, key)) {
    throw new AllowlyProtocolError(`${key} must be present as a string or null`);
  }
  const value = optionalString(raw, key);
  if (value === "" && key !== "resource") {
    throw new AllowlyProtocolError(`${key} must be non-empty or null`);
  }
  return value;
}

function statusTimestamp(raw: Record<string, unknown>, key: string, nullable = false): string | null {
  const value = nullable ? statusNullableString(raw, key) : requireString(raw, key);
  if (value === null) return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value);
  if (!match) throw new AllowlyProtocolError(`${key} must be a valid timezone-aware timestamp`);
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > daysInMonth
      || hour > 23 || minute > 59 || second > 59 || Number(match[7] ?? 0) > 23 || Number(match[8] ?? 0) > 59) {
    throw new AllowlyProtocolError(`${key} must be a valid timezone-aware timestamp`);
  }
  try {
    return clientTimestamp(value);
  } catch {
    throw new AllowlyProtocolError(`${key} must be a valid timezone-aware timestamp`);
  }
}

function parsePromptStatus(raw: Record<string, unknown>) {
  const status = requireString(raw, "status");
  if (status !== "pending" && status !== "approved" && status !== "rejected" && status !== "expired" && status !== "unknown") {
    throw new AllowlyProtocolError(`unknown prompt status: ${JSON.stringify(status)}`);
  }
  const authorizationId = requireString(raw, "authorization_id");
  const action = requireString(raw, "action");
  if (!authorizationId || !action) {
    throw new AllowlyProtocolError("status authorization_id and action must be non-empty");
  }
  const resolvedAt = statusTimestamp(raw, "resolved_at", true);
  if ((status === "pending" || status === "expired") && resolvedAt !== null) {
    throw new AllowlyProtocolError("unresolved prompt resolved_at must be null");
  }
  return {
    authorizationId,
    action,
    resource: statusNullableString(raw, "resource"),
    status: status as PromptStatus,
    expiresAt: statusTimestamp(raw, "expires_at")!,
    resolvedAt,
    sourceReceiptId: statusNullableString(raw, "source_receipt_id"),
    resolutionReceiptId: statusNullableString(raw, "resolution_receipt_id"),
  };
}

function parseConfirmationStatus(value: unknown, expectedId: string): ConfirmationStatus {
  const raw = requireRecord(value, "confirmation status");
  const confirmationId = requireString(raw, "confirmation_id");
  if (confirmationId !== expectedId) {
    throw new AllowlyProtocolError("confirmation_id does not match the request");
  }
  const base = parsePromptStatus(raw);
  const authority = requireString(raw, "authority_status");
  if (authority !== "none" && authority !== "available" && authority !== "expired" && authority !== "revoked" && authority !== "unknown") {
    throw new AllowlyProtocolError(`unknown confirmation authority_status: ${JSON.stringify(authority)}`);
  }
  const childAuthorizationId = statusNullableString(raw, "child_authorization_id");
  const authorityExpiresAt = statusTimestamp(raw, "authority_expires_at", true);
  if (authority === "available" && (base.status !== "approved" || childAuthorizationId === null || authorityExpiresAt === null)) {
    throw new AllowlyProtocolError("available confirmation authority requires an approved choice and child grant");
  }
  if (base.status === "rejected" && authority !== "none") {
    throw new AllowlyProtocolError("rejected confirmation authority_status must be none");
  }
  return { ...base, confirmationId, childAuthorizationId, authorityStatus: authority, authorityExpiresAt };
}

function parseEscalationStatus(value: unknown, expectedId: string): EscalationStatus {
  const raw = requireRecord(value, "escalation status");
  const escalationId = requireString(raw, "escalation_id");
  if (escalationId !== expectedId) {
    throw new AllowlyProtocolError("escalation_id does not match the request");
  }
  const base = parsePromptStatus(raw);
  const authority = requireString(raw, "authority_status");
  if (authority !== "none" && authority !== "available" && authority !== "expired" && authority !== "revoked" && authority !== "consumed" && authority !== "unknown") {
    throw new AllowlyProtocolError(`unknown escalation authority_status: ${JSON.stringify(authority)}`);
  }
  if (authority === "available" && base.status !== "approved") {
    throw new AllowlyProtocolError("available escalation authority requires an approved choice");
  }
  if (base.status === "rejected" && authority !== "none") {
    throw new AllowlyProtocolError("rejected escalation authority_status must be none");
  }
  return { ...base, escalationId, authorityStatus: authority, consumedAt: statusTimestamp(raw, "consumed_at", true) };
}

function validateSealReceipt(
  receipt: Record<string, unknown>,
  recordSha256: string,
  expectedWorkspaceId: string,
  expectedReceiptId?: string,
): void {
  const receiptId = requireString(receipt, "receipt_id");
  if (receiptId.length === 0) {
    throw new AllowlyProtocolError("seal receipt_id must be non-empty");
  }
  if (expectedReceiptId !== undefined && receiptId !== expectedReceiptId) {
    throw new AllowlyProtocolError("seal receipt_id does not match the pending receipt");
  }
  const expectedFields: Record<string, string> = {
    schema_version: "4",
    action: SEAL_ACTION,
    decision: "allow",
    agent_id: SEAL_AGENT_ID,
    user_id: SEAL_USER_ID,
    alg: "Ed25519",
  };
  for (const [key, expected] of Object.entries(expectedFields)) {
    if (requireString(receipt, key) !== expected) {
      throw new AllowlyProtocolError(`seal receipt ${key} does not match the request`);
    }
  }
  if (requireString(receipt, "workspace_id") !== expectedWorkspaceId) {
    throw new AllowlyProtocolError("seal receipt workspace_id does not match the response");
  }
  for (const key of ["key_id", "signature"]) {
    if (requireString(receipt, key).length === 0) {
      throw new AllowlyProtocolError(`seal receipt ${key} must be non-empty`);
    }
  }
  const context = requireRecord(receipt.context, "seal receipt context");
  if (requireString(context, "seal_profile") !== SEAL_PROFILE) {
    throw new AllowlyProtocolError("seal receipt profile does not match the request");
  }
  if (requireString(context, "record_sha256") !== recordSha256) {
    throw new AllowlyProtocolError("seal receipt record_sha256 does not match the request");
  }
}

function requirePromptId(id: string, kind: "confirmation" | "escalation"): void {
  if (typeof id !== "string" || !(kind === "confirmation" ? /^cnf_[A-Za-z0-9_-]+$/ : /^esc_[A-Za-z0-9_-]+$/).test(id)) {
    throw new Error(`Use the opaque review ID (${kind === "confirmation" ? "opaque cnf_" : "opaque esc_"} ID), never a confirmation nonce`);
  }
}

function requireString(raw: Record<string, unknown>, key: string): string {
  const value = raw[key];
  if (typeof value !== "string") {
    throw new AllowlyProtocolError(`${key} must be a string`);
  }
  return value;
}

function requireStringArray(raw: Record<string, unknown>, key: string): string[] {
  const value = raw[key];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new AllowlyProtocolError(`${key} must be an array of strings`);
  }
  return value as string[];
}

function requireStringMap(raw: Record<string, unknown>, key: string): Record<string, string> {
  const value = requireRecord(raw[key], key);
  if (!Object.values(value).every((mapValue) => typeof mapValue === "string")) {
    throw new AllowlyProtocolError(`${key} values must be strings`);
  }
  return value as Record<string, string>;
}

function optionalString(raw: Record<string, unknown>, key: string): string | null {
  const value = raw[key];
  if (value == null) return null;
  if (typeof value !== "string") {
    throw new AllowlyProtocolError(`${key} must be a string or null`);
  }
  return value;
}

function requireNull(raw: Record<string, unknown>, key: string): null {
  if (!Object.prototype.hasOwnProperty.call(raw, key) || raw[key] !== null) {
    throw new AllowlyProtocolError(`${key} must be null`);
  }
  return null;
}

function optionalNumber(raw: Record<string, unknown>, key: string): number | null {
  const value = raw[key];
  if (value == null) return null;
  if (typeof value !== "number") {
    throw new AllowlyProtocolError(`${key} must be a number or null`);
  }
  return value;
}

function requireNumber(raw: Record<string, unknown>, key: string): number {
  const value = raw[key];
  if (typeof value !== "number") {
    throw new AllowlyProtocolError(`${key} must be a number`);
  }
  return value;
}

function parseBudgetInfo(raw: unknown): BudgetInfo | null {
  if (raw == null) return null;
  const budget = requireRecord(raw, "budget");
  return {
    limitMicros: requireNumber(budget, "limit_micros"),
    spentMicros: requireNumber(budget, "spent_micros"),
    estimatedCostMicros: requireNumber(budget, "estimated_cost_micros"),
    spentAfterMicros: optionalNumber(budget, "spent_after_micros"),
  };
}

function parseBudgetSettlementResponse(value: unknown): BudgetSettlementResponse {
  const raw = requireRecord(value, "budget settlement response");
  return {
    checkReceiptId: requireString(raw, "check_receipt_id"),
    authorizationId: requireString(raw, "authorization_id"),
    estimatedCostMicros: requireNumber(raw, "estimated_cost_micros"),
    actualCostMicros: requireNumber(raw, "actual_cost_micros"),
    deltaMicros: requireNumber(raw, "delta_micros"),
    spentBeforeMicros: requireNumber(raw, "spent_before_micros"),
    spentAfterMicros: requireNumber(raw, "spent_after_micros"),
    receipt: parseReceiptEnvelope(raw.receipt),
  };
}

function parseEscalationInfo(raw: unknown): EscalationInfo | null {
  if (raw == null) return null;
  const escalation = requireRecord(raw, "escalation");
  return {
    escalationId: requireString(escalation, "escalation_id"),
    status: requireString(escalation, "status"),
    escalationTo: optionalString(escalation, "escalation_to"),
    expiresAt: optionalString(escalation, "expires_at"),
  };
}

function parsePolicyEval(raw: unknown): PolicyEvalInfo | null {
  if (raw == null) return null;
  const policyEval = requireRecord(raw, "policy evaluation");
  const matched = policyEval.matched_condition;
  const condition = matched == null ? null : requireRecord(matched, "matched policy condition");
  return {
    matchedCondition: condition ? {
      field: requireString(condition, "field"),
      op: requireString(condition, "op"),
      value: (condition.value ?? null) as PolicyConditionEvidence["value"],
    } : null,
    fieldValue: (policyEval.field_value ?? null) as PolicyEvalInfo["fieldValue"],
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
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("baseUrl must use HTTP or HTTPS");
  }
  if (parsed.protocol !== "https:" && !allowInsecure) {
    throw new Error("baseUrl must use HTTPS");
  }
  return normalized;
}

function parseRetryAfter(value: string | null): number | undefined {
  // Allowly only emits integer-seconds Retry-After; tolerate floats, ignore
  // HTTP-date and garbage rather than throwing inside error handling.
  if (value === null) return undefined;
  const seconds = Number(value.trim());
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : undefined;
}

function clientTimestamp(value: Date | string): string {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) throw new Error("clientTimestamp must be a valid Date");
    return value.toISOString();
  }
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("clientTimestamp must be a non-empty timezone-aware timestamp");
  }
  if (!/(?:Z|[+-]\d{2}:\d{2})$/i.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error("clientTimestamp must include a valid timezone");
  }
  return value;
}

function serializeCustomerHttpCommitment(
  value: import("./types.js").CustomerHttpRequestCommitment,
): Record<string, unknown> {
  return {
    method: value.method,
    origin: value.origin,
    path: value.path,
    query: value.query,
    headers: value.headers.map((header) => ({
      name: header.name,
      value_sha256: header.valueSha256,
    })),
    body_sha256: value.bodySha256,
    body_size: value.bodySize,
    content_type: value.contentType,
  };
}

function serializeExecutionRequest(
  req: Omit<PrepareExecutionRequest, "idempotencyKey" | "agentToken">,
): Record<string, unknown> {
  return {
    operation_id: req.operationId,
    authorization_id: req.authorizationId,
    enabled_executable_id: req.enabledExecutableId,
    catalog_operation_id: req.catalogOperationId,
    action: req.action,
    evidence_mode: req.evidenceMode,
    http_request: serializeCustomerHttpCommitment(req.httpRequest),
    policy_input: {
      resource: req.policyInput?.resource ?? null,
      context: req.policyInput?.context ?? {},
      estimated_cost_micros: req.policyInput?.estimatedCostMicros ?? null,
    },
    client_timestamp: clientTimestamp(req.clientTimestamp),
  };
}

function validateExecutionResponseScope(
  response: CustomerExecutionResponse,
  req: Omit<PrepareExecutionRequest, "idempotencyKey" | "agentToken">,
): void {
  if (response.operationId !== req.operationId
      || response.destinationId !== req.enabledExecutableId
      || response.requestDescriptor.authorizationId !== req.authorizationId
      || response.requestDescriptor.action !== req.action) {
    throw new AllowlyProtocolError("customer execution response does not match the request");
  }
}

function parseHeaderCommitments(value: unknown): import("./types.js").CustomerHeaderCommitment[] {
  if (!Array.isArray(value)) {
    throw new AllowlyProtocolError("customer request headers must be an array");
  }
  return value.map((item) => {
    const raw = requireRecord(item, "customer request header");
    return {
      name: requireString(raw, "name"),
      valueSha256: requireString(raw, "value_sha256"),
    };
  });
}

function parseCustomerExecutionResponse(value: unknown): CustomerExecutionResponse {
  const raw = requireRecord(value, "customer execution response");
  const operationId = requireString(raw, "operation_id");
  const destinationId = requireString(raw, "destination_id");
  const action = requireString(raw, "action");
  const status = requireString(raw, "status");
  const statuses: import("./types.js").CustomerExecutionStatus[] = [
    "denied",
    "waiting_for_review",
    "confirmation_required",
    "escalation_required",
    "approved",
    "succeeded",
    "failed",
    "unknown",
  ];
  if (!statuses.includes(status as import("./types.js").CustomerExecutionStatus)) {
    throw new AllowlyProtocolError(`invalid customer execution status: ${JSON.stringify(status)}`);
  }
  const decision = requireString(raw, "decision");
  if (!["allow", "deny", "confirm", "escalate"].includes(decision)) {
    throw new AllowlyProtocolError(`invalid customer execution decision: ${JSON.stringify(decision)}`);
  }
  const requestFingerprintProfile = requireString(raw, "request_fingerprint_profile");
  if (requestFingerprintProfile !== "allowly.execution.request.v1") {
    throw new AllowlyProtocolError("customer execution fingerprint profile is unsupported");
  }
  const descriptorRaw = requireRecord(raw.request_descriptor, "customer request descriptor");
  const requestDescriptor: import("./types.js").CustomerExecutionRequestDescriptor = {
    operationId: requireString(descriptorRaw, "operation_id"),
    authorizationId: requireString(descriptorRaw, "authorization_id"),
    destinationId: requireString(descriptorRaw, "destination_id"),
    action: requireString(descriptorRaw, "action"),
    method: requireString(descriptorRaw, "method"),
    origin: requireString(descriptorRaw, "origin"),
    path: requireString(descriptorRaw, "path"),
    query: requireString(descriptorRaw, "query"),
    headers: parseHeaderCommitments(descriptorRaw.headers),
    bodySha256: requireString(descriptorRaw, "body_sha256"),
    bodySize: requireNumber(descriptorRaw, "body_size"),
    contentType: optionalString(descriptorRaw, "content_type"),
  };
  if (requestDescriptor.operationId !== operationId
      || requestDescriptor.destinationId !== destinationId
      || requestDescriptor.action !== action) {
    throw new AllowlyProtocolError("customer request descriptor does not match the response");
  }
  const effectiveEvidenceMode = requireString(raw, "effective_evidence_mode");
  if (effectiveEvidenceMode !== "receipt" && effectiveEvidenceMode !== "witnessed") {
    throw new AllowlyProtocolError("invalid effective_evidence_mode");
  }
  const decisionState = requireString(raw, "decision_state");
  if (decisionState !== "allowed" && decisionState !== "not_allowed") {
    throw new AllowlyProtocolError("invalid customer execution decision_state");
  }
  const targetState = requireString(raw, "target_state");
  if (!["not_started", "response_observed", "unknown"].includes(targetState)) {
    throw new AllowlyProtocolError("invalid customer execution target_state");
  }
  const evidenceState = requireString(raw, "evidence_state");
  if (!["pending", "customer_reported", "customer_held_witness_bundle", "evidence_gap"]
    .includes(evidenceState)) {
    throw new AllowlyProtocolError("invalid customer execution evidence_state");
  }
  let witnessSession: import("./types.js").CustomerExecutionWitnessSession | null = null;
  if (raw.witness_session !== undefined && raw.witness_session !== null) {
    const session = requireRecord(raw.witness_session, "customer witness session");
    const profile = requireString(session, "native_profile");
    const delivery = requireString(session, "admission_token_delivery");
    if (profile !== "customer_held_tlsn_bundle_v1"
        || delivery !== "separate_one_time_endpoint") {
      throw new AllowlyProtocolError("unsupported customer witness session");
    }
    witnessSession = {
      sessionId: requireString(session, "session_id"),
      witnessUrl: requireString(session, "witness_url"),
      expiresAt: requireString(session, "expires_at"),
      trustedNotaryKeyFingerprintSha256: requireString(
        session,
        "trusted_notary_key_fingerprint_sha256",
      ),
      nativeProfile: "customer_held_tlsn_bundle_v1",
      admissionTokenDelivery: "separate_one_time_endpoint",
    };
  }
  let downstream: import("./types.js").CustomerExecutionDownstream | null = null;
  if (raw.downstream !== undefined && raw.downstream !== null) {
    const item = requireRecord(raw.downstream, "customer execution downstream");
    if (requireString(item, "source") !== "customer_runtime") {
      throw new AllowlyProtocolError("customer execution downstream source is invalid");
    }
    const httpStatus = optionalNumber(item, "http_status");
    const responseFingerprint = optionalString(item, "response_fingerprint");
    const scope = requireString(item, "response_fingerprint_scope");
    if (scope !== "complete" && scope !== "unavailable") {
      throw new AllowlyProtocolError("customer downstream fingerprint scope is invalid");
    }
    if (item.business_completion !== "not_verified") {
      throw new AllowlyProtocolError("customer downstream business_completion is invalid");
    }
    downstream = {
      source: "customer_runtime",
      httpStatus,
      responseFingerprint,
      responseFingerprintScope: scope,
      result: requireRecord(item.result, "customer execution downstream result"),
      businessCompletion: "not_verified",
    };
  }
  const approval = raw.approval === undefined || raw.approval === null
    ? null
    : requireRecord(raw.approval, "customer execution approval");
  const decisionReceipt = parseReceiptEnvelope(raw.decision_receipt);
  let review: import("./types.js").CustomerExecutionReview | null = null;
  if (raw.review !== undefined && raw.review !== null) {
    const item = requireRecord(raw.review, "customer execution review");
    const kind = requireString(item, "kind");
    const id = requireString(item, "id");
    const expiresAt = requireString(item, "expires_at");
    if ((kind !== "confirm" && kind !== "escalate")
        || !id.startsWith(kind === "confirm" ? "cnf_" : "esc_")
        || Number.isNaN(Date.parse(expiresAt))) {
      throw new AllowlyProtocolError("invalid customer execution review");
    }
    review = { kind, id, sourceReceiptId: requireString(item, "source_receipt_id"), expiresAt };
  }
  if (status === "waiting_for_review"
      && (review === null || review.kind !== decision
        || review.sourceReceiptId !== (decisionReceipt.status === "pending"
          ? decisionReceipt.receiptId : decisionReceipt.receipt.receipt_id)
        || decisionState !== "not_allowed" || targetState !== "not_started"
        || approval !== null || downstream !== null || evidenceState !== "pending")) {
    throw new AllowlyProtocolError("waiting customer execution is not bound to a review");
  }
  return {
    operationId,
    status: status as import("./types.js").CustomerExecutionStatus,
    decision: decision as CustomerExecutionResponse["decision"],
    reason: requireString(raw, "reason"),
    destinationId,
    action,
    requestFingerprintProfile,
    requestFingerprint: requireString(raw, "request_fingerprint"),
    requestDescriptor,
    decisionReceipt,
    effectiveEvidenceMode,
    decisionState,
    targetState: targetState as CustomerExecutionResponse["targetState"],
    evidenceState: evidenceState as CustomerExecutionResponse["evidenceState"],
    approval,
    approvalSha256: optionalString(raw, "approval_sha256"),
    approvalExpiresAt: optionalString(raw, "approval_expires_at"),
    witnessSession,
    downstream,
    outcomeEvidence: raw.outcome_evidence === undefined || raw.outcome_evidence === null
      ? null
      : parseOutcomeEvidence(raw.outcome_evidence),
    review,
    confirmationId: optionalString(raw, "confirmation_id"),
    confirmNonce: optionalString(raw, "confirm_nonce"),
    confirmExpiresAt: optionalString(raw, "confirm_expires_at"),
    confirmPromptHint: optionalString(raw, "confirm_prompt_hint"),
    escalationId: optionalString(raw, "escalation_id"),
    escalationExpiresAt: optionalString(raw, "escalation_expires_at"),
    escalationTo: optionalString(raw, "escalation_to"),
    escalation: parseEscalationInfo(raw.escalation),
  };
}

function parseDispatchResponse(
  value: unknown,
  operationId: string,
  approvalSha256: string,
): ClaimExecutionDispatchResponse {
  const raw = requireRecord(value, "dispatch response");
  const mode = requireString(raw, "effective_evidence_mode");
  if (requireString(raw, "operation_id") !== operationId
      || requireString(raw, "approval_sha256") !== approvalSha256
      || requireString(raw, "dispatch_state") !== "claimed"
      || (mode !== "receipt" && mode !== "witnessed")) {
    throw new AllowlyProtocolError("dispatch response does not match the request");
  }
  return {
    operationId,
    dispatchState: "claimed",
    approval: requireRecord(raw.approval, "dispatch approval"),
    approvalSha256,
    approvalExpiresAt: requireString(raw, "approval_expires_at"),
    effectiveEvidenceMode: mode,
  };
}

function parseWitnessTokenResponse(
  value: unknown,
  approvalSha256: string,
): ExecutionWitnessTokenResponse {
  const raw = requireRecord(value, "witness token response");
  if (requireString(raw, "approval_sha256") !== approvalSha256
      || requireString(raw, "native_profile") !== "customer_held_tlsn_bundle_v1") {
    throw new AllowlyProtocolError("witness token response does not match the approval");
  }
  return {
    sessionId: requireString(raw, "session_id"),
    workspaceId: requireString(raw, "workspace_id"),
    approvalSha256,
    witnessUrl: requireString(raw, "witness_url"),
    admissionToken: requireString(raw, "admission_token"),
    expiresAt: requireString(raw, "expires_at"),
    trustedNotaryKeyFingerprintSha256: requireString(
      raw,
      "trusted_notary_key_fingerprint_sha256",
    ),
    nativeProfile: "customer_held_tlsn_bundle_v1",
  };
}

function parseOutcomeEvidence(value: unknown): OutcomeEvidence {
  const raw = requireRecord(value, "outcome evidence");
  const profile = requireString(raw, "profile");
  if (profile !== "allowly.seal.jcs-sha256.v1") {
    throw new AllowlyProtocolError(`invalid outcome evidence profile: ${JSON.stringify(profile)}`);
  }
  const evidenceError = raw.evidence_error ?? null;
  if (evidenceError !== null && evidenceError !== "unavailable") {
    throw new AllowlyProtocolError(
      `invalid outcome evidence error: ${JSON.stringify(evidenceError)}`,
    );
  }
  return {
    profile,
    record: requireRecord(raw.record, "outcome evidence record"),
    recordSha256: requireString(raw, "record_sha256"),
    receipt: raw.receipt === null || raw.receipt === undefined
      ? null
      : parseReceiptEnvelope(raw.receipt),
    evidenceError,
  };
}

function parseReceiptAcknowledgmentResponse(value: unknown): ReceiptAcknowledgmentResponse {
  const raw = requireRecord(value, "receipt acknowledgment response");
  const caller = requireRecord(raw.caller, "receipt acknowledgment caller");
  const kind = requireString(caller, "kind");
  if (kind !== "workspace_runtime_key") {
    throw new AllowlyProtocolError(`invalid receipt acknowledgment caller kind: ${JSON.stringify(kind)}`);
  }
  return {
    acknowledgmentId: requireString(raw, "acknowledgment_id"),
    receiptId: requireString(raw, "receipt_id"),
    receiptSha256: requireString(raw, "receipt_sha256"),
    clientTimestamp: requireString(raw, "client_timestamp"),
    receivedAt: requireString(raw, "received_at"),
    caller: {
      kind: "workspace_runtime_key",
      apiKeyId: requireString(caller, "api_key_id"),
      agentIdentity: caller.agent_identity === null || caller.agent_identity === undefined
        ? null
        : requireRecord(caller.agent_identity, "receipt acknowledgment agent identity"),
    },
    evidence: parseOutcomeEvidence(raw.evidence),
  };
}

function isAbortError(err: unknown): boolean {
  const name = (err as { name?: string } | null)?.name;
  return name === "AbortError" || name === "TimeoutError";
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
