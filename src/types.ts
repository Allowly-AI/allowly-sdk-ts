export type Decision = "allow" | "deny" | "confirm" | "escalate";
export type FallbackMode = "fail_open" | "fail_closed";

export interface CustomExecutableCreateRequest {
  name: string;
  /** Exact public HTTPS URL, optionally with whole-segment path placeholders. No credentials or query. */
  url: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  requestContentType?: "application/json" | "application/x-www-form-urlencoded" | null;
  /** Header names only; provider credential values stay in the customer runtime. */
  requiredHeaders?: string[];
}

export interface ExecutableEvidenceCapability {
  available: boolean;
  evidenceSource: "customer_reported" | "independent_allowly_witness";
  profile: string | null;
  reason: string | null;
  apiRequestMatchVerification: string | null;
}

export interface ExecutableOperation {
  providerId: string;
  operationId: string;
  label: string;
  method: string;
  path: string;
  effect: string;
  requestContentType: string | null;
  requiredHeaders: string[];
  status: string;
  definitionFingerprint: string;
  capabilities: {
    customerReportedReceipt: ExecutableEvidenceCapability;
    tlsWitness: ExecutableEvidenceCapability;
  };
  allowlyLiveTested: boolean;
  tlsWitnessTested: boolean;
}

export interface EnabledExecutableResponse {
  enabledExecutableId: string;
  providerId: string;
  providerName: string;
  category: string;
  origin: string;
  catalogRevision: string;
  status: string;
  credentialLocation: "customer_runtime";
  connectionStatus: "not_verified";
  allowlyLiveTested: boolean;
  tlsWitnessTested: boolean;
  operations: ExecutableOperation[];
  operationCount: number;
  enabledAt: string;
  disabledAt: string | null;
}
export type SealWebhookStatus = "received" | "signing" | "sealed" | "rejected" | "failed";
export interface ReceiptEnvelopePending {
  status: "pending";
  receiptId: string;
  readyAtEstimate: string | null;
  url: string;
}

export interface ReceiptEnvelopeSigned {
  status: "signed";
  receipt: Record<string, unknown>;
}

export type ReceiptEnvelope = ReceiptEnvelopePending | ReceiptEnvelopeSigned;

export interface SealRequest {
  requestId: string;
  metadata?: Record<string, string>;
  /** Polling interval in seconds. Defaults to 1. */
  pollInterval?: number;
  /** Total signing timeout in seconds. Defaults to 120. */
  timeout?: number;
}

export interface SealResponse {
  requestId: string;
  workspaceId: string;
  profile: string;
  recordSha256: string;
  decision: "allow";
  reason: string;
  receipt: Record<string, unknown>;
}

export interface SealWebhookDelivery {
  attemptId: string;
  workspaceId: string;
  status: SealWebhookStatus;
  receivedAt: string;
  updatedAt: string;
  profile: "allowly.seal.jcs-sha256.v1";
  recordSha256: string | null;
  metadata: Record<string, string> | null;
  receiptId: string | null;
  errorCode: string | null;
  statusUrl: string;
  receiptUrl: string | null;
  keysUrl: string;
  receipt: Record<string, unknown> | null;
}

export interface SealWebhookClientOptions {
  dangerouslyAllowInsecureUrl?: boolean;
  fetch?: typeof globalThis.fetch;
  requestTimeoutMs?: number;
}

export interface BudgetInfo {
  limitMicros: number;
  spentMicros: number;
  estimatedCostMicros: number;
  spentAfterMicros?: number | null;
}

export interface BudgetSettlementResponse {
  checkReceiptId: string;
  authorizationId: string;
  estimatedCostMicros: number;
  actualCostMicros: number;
  deltaMicros: number;
  spentBeforeMicros: number;
  spentAfterMicros: number;
  receipt: ReceiptEnvelope;
}

export interface OutcomeEvidence {
  profile: "allowly.seal.jcs-sha256.v1";
  record: Record<string, unknown>;
  recordSha256: string;
  receipt: ReceiptEnvelope | null;
  evidenceError: "unavailable" | null;
}

export type CustomerEvidenceMode = "receipt" | "witnessed";

export interface CustomerHeaderCommitment {
  name: string;
  valueSha256: string;
}

/** The request summary sent to Allowly. Header values and body bytes stay local. */
export interface CustomerHttpRequestCommitment {
  method: string;
  origin: string;
  path: string;
  query: string;
  headers: CustomerHeaderCommitment[];
  bodySha256: string;
  bodySize: number;
  contentType: string | null;
}

export interface CustomerPolicyInput {
  resource?: string | null;
  context?: Record<string, unknown>;
  estimatedCostMicros?: number | null;
}

export interface PrepareExecutionRequest {
  operationId: string;
  authorizationId: string;
  enabledExecutableId: string;
  catalogOperationId: string;
  action: string;
  evidenceMode: CustomerEvidenceMode;
  httpRequest: CustomerHttpRequestCommitment;
  policyInput?: CustomerPolicyInput;
  clientTimestamp: Date | string;
  idempotencyKey: string;
  agentToken?: string;
}

export interface ContinueExecutionRequest {
  /** The exact original prepare request, including its original timestamp. */
  executionRequest: Omit<PrepareExecutionRequest, "idempotencyKey" | "agentToken">;
  reviewId: string;
  sourceReceiptId: string;
  idempotencyKey: string;
  agentToken?: string;
}

export interface CustomerExecutionReview {
  kind: "confirm" | "escalate";
  id: string;
  sourceReceiptId: string;
  expiresAt: string;
}

/** Current review state is a wake-up signal, not permission to dispatch. */
export interface PromptStatusResponse {
  authorizationId: string;
  action: string;
  resource: string | null;
  status: "pending" | "approved" | "rejected" | "expired" | "unknown";
  expiresAt: string;
  resolvedAt: string | null;
  sourceReceiptId: string | null;
  resolutionReceiptId: string | null;
}

export interface ConfirmationStatusResponse extends PromptStatusResponse {
  confirmationId: string;
  childAuthorizationId: string | null;
  authorityStatus: "none" | "available" | "expired" | "revoked" | "unknown";
  authorityExpiresAt: string | null;
}

export interface EscalationStatusResponse extends PromptStatusResponse {
  escalationId: string;
  authorityStatus: "none" | "available" | "expired" | "revoked" | "consumed" | "unknown";
  consumedAt: string | null;
}

export interface CustomerExecutionRequestDescriptor {
  operationId: string;
  authorizationId: string;
  destinationId: string;
  action: string;
  method: string;
  origin: string;
  path: string;
  query: string;
  headers: CustomerHeaderCommitment[];
  bodySha256: string;
  bodySize: number;
  contentType: string | null;
}

export interface CustomerExecutionWitnessSession {
  sessionId: string;
  witnessUrl: string;
  expiresAt: string;
  trustedNotaryKeyFingerprintSha256: string;
  nativeProfile: "customer_held_tlsn_bundle_v1";
  admissionTokenDelivery: "separate_one_time_endpoint";
}

export interface CustomerExecutionDownstream {
  source: "customer_runtime";
  httpStatus: number | null;
  responseFingerprint: string | null;
  responseFingerprintScope: "complete" | "unavailable";
  result: Record<string, unknown>;
  businessCompletion: "not_verified";
}

export type CustomerExecutionStatus =
  | "denied"
  | "waiting_for_review"
  | "confirmation_required"
  | "escalation_required"
  | "approved"
  | "succeeded"
  | "failed"
  | "unknown";

export interface CustomerExecutionResponse {
  operationId: string;
  status: CustomerExecutionStatus;
  decision: Decision;
  reason: string;
  destinationId: string;
  action: string;
  requestFingerprintProfile: "allowly.execution.request.v1";
  requestFingerprint: string;
  requestDescriptor: CustomerExecutionRequestDescriptor;
  decisionReceipt: ReceiptEnvelope;
  effectiveEvidenceMode: CustomerEvidenceMode;
  decisionState: "allowed" | "not_allowed";
  targetState: "not_started" | "response_observed" | "unknown";
  evidenceState:
    | "pending"
    | "customer_reported"
    | "customer_held_witness_bundle"
    | "evidence_gap";
  approval: Record<string, unknown> | null;
  approvalSha256: string | null;
  approvalExpiresAt: string | null;
  witnessSession: CustomerExecutionWitnessSession | null;
  downstream: CustomerExecutionDownstream | null;
  outcomeEvidence: OutcomeEvidence | null;
  review?: CustomerExecutionReview | null;
  confirmationId?: string | null;
  confirmNonce?: string | null;
  confirmExpiresAt?: string | null;
  confirmPromptHint?: string | null;
  escalationId?: string | null;
  escalationExpiresAt?: string | null;
  escalationTo?: string | null;
  escalation?: EscalationInfo | null;
}

export interface ClaimExecutionDispatchRequest {
  operationId: string;
  approvalSha256: string;
  agentToken?: string;
}

export interface ClaimExecutionDispatchResponse {
  operationId: string;
  dispatchState: "claimed";
  approval: Record<string, unknown>;
  approvalSha256: string;
  approvalExpiresAt: string;
  effectiveEvidenceMode: CustomerEvidenceMode;
}

export interface GetExecutionWitnessTokenRequest {
  operationId: string;
  approvalSha256: string;
  agentToken?: string;
}

export interface ExecutionWitnessTokenResponse {
  sessionId: string;
  workspaceId: string;
  approvalSha256: string;
  witnessUrl: string;
  admissionToken: string;
  expiresAt: string;
  trustedNotaryKeyFingerprintSha256: string;
  nativeProfile: "customer_held_tlsn_bundle_v1";
}

export interface CustomerExecutionOutcome {
  approvalSha256: string;
  targetState: "response_observed" | "unknown";
  dispatchStartedAt: Date | string;
  completedAt: Date | string;
  httpStatus?: number;
  responseSha256?: string;
  responseSize?: number;
  providerOperationId?: string;
  evidenceBundleSha256?: string;
  notaryAttestation?: Record<string, unknown>;
}

export interface ReportExecutionOutcomeRequest extends CustomerExecutionOutcome {
  operationId: string;
  idempotencyKey: string;
  agentToken?: string;
}

export interface CustomerHttpOptions {
  operationId: string;
  authorizationId: string;
  enabledExecutableId: string;
  catalogOperationId: string;
  action: string;
  evidenceMode?: CustomerEvidenceMode;
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  headers?: Record<string, string>;
  body?: string;
  policyInput?: CustomerPolicyInput;
  clientTimestamp?: Date | string;
  idempotencyKey?: string;
  outcomeIdempotencyKey?: string;
  agentToken?: string;
  journalDirectory: string;
  /** Provider timeout. Also bounds native execution unless witness.timeoutMs is set. */
  timeoutMs?: number;
  witness?: {
    /** Omit both paths to use the workspace key and helper installed by `allowly setup witness`. */
    nativeBinaryPath?: string;
    trustedNotaryKeyPath?: string;
    evidenceDirectory: string;
    /** Optional expected workspace. If supplied, it must match the approval. */
    workspaceId?: string;
    timeoutMs?: number;
  };
}

export interface CustomerExecutionEvidencePackage {
  profile: "allowly.customer_execution.evidence.v1";
  operationId: string;
  approval: Record<string, unknown>;
  approvalSha256: string;
  decisionReceipt: ReceiptEnvelope;
  decisionReceiptVerification: "pending" | "not_verified" | "verified";
  requestDescriptor: CustomerExecutionRequestDescriptor;
  outcome: CustomerExecutionOutcome | null;
  witness:
    | {
      profile: "customer_held_tlsn_bundle_v1";
      evidencePath: string;
      attestationPath: string;
      trustedNotaryKeyPath: string;
    }
    | null;
}

export interface CustomerHttpProviderResponse {
  status: number;
  /** Full local response bytes. Never uploaded to Allowly or saved in the journal. */
  body: Uint8Array;
}

export type CustomerHttpExecutionResult =
  | {
    state: "waiting_for_review";
    authorization: CustomerExecutionResponse;
    review: CustomerExecutionReview;
  }
  | {
    state: "not_allowed";
    authorization: CustomerExecutionResponse;
  }
  | {
    state: "response_observed";
    authorization: CustomerExecutionResponse;
    /** Allowly's outcome response; null while outcome upload is unconfirmed. */
    response: CustomerExecutionResponse | null;
    evidencePackage: CustomerExecutionEvidencePackage;
    outcomePending: boolean;
    /** Available only on the call that observed provider bytes, not journal resume. */
    providerResponse: CustomerHttpProviderResponse | null;
  }
  | {
    state: "unknown";
    authorization: CustomerExecutionResponse;
    response: CustomerExecutionResponse | null;
    evidencePackage: CustomerExecutionEvidencePackage;
    outcomePending: boolean;
    providerResponse: CustomerHttpProviderResponse | null;
  };

export interface ResumeHttpExecutionRequest {
  operationId: string;
  journalDirectory: string;
  agentToken?: string;
}

export interface ReceiptAcknowledgmentRequest {
  receiptId: string;
  receiptSha256: string;
  clientTimestamp: Date | string;
  idempotencyKey: string;
  agentToken?: string;
}

export interface ReceiptAcknowledgmentResponse {
  acknowledgmentId: string;
  receiptId: string;
  receiptSha256: string;
  clientTimestamp: string;
  receivedAt: string;
  caller: {
    kind: "workspace_runtime_key";
    apiKeyId: string;
    agentIdentity: Record<string, unknown> | null;
  };
  evidence: OutcomeEvidence;
}

export interface EscalationInfo {
  escalationId: string;
  status: string;
  escalationTo?: string | null;
  expiresAt?: string | null;
}

export interface PolicyConditionEvidence {
  field: string;
  op: string;
  value: string | number | boolean | null | Array<string | number | boolean | null>;
}

export interface PolicyEvalInfo {
  matchedCondition: PolicyConditionEvidence | null;
  fieldValue: string | number | boolean | null;
}

export interface ActionCheckResultBase {
  decision: Decision;
  reason: string;
  receipt: ReceiptEnvelope | null;
  isFallback: boolean;
  fallbackMode: FallbackMode | null;
  budget: BudgetInfo | null;
  escalation: EscalationInfo | null;
  policyEval: PolicyEvalInfo | null;
}

export interface ActionCheckResultAllow extends ActionCheckResultBase {
  decision: "allow";
}

export interface ActionCheckResultDeny extends ActionCheckResultBase {
  decision: "deny";
  supersededBy?: string | null;
}

export interface ActionCheckResultConfirm extends ActionCheckResultBase {
  decision: "confirm";
  confirmNonce: string;
  confirmExpiresAt: string;
  confirmPromptHint: string;
}

export interface ActionCheckResultEscalate extends ActionCheckResultBase {
  decision: "escalate";
  escalationId: string;
  escalationTo?: string | null;
  escalationExpiresAt?: string | null;
}

export type ActionCheckResult =
  | ActionCheckResultAllow
  | ActionCheckResultDeny
  | ActionCheckResultConfirm
  | ActionCheckResultEscalate;

export interface CheckResponse {
  authorizationId: string;
  userId: string | null;
  agentId: string | null;
  authorizationExpiresAt: string | null;
  engineVersion: string;
  results: Record<string, ActionCheckResult>;
  /** X-Allowly-Billing-Warning response header, when the workspace is close
   * to a quota/payment boundary. Surface it to operators. */
  billingWarning?: string;
}

export interface ActionEntry {
  name: string;
  constraints?: Record<string, unknown>;
  /** Exact executable operations granted to this action. Empty means none. */
  executableOperations?: ExecutableOperationGrant[];
}

export interface ExecutableOperationGrant {
  enabledExecutableId: string;
  providerId: string;
  operationId: string;
  catalogRevision: string;
  definitionFingerprint: string;
  minimumEvidenceMode: CustomerEvidenceMode;
}

interface AuthorizationCreateBase {
  userId: string;
  budgetLimitMicros?: number;
  replaces?: string;
  metadata?: Record<string, unknown>;
  idempotencyKey?: string;
}

interface AuthorizationCreateInlineControls {
  requiresConfirmFor?: string[];
  requiresEscalationFor?: string[];
  requiresDenyFor?: string[];
  escalationTargets?: Record<string, string>;
}

/**
 * Canonical flow: pass `policyId` referencing a reusable agent policy
 * (`expiresAt` optional — the policy's default expiry applies). Inline flow
 * (`agentId` + `actions`, no `policyId`) is for prototyping and ad-hoc
 * per-user grants and requires an explicit `expiresAt`. Exactly one of the
 * two shapes must be used; the runtime rejects mixed shapes with 422.
 */
export type AuthorizationCreateRequest =
  | (AuthorizationCreateBase & {
      policyId: string;
      agentId?: never;
      actions?: never;
      expiresAt?: Date | string;
    })
  | (AuthorizationCreateBase & AuthorizationCreateInlineControls & {
      policyId?: never;
      agentId: string;
      actions: ActionEntry[] | string[];
      expiresAt: Date | string;
    });

export interface AuthorizationCreateResponse {
  authorizationId: string;
  policyId: string | null;
  createdAt: string;
  expiresAt: string;
  receipt: ReceiptEnvelopePending;
  requiresConfirmFor: string[];
  requiresEscalationFor: string[];
  requiresDenyFor: string[];
  escalationTargets: Record<string, string>;
  budgetLimitMicros: number | null;
  budgetSpentMicros: number | null;
  replacedAuthorizationId: string | null;
  revocationReceipt: ReceiptEnvelopePending | null;
  authorizationProvenance: Record<string, unknown> | null;
  /** X-Allowly-Billing-Warning response header, when present. */
  billingWarning?: string;
}

export interface AuthorizationRevokeResponse {
  authorizationId: string;
  revokedAt: string;
  receipt: ReceiptEnvelopePending;
  revokedConfirmations: string[];
}

export interface ConfirmationApproveRequest {
  approved: boolean;
  ttlSeconds?: number;
  idempotencyKey?: string;
}

export type ConfirmationApproveResponse = (
  | { decision: "approved"; authorizationId: string; expiresAt: string }
  | { decision: "not_approved" | "denied_by_user"; authorizationId: null; expiresAt: null }
) & { receipt?: ReceiptEnvelopePending | null };

export type ResolutionWebhookEventType = "confirmation.resolved" | "escalation.resolved";
export type ResolutionWebhookDeliveryStatus = "pending" | "delivered" | "failed" | "cancelled";

export interface ResolutionWebhookEvent {
  id: string;
  type: ResolutionWebhookEventType;
  timestamp: string;
  workspaceId: string;
  data: {
    promptId: string;
    status: "approved" | "rejected";
    sourceReceiptId: string | null;
    resolutionReceiptId: string;
  };
}

export interface ResolutionWebhookVerificationOptions {
  signingSecret: string;
  expectedWorkspaceId: string;
  /** Current Unix seconds. Defaults to the system clock. */
  now?: number;
}

export interface ResolutionWebhookConfig {
  workspaceId: string;
  endpointId: string | null;
  url: string | null;
  enabled: boolean;
  credentialVersion: number | null;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface ResolutionWebhookSecret extends ResolutionWebhookConfig {
  signingSecret: string;
}

export interface ResolutionWebhookDelivery {
  eventId: string;
  eventType: ResolutionWebhookEventType;
  status: ResolutionWebhookDeliveryStatus;
  attempts: number;
  createdAt: string;
  deliveredAt: string | null;
  lastError: string | null;
}

export interface ResolutionWebhookDeliveries {
  items: ResolutionWebhookDelivery[];
}

export interface EscalationResolveRequest {
  resolution: "approved" | "rejected";
  resolvedBy: string;
  note?: string | null;
}

export interface EscalationResolveResponse {
  escalationId: string;
  status: "approved" | "rejected";
  resolvedBy?: string | null;
  resolvedAt?: string | null;
  receipt: ReceiptEnvelopePending | null;
}

export interface AllowlyOptions {
  apiKey: string;
  agentToken?: string;
  agentTokenSupplier?: () => string | Promise<string>;
  baseUrl?: string;
  dangerouslyAllowInsecureBaseUrl?: boolean;
  edgeToken?: string;
  fetch?: typeof globalThis.fetch;
  checkTimeoutMs?: number;
  requestTimeoutMs?: number;
  fallbackByAction?: Record<string, FallbackMode>;
}

export interface AllowlyError {
  code: string;
  message: string;
  fields?: Array<{ field: string; message: string }>;
}
