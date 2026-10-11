import type { JwsReceipt } from "@allowly/verifier";

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
  receipt: JwsReceipt;
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
  receipt: JwsReceipt;
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
  receipt: JwsReceipt | null;
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

/** Canonical retained policy JSON. These members intentionally stay snake_case. */
export interface PolicyReference {
  policy_id: string;
  policy_version: number;
  definition_sha256: string;
}
export type PolicyScalar = string | number | boolean | null;
export interface BasicCondition {
  field: string;
  op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte" | "in" | "not_in" | "exists" | "contains_any" | "contains_none" | "empty";
  value: PolicyScalar | PolicyScalar[];
}
export interface BasicRule {
  id: string;
  decision: Decision;
  target: string | null;
  /** A rule matches when at least one condition matches (OR). */
  conditions: BasicCondition[];
}
export interface BasicPolicy {
  profile: "allowly.basic.v1";
  action: string;
  /** The action-level decision; conditional rules cannot weaken it. */
  decision: Decision;
  target: string | null;
  fields: Record<string, "string" | "integer" | "boolean" | "null" | "list">;
  rules: BasicRule[];
}
export interface ActionGuards {
  resource_pattern?: string;
  allowed_initiators?: string[];
  max_per_day?: number;
}
export interface PolicyExecutableOperationGrant {
  enabled_executable_id: string;
  provider_id: string;
  operation_id: string;
  catalog_revision: string;
  definition_fingerprint: string;
  minimum_evidence_mode: CustomerEvidenceMode;
}
export interface PolicyActionEntry {
  policy: BasicPolicy;
  guards: ActionGuards;
  executable_operations: PolicyExecutableOperationGrant[];
}
export interface PolicyDefinition {
  profile: "allowly.policy.v1";
  agent_id: string;
  actions: PolicyActionEntry[];
  default_expiry_days: number | null;
}
export interface ProvisionalPolicyResult {
  profile: "allowly.basic.v1";
  status: "ok";
  decision: Decision;
  target: string | null;
  matched_rule_id: string | null;
  evaluated_fields: Record<string, unknown>;
}
/** Provisional OPA evidence. Signature validation, replay and final guards are separate. */
export interface PolicyEvalInfo {
  input_sha256: string;
  result: ProvisionalPolicyResult;
}
export interface PolicyCreateRequest {
  policyId: string;
  definition: PolicyDefinition;
  description?: string;
  previousPolicyRef?: PolicyReference;
  idempotencyKey?: string;
}
export interface PolicyResponse {
  policyRef: PolicyReference;
  definition: PolicyDefinition;
  description: string | null;
  createdBy: string | null;
  createdAt: string | null;
  deletedAt: string | null;
}
export interface PolicyListResponse {
  items: PolicyResponse[];
  hasMore: boolean;
  nextCursor: string | null;
}
export interface PolicyPreviewRequest {
  definition: PolicyDefinition;
  action: string;
  context: Record<string, unknown>;
}
export interface PolicyPreviewResponse {
  provisional: true;
  definitionSha256: string;
  action: string;
  policyEval: PolicyEvalInfo;
}
export interface PolicyPublishResponse {
  policyRef: PolicyReference;
  agentId: string;
  createdBy: string;
  createdAt: string;
  authorizationMigrations: Array<{ user_id: string; previous_authorization_id: string; authorization_id: string }>;
  archivedPolicyIds: string[];
  revokedConfirmationCount: number;
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
  confirmationId?: string | null;
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

/** Grant a names-only subset of one exact immutable logical policy edition. */
export interface AuthorizationCreateRequest {
  userId: string;
  policyId: string;
  policyVersion: number;
  actions?: string[];
  expiresAt?: Date | string;
  budgetLimitMicros?: number;
  replaces?: string;
  metadata?: Record<string, unknown>;
  idempotencyKey?: string;
}

export interface AuthorizationCreateResponse {
  authorizationId: string;
  policyRef: PolicyReference;
  actions: string[];
  createdAt: string;
  expiresAt: string;
  receipt: ReceiptEnvelopePending;
  budgetLimitMicros: number | null;
  budgetSpentMicros: number | null;
  replacedAuthorizationId: string | null;
  revocationReceipt: ReceiptEnvelopePending | null;
  authorizationProvenance: Record<string, unknown>;
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
  | { decision: "not_approved"; authorizationId: null; expiresAt: null }
) & { receipt?: ReceiptEnvelopePending | null };

export type PromptStatus = PromptStatusResponse["status"];
export type ConfirmationAuthorityStatus = ConfirmationStatusResponse["authorityStatus"];
export type EscalationAuthorityStatus = EscalationStatusResponse["authorityStatus"];
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

/** Compatible status name from SDK 0.6.1. */
export type ConfirmationStatus = ConfirmationStatusResponse;
/** Compatible status name from SDK 0.6.1. */
export type EscalationStatus = EscalationStatusResponse;
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
