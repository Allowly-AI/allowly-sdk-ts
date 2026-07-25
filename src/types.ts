export type Decision = "allow" | "deny" | "confirm" | "escalate";
export type FallbackMode = "fail_open" | "fail_closed";

export interface ReceiptEnvelopePending {
  status: "pending";
  receiptId: string | null;
  readyAtEstimate: string | null;
  url: string | null;
}

export interface ReceiptEnvelopeSigned {
  status: "signed";
  receipt: Record<string, unknown>;
}

export type ReceiptEnvelope = ReceiptEnvelopePending | ReceiptEnvelopeSigned;

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
}

export interface ActionEntry {
  name: string;
  constraints?: Record<string, unknown>;
}

/**
 * Canonical flow: pass `policyId` referencing a reusable agent policy.
 * Inline flow (`agentId` + `actions`, no `policyId`) is for prototyping and
 * ad-hoc per-user grants. Exactly one of the two shapes must be used.
 */
export interface AuthorizationCreateRequest {
  userId: string;
  policyId?: string;
  agentId?: string;
  actions?: ActionEntry[] | string[];
  requiresConfirmFor?: string[];
  requiresEscalationFor?: string[];
  requiresDenyFor?: string[];
  escalationTargets?: Record<string, string>;
  budgetLimitMicros?: number;
  expiresAt?: Date | string;
  replaces?: string;
  metadata?: Record<string, unknown>;
  idempotencyKey?: string;
}

export interface AuthorizationCreateResponse {
  authorizationId: string;
  policyId: string | null;
  createdAt: string;
  expiresAt: string;
  receipt: ReceiptEnvelopePending;
  requiresEscalationFor: string[];
  requiresDenyFor: string[];
  escalationTargets: Record<string, string>;
  budgetLimitMicros: number | null;
  budgetSpentMicros: number | null;
  replacedAuthorizationId: string | null;
  revocationReceipt: ReceiptEnvelopePending | null;
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

export interface ConfirmationApproveResponse {
  decision: "approved" | "denied_by_user";
  authorizationId?: string;
  expiresAt?: string;
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
  baseUrl?: string;
  dangerouslyAllowInsecureBaseUrl?: boolean;
  fetch?: typeof globalThis.fetch;
  checkTimeoutMs?: number;
  requestTimeoutMs?: number;
  defaultFallback?: FallbackMode;
  fallbackByAction?: Record<string, FallbackMode>;
}

export interface AllowlyError {
  code: string;
  message: string;
  fields?: Array<{ field: string; message: string }>;
}
