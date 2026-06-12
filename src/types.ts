export type Decision = "allow" | "deny" | "confirm" | "escalate";
export type FallbackMode = "fail_open" | "fail_closed";

export interface ReceiptEnvelopePending {
  status: "pending";
  receiptId: string;
  readyAtEstimate: string;
  url: string;
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
  policyVersion: string;
  results: Record<string, ActionCheckResult>;
}

export interface ActionEntry {
  name: string;
  constraints?: Record<string, unknown>;
}

export interface AuthorizationCreateRequest {
  userId: string;
  agentId?: string;
  policyId?: string;
  actions?: ActionEntry[] | string[];
  requiresConfirmFor?: string[];
  requiresEscalationFor?: string[];
  escalationTargets?: Record<string, string>;
  budgetLimitMicros?: number;
  expiresAt?: Date | string;
  replaces?: string;
  metadata?: Record<string, unknown>;
}

export interface AuthorizationCreateResponse {
  authorizationId: string;
  policyId?: string;
  createdAt: string;
  expiresAt: string;
  receipt: ReceiptEnvelopePending;
  requiresConfirmFor: string[];
  requiresEscalationFor: string[];
  escalationTargets: Record<string, string>;
  budgetLimitMicros?: number;
  budgetSpentMicros?: number;
}

export interface AuthorizationRevokeResponse {
  authorizationId: string;
  revokedAt: string;
  receipt: ReceiptEnvelopePending;
}

export interface ConfirmationApproveRequest {
  approved: boolean;
  ttlSeconds?: number;
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
  defaultFallback?: FallbackMode;
  fallbackByAction?: Record<string, FallbackMode>;
}

export interface FetchKeysDocOptions {
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
  cacheTtlMs?: number;
  expectedSha256?: string;
}

export interface AllowlyError {
  code: string;
  message: string;
  fields?: Array<{ field: string; message: string }>;
}
