import { Allowly, NativeAgentCredential, commitCustomerHttpRequest, verifyResolutionWebhook } from "../index.js";
import type {
  CustomerHttpExecutionResult,
  CustomerHttpProviderResponse,
  NativeAgentCredentialData,
} from "../index.js";
import type {
  ActionEntry,
  CustomerExecutionResponse,
  ContinueExecutionRequest,
  PrepareExecutionRequest,
  ReceiptAcknowledgmentRequest,
} from "../types.js";

const client = new Allowly({
  apiKey: "allowly_l1_s001_...",
  agentTokenSupplier: async () => "auth0-access-token",
});

const enrolledAgent = {
  version: 1,
  provider: "allowly",
  workspace_id: "ws_123",
  agent_id: "agent_123",
  binding_id: "aib_123",
  key_id: "ack_123",
  private_key_jwk: { kty: "OKP", crv: "Ed25519", x: "public-key", d: "private-key" },
} satisfies NativeAgentCredentialData;
const nativeCredential = new NativeAgentCredential(enrolledAgent);
const nativeClient = new Allowly({
  apiKey: "allowly_l1_s001_...",
  agentTokenSupplier: nativeCredential.token,
});
void nativeClient;
const fileCredential: Promise<NativeAgentCredential> =
  NativeAgentCredential.fromFile("/secure/path/agent.json");
void fileCredential;

({
  receiptId: "rcp_123",
  receiptSha256: "0".repeat(64),
  clientTimestamp: "2026-09-24T20:02:03.456Z",
  idempotencyKey: "ack-123",
}) satisfies ReceiptAcknowledgmentRequest;

const greenhouseCandidateListUrl =
  "https://harvest.greenhouse.io/v3/candidates?per_page=1&private=false";
const greenhouseCandidateListHeaders = {
  authorization: "Bearer local-provider-access-token",
};
const greenhouseCandidateListCommitment = commitCustomerHttpRequest(
  greenhouseCandidateListUrl,
  { method: "GET", headers: greenhouseCandidateListHeaders },
);

const executableAction = {
  name: "greenhouse.candidates.list",
  executableOperations: [{
    enabledExecutableId: "exe_123",
    providerId: "greenhouse-harvest",
    operationId: "greenhouse.candidates.list",
    catalogRevision:
      "sha256:b1674bd5fd8889f064ce4fb6b820cffce76e1e449cefa6aefe2802f85639cf6a",
    definitionFingerprint:
      "sha256:0d3deed80ddcfd384aefd12d57f800903811b1a6d01d764caf8f24e64de26498",
    minimumEvidenceMode: "receipt",
  }],
} satisfies ActionEntry;

({
  operationId: "greenhouse-candidates-list-page-1",
  authorizationId: "auth_123",
  enabledExecutableId: "exe_123",
  catalogOperationId: "greenhouse.candidates.list",
  action: "greenhouse.candidates.list",
  evidenceMode: "receipt",
  httpRequest: greenhouseCandidateListCommitment,
  policyInput: {
    resource: "greenhouse:candidates",
    context: { pageSize: 1, includePrivate: false },
  },
  clientTimestamp: new Date(),
  idempotencyKey: "greenhouse-candidates-list-page-1",
}) satisfies PrepareExecutionRequest;

void client.check({
  authorizationId: "auth_123",
  actions: ["order.submit"],
  clientTimestamp: "2026-09-24T20:01:02.123Z",
  agentToken: "one-request-token",
});

// @ts-expect-error Hosted provider dispatch is deliberately absent from this SDK.
void client.execute;
const localExecution: Promise<CustomerExecutionResponse> = client.getExecution(
  "greenhouse-candidates-list-page-1", { agentToken: "one-request-token" },
);
void localExecution;

const httpExecution: Promise<CustomerHttpExecutionResult> = client.executeHttp(greenhouseCandidateListUrl, {
  operationId: "greenhouse-candidates-list-page-1",
  authorizationId: "auth_123",
  enabledExecutableId: "exe_123",
  catalogOperationId: "greenhouse.candidates.list",
  action: "greenhouse.candidates.list",
  method: "GET",
  headers: greenhouseCandidateListHeaders,
  policyInput: {
    resource: "greenhouse:candidates",
    context: { pageSize: 1, includePrivate: false },
  },
  journalDirectory: "/var/lib/my-agent/allowly-executions",
});
void httpExecution.then((result) => {
  if (result.state === "not_allowed" || result.state === "waiting_for_review") return;
  const pending: boolean = result.outcomePending;
  const provider: CustomerHttpProviderResponse | null = result.providerResponse;
  const report: CustomerExecutionResponse | null = result.response;
  void [pending, provider, report];
});
const resumedExecution: Promise<CustomerHttpExecutionResult> = client.resumeHttpExecution({
  operationId: "greenhouse-candidates-list-page-1",
  journalDirectory: "/var/lib/my-agent/allowly-executions",
});
void resumedExecution;

const continuedExecution: Promise<CustomerHttpExecutionResult> = client.continueHttpExecution(
  greenhouseCandidateListUrl,
  {
    operationId: "greenhouse-candidates-list-page-1",
    authorizationId: "auth_123",
    enabledExecutableId: "exe_123",
    catalogOperationId: "greenhouse.candidates.list",
    action: "greenhouse.candidates.list",
    method: "GET",
    headers: greenhouseCandidateListHeaders,
    journalDirectory: "/var/lib/my-agent/allowly-executions",
  },
);
void continuedExecution;

const continuation = {
  executionRequest: {
    operationId: "greenhouse-candidates-list-page-1",
    authorizationId: "auth_123",
    enabledExecutableId: "exe_123",
    catalogOperationId: "greenhouse.candidates.list",
    action: "greenhouse.candidates.list",
    evidenceMode: "receipt",
    httpRequest: greenhouseCandidateListCommitment,
    clientTimestamp: "2026-09-24T20:01:02.123Z",
  },
  reviewId: "cnf_123",
  sourceReceiptId: "rcp_123",
  idempotencyKey: "continue-123",
} satisfies ContinueExecutionRequest;
const continuationApproval: Promise<CustomerExecutionResponse> = client.continueExecution(continuation);
void continuationApproval;

// @ts-expect-error Continuation requires the original request, not only an operation ID.
void client.continueExecution({ operationId: "greenhouse-candidates-list-page-1" });

const confirmationStatus: Promise<import("../index.js").ConfirmationStatusResponse> = client.confirmations.getStatus("cnf_example");
const escalationStatus: Promise<import("../index.js").EscalationStatusResponse> = client.escalations.getStatus("esc_example");
const readiness: Promise<boolean> = client.readiness();
void confirmationStatus; void escalationStatus; void readiness;

const webhookConfig: Promise<import("../index.js").ResolutionWebhookConfig> = client.resolutionWebhook.get();
const webhookSecret: Promise<import("../index.js").ResolutionWebhookSecret> = client.resolutionWebhook.configure("https://customer.example/decisions");
const webhookDeliveries: Promise<import("../index.js").ResolutionWebhookDeliveries> = client.resolutionWebhook.deliveries();
const webhookEvent: import("../index.js").ResolutionWebhookEvent = verifyResolutionWebhook(new Uint8Array([123, 125]), {}, {
  signingSecret: "whsec_...", expectedWorkspaceId: "ws_123",
});
void webhookConfig; void webhookSecret; void webhookDeliveries; void webhookEvent;

void client.authorizations.create({
  userId: "user_123",
  agentId: "agent_123",
  actions: [executableAction],
  expiresAt: "2026-12-31T00:00:00Z",
});

void client.acknowledgeReceipt({
  receiptId: "rcp_123",
  receiptSha256: "0".repeat(64),
  clientTimestamp: new Date(),
  idempotencyKey: "ack-123",
});

void client.getReceiptAcknowledgment("rcp_123", "ack_123", {
  agentToken: "one-request-token",
});
