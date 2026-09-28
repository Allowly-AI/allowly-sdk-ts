import { Allowly } from "../index.js";
import type {
  ActionEntry,
  ExecuteRequest,
  PrepareExecutionRequest,
  ReceiptAcknowledgmentRequest,
} from "../types.js";

const client = new Allowly({
  apiKey: "allowly_l1_s001_...",
  agentTokenSupplier: async () => "auth0-access-token",
});

({
  operationId: "order-123",
  authorizationId: "auth_123",
  destinationId: "dst_123",
  payload: { order: { id: "ord_123" } },
  clientTimestamp: new Date(),
  idempotencyKey: "order-123",
}) satisfies ExecuteRequest;

({
  receiptId: "rcp_123",
  receiptSha256: "0".repeat(64),
  clientTimestamp: "2026-09-24T20:02:03.456Z",
  idempotencyKey: "ack-123",
}) satisfies ReceiptAcknowledgmentRequest;

const executableAction = {
  name: "greenhouse.candidates.update",
  executableOperations: [{
    enabledExecutableId: "exe_123",
    providerId: "greenhouse",
    operationId: "greenhouse.candidates.update",
    catalogRevision: "catalog-2026-09-27",
    definitionFingerprint: `sha256:${"0".repeat(64)}`,
    minimumEvidenceMode: "receipt",
  }],
} satisfies ActionEntry;

({
  operationId: "candidate-123-offer-1",
  authorizationId: "auth_123",
  enabledExecutableId: "exe_123",
  catalogOperationId: "greenhouse.candidates.update",
  action: "greenhouse.candidates.update",
  evidenceMode: "receipt",
  httpRequest: {
    method: "PATCH",
    origin: "https://harvest.greenhouse.io",
    path: "/v1/candidates/123",
    query: "",
    headers: [],
    bodySha256: `sha256:${"0".repeat(64)}`,
    bodySize: 0,
    contentType: null,
  },
  clientTimestamp: new Date(),
  idempotencyKey: "candidate-123-offer-1",
}) satisfies PrepareExecutionRequest;

void client.check({
  authorizationId: "auth_123",
  actions: ["order.submit"],
  clientTimestamp: "2026-09-24T20:01:02.123Z",
  agentToken: "one-request-token",
});

void client.execute({
  operationId: "order-123",
  authorizationId: "auth_123",
  destinationId: "dst_123",
  payload: { order: { id: "ord_123" } },
  clientTimestamp: new Date(),
  idempotencyKey: "order-123",
});

void client.getExecution("order-123", { agentToken: "one-request-token" });

void client.executeHttp("https://harvest.greenhouse.io/v1/candidates/123", {
  operationId: "candidate-123-offer-1",
  authorizationId: "auth_123",
  enabledExecutableId: "exe_123",
  catalogOperationId: "greenhouse.candidates.update",
  action: "greenhouse.candidates.update",
  method: "PATCH",
  headers: { authorization: "Basic local-provider-credential" },
  journalDirectory: "/var/lib/my-agent/allowly-executions",
});

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
