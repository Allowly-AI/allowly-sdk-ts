import { Allowly } from "../index.js";
import type {
  ExecuteRequest,
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

void client.acknowledgeReceipt({
  receiptId: "rcp_123",
  receiptSha256: "0".repeat(64),
  clientTimestamp: new Date(),
  idempotencyKey: "ack-123",
});

void client.getReceiptAcknowledgment("rcp_123", "ack_123", {
  agentToken: "one-request-token",
});
