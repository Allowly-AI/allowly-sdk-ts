import { Allowly, type ObserveEventStatus, type ObserveSubmitRequest, type PolicyReference } from "../index.js";
const sdk = new Allowly({ apiKey: "runtime-key" });
const policyRef: PolicyReference = { policy_id: "published", policy_version: 1, definition_sha256: "a".repeat(64) };
const request: ObserveSubmitRequest = { eventId: "operation:1", agentId: "agent_demo", action: "email.send", policyRef,
  occurredAt: "2026-10-18T20:00:00Z", reportedExecution: "sent", sources: { body: "captured" } };
const submitted: Promise<ObserveEventStatus> = sdk.observe.submit(request);
const current: Promise<ObserveEventStatus> = sdk.observe.get("operation:1");
void submitted; void current;
// @ts-expect-error Captured source values are strings, not predictions.
void sdk.observe.submit({ ...request, sources: { medical: true } });
// @ts-expect-error Server implementation credentials are not customer inputs.
void sdk.observe.submit({ ...request, collectorSecret: "secret" });
// @ts-expect-error A completed report is required.
void sdk.observe.submit({ ...request, reportedExecution: "allow" });
// @ts-expect-error Reporting has no synchronous enforcement decision.
void ({} as ObserveEventStatus).decision;
