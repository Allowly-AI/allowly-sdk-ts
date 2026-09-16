# @allowly/sdk

TypeScript SDK for the Allowly runtime API. Check an agent action before it
runs, handle allow/deny/confirm/escalate decisions, and verify signed receipts.

Requires Node.js 20 or newer. This package is ESM-only.

## Install

```bash
npm install @allowly/sdk
```

## Check an action

```typescript
import { Allowly } from "@allowly/sdk";

const allowly = new Allowly({
  apiKey: process.env.ALLOWLY_API_KEY!,
});

const result = await allowly.check({
  authorizationId: "auth_...",
  actions: ["email.send"],
  resource: "gmail:thread:abc",
  context: { initiated_by: "user" },
});

const decision = result.results["email.send"];
if (decision.decision === "allow") {
  await sendTheEmail();
} else {
  // deny stops; confirm and escalate pause for your application's resolution flow.
  throw new Error(`Action not allowed: ${decision.decision} (${decision.reason})`);
}
```

Only `allow` permits execution. Unavailable checks fail closed unless that
action has an explicit `fail_open` fallback configured.

## Create an authorization

Create one authorization for the subject and store its ID in your application:

```typescript
const authorization = await allowly.authorizations.create({
  userId: "subject_abc123",
  policyId: "research_agent",
  expiresAt: "2026-12-31T00:00:00.000Z",
});

await saveAuthorizationId(authorization.authorizationId);
```

Use opaque internal subject IDs. Avoid putting raw names, emails, documents, or
other sensitive data into receipt fields unless that data is intentionally part
of the audit record.

## Send JSON through a private SEAL webhook

Copy the private URL from the dashboard's **SEAL** page. The URL is the only
credential this client sends; it does not use an ordinary API key.

```typescript
import { SealWebhookClient } from "@allowly/sdk";

const webhook = new SealWebhookClient(process.env.ALLOWLY_SEAL_WEBHOOK_URL!);
let delivery = await webhook.send(rawJson, {
  idempotencyKey: eventId,
  type: "invoice",
  reference: "INV-1042",
  statement: "Approved for payment",
});
while (delivery.status === "received" || delivery.status === "signing") {
  await new Promise((resolve) => setTimeout(resolve, 1_000));
  delivery = await webhook.getDelivery(delivery.attemptId);
}
if (delivery.status !== "sealed") {
  throw new Error(delivery.errorCode ?? "SEAL delivery failed");
}
await saveEvidence(delivery.receipt, await webhook.getKeys());
```

The webhook processes your JSON to create a fingerprint; Allowly stores the
fingerprint and signed receipt. Keep the original record in your workflow.
Receipt details are sent in the three explicit `Allowly-Seal-*` headers. Their
values must use printable ASCII, may contain interior spaces, and must not have
leading or trailing whitespace. The client rejects invalid values instead of
changing them. Direct API metadata still supports its existing Unicode values.
When a signed receipt is present, the client returns its signed metadata and
rejects a conflicting top-level delivery projection.
Treat the full URL like a password and keep it out of logs, tickets, and source
control. Regenerating or disabling it stops the old URL. Delivery associations
and status remain available for 7 days; preserve signed receipts and keys under
your own retention policy. With no `idempotencyKey`, retrying after a lost
response can create another seal.

## Seal a JSON record with local hashing

`seal` hashes strict raw JSON in your process, sends only its digest to Allowly,
and waits for the full signed receipt. Generate and persist `requestId` in your
workflow so a retry recovers the same seal:

```typescript
import { randomUUID } from "node:crypto";

const requestId = randomUUID();
const sealed = await allowly.seal(rawJson, {
  requestId,
  metadata: { source: "invoice-workflow" },
});
await saveBesideRecord(sealed.receipt);
```

Use `sealValue(parsedJson, ...)` only when the original JSON text is no longer
available. A parsed value cannot reveal duplicate object names or the original
number spelling, so `seal` is the safer input boundary.

Verify later with the authenticated `workspaceId` response and keys fetched
from Allowly through an authenticated or previously trusted source:

```typescript
import { loadKeysFromJson, verifySealJson } from "@allowly/sdk";

const result = await verifySealJson(rawJson, sealed.receipt, loadKeysFromJson(keysDoc), {
  expectedWorkspaceId: sealed.workspaceId,
  trustedKeyFingerprints: configuredKeyFingerprints,
});
if (!result.signatureVerified || !result.recordMatches) {
  throw new Error(result.failureReason ?? "SEAL verification failed");
}
```

## Verify a signed receipt

```typescript
import { fetchKeysDoc, loadKeysFromJson, verifyReceipt } from "@allowly/sdk";

const receipt = await allowly.receipts.fetchSigned(receiptId);
const workspaceId = process.env.ALLOWLY_WORKSPACE_ID!;
const keys = loadKeysFromJson(await fetchKeysDoc(workspaceId));

await verifyReceipt(receipt, keys, { expectedWorkspaceId: workspaceId });
```

Take the expected workspace ID from trusted application configuration, not from
the receipt being verified.

## Documentation

- [TypeScript SDK guide](https://allowly.ai/docs/sdk/typescript)
- [Agent integration loop](https://allowly.ai/docs/sdk/agent-loop)
- [MCP middleware](https://allowly.ai/docs/sdk/mcp)
