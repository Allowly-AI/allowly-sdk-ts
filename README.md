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

## Auth0 agent identity

For an authorization bound to an Auth0 machine identity, supply its short-lived
access token separately from the Allowly runtime key. The supplier runs for
each check or local execution. Use your existing OAuth client library for Auth0
token reuse and keep the client secret outside this SDK.

```typescript
import { Allowly } from "@allowly/sdk";

const allowly = new Allowly({
  apiKey: process.env.ALLOWLY_API_KEY!,
  agentTokenSupplier: getAuth0AgentToken,
});

await allowly.check({
  authorizationId: "auth_...",
  actions: ["order.submit"],
  clientTimestamp: new Date(),
});

```

Identity-enabled checks always fail closed, including token supplier failures
and `identity_verification_unavailable` responses.

## Execute HTTP with provider credentials kept locally

Enable a provider in **Settings → Executables** and grant the exact catalog
operation to an action before using `executeHttp`. The SDK sends a request
descriptor and byte commitments to Allowly for approval, then sends the original
HTTP request from your runtime. Allowly never receives provider credentials or
sends the provider request.
Allowly receives the method, origin, path, query, content type, byte counts, header
names and hashes, body hash, and customer-reported policy input. Header values and
body bytes stay local. Put provider credentials in local headers; do not put
secrets in the URL, query, or policy input.

```typescript
const result = await allowly.executeHttp(
  "https://harvest.greenhouse.io/v3/candidates?per_page=1&private=false",
  {
    operationId: "greenhouse-candidates-list-page-1", // persist and reuse this ID
    authorizationId: "auth_...",
    enabledExecutableId: "exe_...",
    catalogOperationId: "greenhouse.candidates.list",
    action: "greenhouse.candidates.list",
    method: "GET",
    headers: {
      authorization: `Bearer ${process.env.GREENHOUSE_ACCESS_TOKEN}`,
    },
    policyInput: {
      resource: "greenhouse:candidates",
      context: { pageSize: 1, includePrivate: false }, // customer-reported
    },
    journalDirectory: "/var/lib/my-agent/allowly-executions",
  },
);

if (result.state === "not_allowed") return;
if (result.state === "unknown") {
  // Reconcile the same operation. Never send the provider request again.
  await allowly.resumeHttpExecution({
    operationId: "greenhouse-candidates-list-page-1",
    journalDirectory: "/var/lib/my-agent/allowly-executions",
  });
}
```

This uses Greenhouse's documented Harvest v3
[List candidates](https://harvestdocs.greenhouse.io/reference/get_v3-candidates)
endpoint with an OAuth
[Bearer access token](https://harvestdocs.greenhouse.io/docs/authentication). The
GET has no request body, limits the page to one non-private candidate, and needs
the `harvest:candidates:list` scope with a Site Admin authorizing user.

The private journal stores request commitments, the approval, and a pending
outcome upload. It does not store the provider credential or request body. Once
dispatch has been attempted, resume only uploads the same stored outcome or
reconciles the same operation ID. Redirects are not followed, DNS must resolve
only to public addresses, and the chosen address is pinned for the TLS
connection.

The decision receipt can still be pending when the HTTP response returns.
Finish and verify that evidence later; this does not contact the provider:

```typescript
import {
  completeCustomerExecutionEvidence,
  fetchKeysDoc,
  loadKeysFromJson,
} from "@allowly/sdk";

const keys = loadKeysFromJson(await fetchKeysDoc(configuredWorkspaceId));
const completeEvidence = await completeCustomerExecutionEvidence(
  allowly,
  result.evidencePackage,
  keys,
  {
    expectedWorkspaceId: configuredWorkspaceId,
    trustedKeyFingerprints: configuredKeyFingerprints,
  },
);
await saveEvidence(completeEvidence);
```

`receipt` evidence records the customer runtime's reported HTTP outcome. It
does not verify business completion. If the policy upgrades the request to
`witnessed`, `executeHttp` fails closed unless native witness options were
provided. The current native profile is limited to HTTPS on port 443, HTTP/1.1
over TLS 1.2, a 2 KiB request transcript, a 16 KiB UTF-8 response, and no
redirect follow. Use witnessed mode only when the catalog and deployed witness
service report it available.

Run `allowly setup witness` from `@allowly-ai/cli` for the same workspace before
using witnessed execution. That interactive command installs the Rust helper and
pins the public witness key after you compare its fingerprint with the
authenticated workspace page. Then request witnessed mode and give the SDK a new
evidence directory for each operation:

```typescript
await allowly.executeHttp("https://api.vendor.example/v1/items", {
  operationId: "items-read-1",
  authorizationId: "auth_...",
  enabledExecutableId: "exe_...",
  catalogOperationId: "vendor.items.list",
  action: "vendor.items.list",
  evidenceMode: "witnessed",
  journalDirectory: "/var/lib/my-agent/allowly-executions",
  witness: { evidenceDirectory: "/var/lib/my-agent/allowly-evidence/items-read-1" },
});
```

The SDK selects the installed configuration by the approved workspace ID and
checks the pinned key against the witness session before it starts the helper.
To use a separately provisioned helper and public key, provide both
`witness.nativeBinaryPath` and `witness.trustedNotaryKeyPath` with the
`witness.workspaceId` you expect.

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
