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
