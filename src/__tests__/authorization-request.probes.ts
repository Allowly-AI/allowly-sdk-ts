import type { AuthorizationCreateRequest } from "../types.js";
import { Allowly } from "../client.js";

// Compile-time probes for the two-shape authorization request union.
// No runtime assertions here — `npm run typecheck` is the test.

({ userId: "u1", policyId: "p1" }) satisfies AuthorizationCreateRequest;

({
  userId: "u1",
  policyId: "p1",
  expiresAt: "2026-12-31T00:00:00Z",
  budgetLimitMicros: 50_000_000,
}) satisfies AuthorizationCreateRequest;

({
  userId: "u1",
  agentId: "a1",
  actions: ["email.send"],
  expiresAt: "2026-12-31T00:00:00Z",
}) satisfies AuthorizationCreateRequest;

({
  userId: "u1",
  agentId: "a1",
  actions: [{ name: "email.send", constraints: { max_per_day: 5 } }],
  expiresAt: new Date("2026-12-31T00:00:00Z"),
  replaces: "auth_old",
  requiresConfirmFor: ["email.send"],
  requiresEscalationFor: ["candidate.delete"],
  requiresDenyFor: ["payments.send"],
  escalationTargets: { "candidate.delete": "compliance" },
}) satisfies AuthorizationCreateRequest;

({
  userId: "u1",
  policyId: "p1",
  // @ts-expect-error policy-based requests cannot override reviewed confirmation decisions
  requiresConfirmFor: ["email.send"],
}) satisfies AuthorizationCreateRequest;

({
  userId: "u1",
  policyId: "p1",
  // @ts-expect-error policy-based requests cannot override reviewed escalation decisions
  requiresEscalationFor: ["candidate.delete"],
}) satisfies AuthorizationCreateRequest;

({
  userId: "u1",
  policyId: "p1",
  // @ts-expect-error policy-based requests cannot override reviewed deny decisions
  requiresDenyFor: ["payments.send"],
}) satisfies AuthorizationCreateRequest;

({
  userId: "u1",
  policyId: "p1",
  // @ts-expect-error policy-based requests cannot override reviewed escalation targets
  escalationTargets: { "candidate.delete": "compliance" },
}) satisfies AuthorizationCreateRequest;

new Allowly({
  apiKey: "test-key",
  // @ts-expect-error fail-open is only configurable per action
  defaultFallback: "fail_open",
});

const client = new Allowly({ apiKey: "test-key" });
client.authorizations.revoke("auth_old", {
  // @ts-expect-error replacements must use authorizations.create({ replaces: "auth_old" })
  supersededBy: "auth_new",
});

// @ts-expect-error one of the two request shapes is required
({ userId: "u1" }) satisfies AuthorizationCreateRequest;

// @ts-expect-error mixing policy and inline shapes is rejected by the API (422)
({ userId: "u1", policyId: "p1", agentId: "a1", actions: ["email.send"], expiresAt: "2026-12-31T00:00:00Z" }) satisfies AuthorizationCreateRequest;

// @ts-expect-error the inline flow requires expiresAt
({ userId: "u1", agentId: "a1", actions: ["email.send"] }) satisfies AuthorizationCreateRequest;

// @ts-expect-error the inline flow requires actions
({ userId: "u1", agentId: "a1", expiresAt: "2026-12-31T00:00:00Z" }) satisfies AuthorizationCreateRequest;
