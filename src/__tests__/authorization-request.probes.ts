import type { AuthorizationCreateRequest } from "../types.js";

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
}) satisfies AuthorizationCreateRequest;

// @ts-expect-error one of the two request shapes is required
({ userId: "u1" }) satisfies AuthorizationCreateRequest;

// @ts-expect-error mixing policy and inline shapes is rejected by the API (422)
({ userId: "u1", policyId: "p1", agentId: "a1", actions: ["email.send"], expiresAt: "2026-12-31T00:00:00Z" }) satisfies AuthorizationCreateRequest;

// @ts-expect-error the inline flow requires expiresAt
({ userId: "u1", agentId: "a1", actions: ["email.send"] }) satisfies AuthorizationCreateRequest;

// @ts-expect-error the inline flow requires actions
({ userId: "u1", agentId: "a1", expiresAt: "2026-12-31T00:00:00Z" }) satisfies AuthorizationCreateRequest;
