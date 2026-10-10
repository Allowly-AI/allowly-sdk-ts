import type { AuthorizationCreateRequest, PolicyDefinition } from "../types.js";
import { Allowly } from "../client.js";

// Exact logical policy edition and optional names-only action scope.
({ userId: "u1", policyId: "p1", policyVersion: 1 }) satisfies AuthorizationCreateRequest;
({
  userId: "u1", policyId: "p1", policyVersion: 1, actions: ["email.send"],
  expiresAt: "2027-01-01T00:00:00Z", budgetLimitMicros: 0, replaces: "auth_old",
}) satisfies AuthorizationCreateRequest;

// @ts-expect-error a policy version is required
({ userId: "u1", policyId: "p1" }) satisfies AuthorizationCreateRequest;
// @ts-expect-error the old inline grant shape is gone
({ userId: "u1", agentId: "a1", actions: ["email.send"], expiresAt: new Date() }) satisfies AuthorizationCreateRequest;
({
  userId: "u1", policyId: "p1", policyVersion: 1,
  // @ts-expect-error action objects/inline constraints are not grant scope
  actions: [{ name: "email.send", constraints: { max_per_day: 5 } }],
}) satisfies AuthorizationCreateRequest;
({
  userId: "u1", policyId: "p1", policyVersion: 1,
  // @ts-expect-error reviewed decisions belong to the retained definition
  requiresConfirmFor: ["email.send"],
}) satisfies AuthorizationCreateRequest;

const definition: PolicyDefinition = {
  profile: "allowly.policy.v1", agent_id: "a1", default_expiry_days: 7,
  actions: [{
    policy: { profile: "allowly.basic.v1", action: "email.send",
      default_decision: "confirm", default_target: "agent_owner", fields: {}, rules: [] },
    guards: {}, executable_operations: [],
  }],
};
const client = new Allowly({ apiKey: "setup-key" });
void client.policies.create({ policyId: "p1", definition });
void client.policies.preview({ definition, action: "email.send", context: {} });
void client.policies.publish({ policyId: "p1", definition, idempotencyKey: "publish-p1" });
// @ts-expect-error publication requires an explicit stable idempotency key
void client.policies.publish({ policyId: "p1", definition });
new Allowly({
  apiKey: "test-key",
  // @ts-expect-error fail-open is only configurable per action
  defaultFallback: "fail_open",
});
client.authorizations.revoke("auth_old", {
  // @ts-expect-error replacements must use authorizations.create({ replaces: "auth_old" })
  supersededBy: "auth_new",
});
