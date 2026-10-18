import type { AuthorizationCreateRequest, BasicPolicy, PolicyDefinition } from "../types.js";
import { Allowly } from "../client.js";
import type { PolicyEvidenceRequirement } from "../index.js";

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
      decision: "confirm", target: "agent_owner", fields: { tags: "list" },
      rules: [{ id: "sensitive-tags", decision: "escalate", target: "member:reviewer",
        conditions: [
          { field: "tags", op: "contains_any", value: ["sensitive", 1, true, null] },
          { field: "tags", op: "contains_none", value: ["internal"] },
          { field: "tags", op: "empty", value: false },
        ] }] },
    guards: {}, executable_operations: [],
  }],
};
const client = new Allowly({ apiKey: "setup-key" });
({ ...definition.actions[0].policy,
  // @ts-expect-error old fallback fields are not policy authority
  default_decision: "allow", default_target: null,
}) satisfies BasicPolicy;
void client.policies.create({ policyId: "p1", definition });
void client.policies.preview({ definition, action: "email.send", context: {} });
void client.policies.publish({ policyId: "p1", definition, idempotencyKey: "publish-p1" });
const evidence = {
  sensitive: { sources: ["body"], instruction: "Identify sensitive information." },
  external: { sources: ["recipient"], instruction: "Is the recipient outside example.com?" },
  both: { all_of: ["sensitive", "external"] },
  domain: { source: "recipient", transform: "email_domain", empty_sources: ["cc", "bcc"] },
} satisfies Record<string, PolicyEvidenceRequirement>;
const observedDefinition: PolicyDefinition = {
  ...definition,
  actions: [{
    ...definition.actions[0],
    policy: { ...definition.actions[0].policy, decision: "allow", target: null,
      fields: { sensitive: "boolean", external: "boolean", both: "boolean", domain: "string" }, rules: [] },
    evidence,
  }],
};
void client.policies.create({ policyId: "observed", definition: observedDefinition });
void client.policies.preview({ definition: observedDefinition, action: "email.send", context: {} });
void client.policies.publish({ policyId: "observed", definition: observedDefinition, idempotencyKey: "publish-observed" });
// @ts-expect-error evidence has no executable extraction transform
({ source: "body", transform: "arbitrary_code", empty_sources: [] }) satisfies PolicyEvidenceRequirement;
// @ts-expect-error the full envelope-empty check is explicit for domain extraction
({ source: "recipient", transform: "email_domain" }) satisfies PolicyEvidenceRequirement;
// @ts-expect-error absence is permitted; explicit null is not evidence metadata
({ ...observedDefinition.actions[0], evidence: null }) satisfies PolicyDefinition["actions"][number];
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
