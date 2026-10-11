import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { Allowly, AllowlyAPIError, AllowlyProtocolError, decodeReceipt } from "../index.js";
import { definitionDigest, parsePolicyEvaluation, parsePolicyReference, validatePolicyDefinition } from "../policies.js";
import type { BasicCondition, PolicyDefinition } from "../types.js";

const BASE = "https://api.example.com";
const vectors: { signature_cases: Array<{ name: string; definition: PolicyDefinition; receipt: any }> } = JSON.parse(readFileSync(new URL("../../../allowly-receipt-format/vectors/policy/profile-v1.json", import.meta.url), "utf8"));
function definition(): PolicyDefinition { return structuredClone(vectors.signature_cases[1].definition); }
function response(value = definition(), policyId = "review", version = 1) {
  return { policy_ref: { policy_id: policyId, policy_version: version, definition_sha256: definitionDigest(value) },
    definition: value, description: null, created_by: "member:owner", created_at: "2026-10-10T00:00:00Z", deleted_at: null };
}
function fetchResponse(status: number, value: unknown) {
  return { ok: status >= 200 && status < 300, status, redirected: false, headers: new Headers(), json: async () => value };
}
function mockFetch(status: number, value: unknown) { return vi.fn().mockResolvedValue(fetchResponse(status, value)); }

describe("canonical policy JSON", () => {
  it.each(vectors.signature_cases)("keeps shared $name evidence without renaming or recalculating it", item => {
    expect(validatePolicyDefinition(item.definition)).toEqual(item.definition);
    expect(parsePolicyEvaluation(decodeReceipt(item.receipt).policy_eval)).toEqual(decodeReceipt(item.receipt).policy_eval);
    expect(parsePolicyReference(decodeReceipt(item.receipt).policy_ref)).toEqual(decodeReceipt(item.receipt).policy_ref);
  });

  const invalid: Array<[string, (value: any) => void]> = [
    ["old constraints", d => d.actions[0].constraints = {}],
    ["requires map", d => d.requires_confirm_for = []],
    ["missing expiry", d => delete d.default_expiry_days],
    ["float expiry", d => d.default_expiry_days = 1.5],
    ["boolean expiry", d => d.default_expiry_days = true],
    ["NUL agent", d => d.agent_id = "agent\0"],
    ["unpaired surrogate", d => d.agent_id = "agent\ud800"],
    ["decision label action", d => d.actions[0].policy.action = "allow"],
    ["long action", d => d.actions[0].policy.action = "a".repeat(65)],
    ["unknown basic member", d => d.actions[0].policy.extra = true],
    ["duplicate action", d => d.actions.push(structuredClone(d.actions[0]))],
    ["null guard", d => d.actions[0].guards.max_per_day = null],
    ["boolean guard", d => d.actions[0].guards.max_per_day = true],
    ["unknown guard", d => d.actions[0].guards.confirmation = true],
    ["duplicate initiator", d => d.actions[0].guards.allowed_initiators = ["a", "a"]],
    ["allow target", d => { d.actions[0].policy.decision = "allow"; d.actions[0].policy.target = "agent_owner"; }],
    ["deny target", d => { d.actions[0].policy.decision = "deny"; d.actions[0].policy.target = "agent_owner"; }],
    ["confirm team", d => { d.actions[0].policy.decision = "confirm"; d.actions[0].policy.target = "team:legal"; }],
    ["confirm null", d => { d.actions[0].policy.decision = "confirm"; d.actions[0].policy.target = null; }],
    ["escalate team", d => { d.actions[0].policy.decision = "escalate"; d.actions[0].policy.target = "team:legal"; }],
    ["empty member", d => { d.actions[0].policy.decision = "escalate"; d.actions[0].policy.target = "member: "; }],
    ["escalate null", d => { d.actions[0].policy.decision = "escalate"; d.actions[0].policy.target = null; }],
    ["missing action decision", d => delete d.actions[0].policy.decision],
    ["missing action target", d => delete d.actions[0].policy.target],
    ["legacy default decision", d => d.actions[0].policy.default_decision = "allow"],
    ["legacy default target", d => d.actions[0].policy.default_target = null],
    ["undeclared field", d => d.actions[0].policy.rules[0].conditions[0].field = "absent"],
    ["old neq", d => d.actions[0].policy.rules[0].conditions[0].op = "neq"],
    ["integer boolean", d => d.actions[0].policy.rules[0].conditions[0].value = true],
    ["unsafe integer", d => d.actions[0].policy.rules[0].conditions[0].value = 2 ** 53],
    ["float condition", d => d.actions[0].policy.rules[0].conditions[0].value = 1.5],
    ["exists string", d => { d.actions[0].policy.rules[0].conditions[0].op = "exists"; d.actions[0].policy.rules[0].conditions[0].value = "true"; }],
    ["membership scalar", d => { d.actions[0].policy.rules[0].conditions[0].op = "not_in"; d.actions[0].policy.rules[0].conditions[0].value = 1; }],
    ["duplicate rule", d => d.actions[0].policy.rules.push(structuredClone(d.actions[0].policy.rules[0]))],
    ["empty conditions", d => d.actions[0].policy.rules[0].conditions = []],
    ["unknown rule key", d => d.actions[0].policy.rules[0].priority = 1],
    ["rule review target", d => { d.actions[0].policy.rules[0].decision = "confirm"; d.actions[0].policy.rules[0].target = "someone"; }],
  ];
  it.each(invalid)("rejects %s without an old-shape translator", (_name, edit) => {
    const value = definition(); edit(value);
    expect(() => validatePolicyDefinition(value)).toThrow(AllowlyProtocolError);
  });
  it("rejects the legacy default fields instead of replacing action decision and target", () => {
    const value: any = definition(), policy = value.actions[0].policy;
    policy.default_decision = policy.decision; delete policy.decision;
    policy.default_target = policy.target; delete policy.target;
    expect(() => validatePolicyDefinition(value)).toThrow(AllowlyProtocolError);
  });
  it.each<["allow" | "deny" | "confirm" | "escalate", string | null]>([
    ["allow", null], ["deny", null], ["confirm", "agent_owner"], ["escalate", "member:reviewer"],
  ])("retains action %s and target %j when reading saved policies", async (decision, target) => {
    const value = definition(); Object.assign(value.actions[0].policy, { decision, target });
    const policy = response(value), fetch = vi.fn().mockResolvedValueOnce(fetchResponse(200, policy))
      .mockResolvedValueOnce(fetchResponse(200, { items: [policy], has_more: false }));
    const client = new Allowly({ apiKey: "setup-key", baseUrl: BASE, fetch });
    expect((await client.policies.get("review")).definition).toEqual(value);
    expect((await client.policies.list()).items[0].definition).toEqual(value);
  });
  it.each<[BasicCondition["op"], BasicCondition["value"]]>([
    ["contains_any", ["sensitive", 1, true, null]], ["contains_none", ["external"]],
    ["contains_any", Array.from({ length: 64 }, (_, index) => index)],
    ["empty", true], ["empty", false], ["exists", true], ["exists", false],
  ])("retains list %s with exact scalar operands %j", (op, compared) => {
    const value = definition(), policy = value.actions[0].policy;
    policy.fields.tags = "list";
    policy.rules[0].conditions = [{ field: "tags", op, value: compared }];
    const snapshot = validatePolicyDefinition(value);
    expect(snapshot).toEqual(value); expect(snapshot).not.toBe(value);
  });
  it.each([
    ["list", "contains_any", []], ["list", "contains_none", []],
    ["list", "contains_any", Array.from({ length: 65 }, (_, index) => index)],
    ["list", "contains_any", "sensitive"],
    ["list", "contains_any", [["sensitive"]]], ["list", "contains_none", [{ tag: "sensitive" }]],
    ["list", "contains_any", [1.5]], ["list", "contains_any", [2 ** 53]], ["list", "contains_none", [NaN]],
    ["list", "empty", 1], ["list", "empty", "true"], ["list", "empty", null],
    ["list", "eq", []], ["list", "ne", "sensitive"], ["list", "gt", 1],
    ["list", "in", []], ["list", "not_in", []],
    ["string", "contains_any", ["sensitive"]], ["integer", "contains_none", [1]],
    ["boolean", "empty", true], ["null", "empty", false], ["array", "contains_any", ["sensitive"]],
  ])("rejects list condition type/shape %j %j %j", (declared, op, compared) => {
    const value: any = definition(), policy = value.actions[0].policy;
    policy.fields.tags = declared;
    policy.rules[0].conditions = [{ field: "tags", op, value: compared }];
    expect(() => validatePolicyDefinition(value)).toThrow(AllowlyProtocolError);
  });
  it.each<["string" | "integer" | "boolean" | "null", BasicCondition["op"], BasicCondition["value"]]>([
    ["string", "eq", "internal"], ["string", "ne", "external"],
    ["integer", "gt", -1], ["integer", "gte", 0], ["integer", "lt", 1], ["integer", "lte", Number.MAX_SAFE_INTEGER],
    ["boolean", "eq", true], ["null", "eq", null], ["string", "in", ["internal"]], ["integer", "not_in", [0]],
    ["boolean", "in", []], ["null", "not_in", []],
  ])("keeps scalar %s %s %j supported", (declared, op, compared) => {
    const value = definition(), policy = value.actions[0].policy;
    policy.fields.scalar = declared;
    policy.rules[0].conditions = [{ field: "scalar", op, value: compared }];
    expect(validatePolicyDefinition(value)).toEqual(value);
  });
  it.each([true, false, 0, -1, 1.5, 2 ** 53, "1", null])("rejects a non-positive safe version %j", version => {
    expect(() => parsePolicyReference({ policy_id: "review", policy_version: version, definition_sha256: "a".repeat(64) })).toThrow(AllowlyProtocolError);
  });
  it("retains ordered rules, Unicode field names, safe integers and literal escaped NUL text", () => {
    const value = definition(), basic = value.actions[0].policy;
    basic.rules.push({ ...structuredClone(basic.rules[0]), id: "second" });
    basic.fields["𐀀"] = "string";
    basic.fields["\uff61"] = "string";
    basic.rules[0].conditions[0].value = Number.MAX_SAFE_INTEGER;
    value.actions[0].guards.resource_pattern = String.raw`record:\u0000`;
    const snapshot = validatePolicyDefinition(value);
    expect(snapshot).toEqual(value); expect(snapshot).not.toBe(value);
    expect(snapshot.actions[0].policy.rules.map(rule => rule.id)).toEqual([basic.rules[0].id, "second"]);
    expect(definitionDigest(snapshot)).toBe(definitionDigest(value));
  });
  const badEvidence: Array<[string, (value: any) => void]> = [
    ["old summary", e => e.matched_condition = null], ["uppercase digest", e => e.input_sha256 = "A".repeat(64)],
    ["failure status", e => e.result.status = "error"], ["unknown result", e => e.result.extra = true],
    ["missing target", e => delete e.result.target], ["confirm team", e => { e.result.decision = "confirm"; e.result.target = "team:legal"; }],
    ["allow target", e => { e.result.decision = "allow"; e.result.target = "agent_owner"; }],
    ["action-level fields", e => { e.result.matched_rule_id = null; e.result.evaluated_fields = { risk: 1 }; }],
    ["float fields", e => e.result.evaluated_fields = { risk: 1.5 }],
  ];
  it.each(badEvidence)("rejects malformed provisional evidence: %s", (_name, edit) => {
    const value = structuredClone(decodeReceipt(vectors.signature_cases[1].receipt).policy_eval!); edit(value);
    expect(() => parsePolicyEvaluation(value)).toThrow(AllowlyProtocolError);
  });
  it("retains arbitrary canonical JSON reported by an exists condition", () => {
    const value = structuredClone(decodeReceipt(vectors.signature_cases[1].receipt).policy_eval!);
    value.result.evaluated_fields = { value: { present: [null, true, 0, "nested"] } };
    expect(parsePolicyEvaluation(value)).toEqual(value);
  });
  it("keeps exact witnessed executable grants in retained authoring definitions", () => {
    const value = definition();
    value.actions[0].executable_operations = [{ enabled_executable_id: "exe_1", provider_id: "vendor", operation_id: "vendor.read", catalog_revision: "r1", definition_fingerprint: `sha256:${"a".repeat(64)}`, minimum_evidence_mode: "witnessed" }];
    expect(validatePolicyDefinition(value)).toEqual(value);
    const invalid = structuredClone(value); invalid.actions[0].executable_operations.push(invalid.actions[0].executable_operations[0]);
    expect(() => validatePolicyDefinition(invalid)).toThrow(AllowlyProtocolError);
  });
});

describe("policy setup transport", () => {
  it.each(["2026-04-19.1", "a".repeat(64), `sha256:${"A".repeat(64)}`, `sha256:${"a".repeat(63)}`, "", null])("rejects old or malformed Check engine identity %j without fallback", async engine => {
    const client = new Allowly({ apiKey: "runtime-key", baseUrl: BASE, fallbackByAction: { "web.search": "fail_open" }, fetch: mockFetch(200, {
      authorization_id: "auth_1", engine_version: engine,
      results: { "web.search": { decision: "allow", reason: "authorization_granted_action_active", receipt: null } },
    }) });
    await expect(client.check({ authorizationId: "auth_1", actions: ["web.search"] })).rejects.toBeInstanceOf(AllowlyProtocolError);
  });
  it.each([
    { matched_condition: null, decision: "allow", evaluated_fields: {} },
    { input_sha256: "a".repeat(64) },
    { input_sha256: "a".repeat(64), result: { profile: "allowly.basic.v1", status: "ok", decision: "allow", target: null, matched_rule_id: null, evaluated_fields: { risk: 1 } } },
  ])("rejects malformed Check OPA evidence %j without unsigned fallback", async evaluation => {
    const client = new Allowly({ apiKey: "runtime-key", baseUrl: BASE, fallbackByAction: { "web.search": "fail_open" }, fetch: mockFetch(200, {
      authorization_id: "auth_1", engine_version: `sha256:${"a".repeat(64)}`,
      results: { "web.search": { decision: "allow", reason: "authorization_granted_action_active", receipt: null, policy_eval: evaluation } },
    }) });
    await expect(client.check({ authorizationId: "auth_1", actions: ["web.search"] })).rejects.toBeInstanceOf(AllowlyProtocolError);
  });
  it("creates, gets, lists, archives and previews with setup credentials and canonical snake_case evidence", async () => {
    const retained = definition(), policy = response(retained), action = retained.actions[0].policy.action;
    const evaluation = decodeReceipt(vectors.signature_cases[1].receipt).policy_eval!;
    const fetch = vi.fn().mockResolvedValueOnce(fetchResponse(201, policy)).mockResolvedValueOnce(fetchResponse(200, policy))
      .mockResolvedValueOnce(fetchResponse(200, { items: [policy], has_more: false, next_cursor: null }))
      .mockResolvedValueOnce(fetchResponse(200, { provisional: true, definition_sha256: definitionDigest(retained), action, policy_eval: evaluation }))
      .mockResolvedValueOnce(fetchResponse(204, undefined));
    const identity = vi.fn(() => { throw new Error("setup never signs agent identity"); });
    const client = new Allowly({ apiKey: "setup-key", baseUrl: BASE, fetch, agentTokenSupplier: identity });
    expect((await client.policies.create({ policyId: "review", definition: retained, idempotencyKey: "create-1" })).definition).toEqual(retained);
    expect((await client.policies.get("review")).policyRef).toEqual(policy.policy_ref);
    expect((await client.policies.list({ limit: 2, cursor: "a/b?" })).items[0].definition).toEqual(retained);
    expect((await client.policies.preview({ definition: retained, action, context: { risk: 2 } })).policyEval).toEqual(evaluation);
    await client.policies.archive("review", { idempotencyKey: "archive-1" });
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ ...retained, policy_id: "review" });
    expect(JSON.parse(fetch.mock.calls[3][1].body)).toEqual({ definition: retained, action, context: { risk: 2 } });
    expect(fetch.mock.calls[2][0]).toBe(`${BASE}/v1/policies?limit=2&cursor=a%2Fb%3F`);
    expect(new Headers(fetch.mock.calls[4][1].headers).get("Idempotency-Key")).toBe("archive-1");
    for (const call of fetch.mock.calls) {
      expect(new Headers(call[1].headers).get("Authorization")).toBe("Bearer setup-key");
      expect(new Headers(call[1].headers).has("X-Allowly-Agent-Token")).toBe(false);
    }
    expect(identity).not.toHaveBeenCalled();
  });
  it("publishes one exact previous edition with a required idempotency key", async () => {
    const value = definition(), previous = response(value).policy_ref, published = { ...previous, policy_version: 2 };
    const fetch = mockFetch(201, { policy_ref: published, agent_id: value.agent_id, created_by: "member:owner", created_at: "2026-10-10T00:00:00Z", authorization_migrations: [], archived_policy_ids: [], revoked_confirmation_count: 0 });
    const client = new Allowly({ apiKey: "setup-key", baseUrl: BASE, fetch });
    expect((await client.policies.publish({ policyId: "review", definition: value, previousPolicyRef: previous, idempotencyKey: "publish-2" })).policyRef).toEqual(published);
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ ...value, policy_id: "review", previous_policy_ref: previous });
    expect(new Headers(fetch.mock.calls[0][1].headers).get("Idempotency-Key")).toBe("publish-2");
  });
  it("binds create to the sent snapshot even if the caller changes its object while awaiting transport", async () => {
    const value = definition(), original = structuredClone(value), policy = response(original);
    const fetch = vi.fn().mockImplementation(async () => {
      const changed = value.actions[0].policy;
      Object.assign(changed, { decision: changed.decision === "allow" ? "deny" : "allow", target: null });
      return fetchResponse(201, policy);
    });
    const client = new Allowly({ apiKey: "setup-key", baseUrl: BASE, fetch });
    expect((await client.policies.create({ policyId: "review", definition: value })).definition).toEqual(original);
    expect(value).not.toEqual(original);
  });
  it.each(["provisional", "action", "definition_sha256"])("rejects mismatched preview %s", async changed => {
    const value = definition(), action = value.actions[0].policy.action;
    const payload: Record<string, unknown> = { provisional: true, action, definition_sha256: definitionDigest(value), policy_eval: decodeReceipt(vectors.signature_cases[1].receipt).policy_eval! };
    payload[changed] = changed === "provisional" ? false : "other";
    const client = new Allowly({ apiKey: "setup-key", baseUrl: BASE, fetch: mockFetch(200, payload) });
    await expect(client.policies.preview({ definition: value, action, context: {} })).rejects.toBeInstanceOf(AllowlyProtocolError);
  });
  it("binds the Preview input commitment without recalculating OPA rules", async () => {
    const value = definition(), action = value.actions[0].policy.action;
    const client = new Allowly({ apiKey: "setup-key", baseUrl: BASE, fetch: mockFetch(200, {
      provisional: true, action, definition_sha256: definitionDigest(value), policy_eval: decodeReceipt(vectors.signature_cases[1].receipt).policy_eval!,
    }) });
    await expect(client.policies.preview({ definition: value, action, context: { risk: 1 } })).rejects.toThrow("input commitment");
  });
  it.each([[403, "setup_key_required"], [503, "policy_evaluator_unavailable"], [422, "policy_input_invalid"]] as const)("does not retry or use Check fallback for setup error %i", async (status, code) => {
    const value = definition(), action = value.actions[0].policy.action;
    const fetch = mockFetch(status, { error: { code, message: "not available" } });
    const client = new Allowly({ apiKey: "runtime-key", baseUrl: BASE, fetch, fallbackByAction: { [action]: "fail_open" } });
    await expect(client.policies.preview({ definition: value, action, context: {} })).rejects.toMatchObject({ constructor: AllowlyAPIError, code });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
