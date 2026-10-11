/** Strict canonical policy JSON and setup transport. No policy interpreter. */
import { createHash } from "node:crypto";
import { canonicalize } from "@allowly/verifier";
import { AllowlyProtocolError } from "./error.js";
import type { Allowly } from "./client.js";
import type { PolicyDefinition, PolicyReference, PolicyEvalInfo, PolicyCreateRequest,
  PolicyResponse, PolicyListResponse, PolicyPreviewRequest, PolicyPreviewResponse,
  PolicyPublishResponse } from "./types.js";

export function document(value: unknown, name: string, limit = 65_536): Record<string, unknown> {
  record(value, name);
  try {
    const bytes = canonicalize(value as Record<string, unknown>);
    if (bytes.byteLength > limit) throw new Error("canonical document exceeds its byte limit");
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new AllowlyProtocolError(`${name} must be bounded canonical JSON with safe integers`);
  }
}
export function record(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new AllowlyProtocolError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}
export function exact(value: unknown, required: string[], name: string, optional: string[] = []): Record<string, unknown> {
  const raw = record(value, name);
  const allowed = new Set([...required, ...optional]);
  if (required.some(key => !Object.prototype.hasOwnProperty.call(raw, key)) || Object.keys(raw).some(key => !allowed.has(key))) {
    throw new AllowlyProtocolError(`${name} has missing or unknown fields`);
  }
  return raw;
}
export function text(value: unknown, name: string, maximum = 128): string {
  if (typeof value !== "string" || [...value].length < 1 || [...value].length > maximum) {
    throw new AllowlyProtocolError(`${name} must be a nonempty bounded string`);
  }
  return value;
}
export function integer(value: unknown, name: string, minimum = 1, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new AllowlyProtocolError(`${name} must be a bounded safe integer`);
  }
  return value;
}
export function strings(value: unknown, name: string, maximum: number, length = 128): string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > maximum) {
    throw new AllowlyProtocolError(`${name} must be a nonempty bounded string array`);
  }
  value.forEach(item => text(item, name, length));
  if (new Set(value).size !== value.length) throw new AllowlyProtocolError(`${name} must contain unique strings`);
  return value;
}
function target(decision: unknown, value: unknown): void {
  if (typeof decision !== "string" || !["allow", "deny", "confirm", "escalate"].includes(decision)) {
    throw new AllowlyProtocolError("policy decision is unsupported");
  }
  if (decision === "allow" || decision === "deny") {
    if (value !== null) throw new AllowlyProtocolError("allow and deny require a null target");
  } else if (decision === "confirm") {
    if (value !== "agent_owner") throw new AllowlyProtocolError("confirm target must be agent_owner");
  } else if (typeof value !== "string" || !value.startsWith("member:") || !value.slice(7).trim()
      || [...value.slice(7)].length > 128) {
    throw new AllowlyProtocolError("escalate target must be member:<account_user_id>");
  }
}
export function parsePolicyReference(value: unknown): PolicyReference {
  const raw = exact(document(value, "policy_ref"), ["policy_id", "policy_version", "definition_sha256"], "policy_ref");
  text(raw.policy_id, "policy_ref.policy_id");
  integer(raw.policy_version, "policy_ref.policy_version");
  if (typeof raw.definition_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(raw.definition_sha256)) {
    throw new AllowlyProtocolError("policy_ref.definition_sha256 must be lowercase hex SHA-256");
  }
  return raw as unknown as PolicyReference;
}
export function validatePolicyDefinition(value: unknown): PolicyDefinition {
  const raw = exact(document(value, "definition"), ["profile", "agent_id", "actions", "default_expiry_days"], "definition");
  if (raw.profile !== "allowly.policy.v1") throw new AllowlyProtocolError("definition profile is unsupported");
  text(raw.agent_id, "definition.agent_id");
  if (raw.default_expiry_days !== null) integer(raw.default_expiry_days, "default_expiry_days", 1, 3650);
  if (!Array.isArray(raw.actions) || raw.actions.length < 1 || raw.actions.length > 32) {
    throw new AllowlyProtocolError("definition.actions must contain 1 to 32 entries");
  }
  const names = new Set<string>(), operations = new Set<string>();
  for (const item of raw.actions) {
    const entry = exact(item, ["policy", "guards", "executable_operations"], "policy action");
    const policy = exact(entry.policy, ["profile", "action", "decision", "target", "fields", "rules"], "basic policy");
    const name = text(policy.action, "policy.action", 64);
    if (names.has(name) || ["allow", "deny", "confirm", "escalate"].includes(name)) {
      throw new AllowlyProtocolError("policy actions must be unique executable names");
    }
    names.add(name);
    if (policy.profile !== "allowly.basic.v1") throw new AllowlyProtocolError("basic policy profile is unsupported");
    target(policy.decision, policy.target);
    const fields = record(policy.fields, "policy.fields");
    if (Object.keys(fields).length > 64) throw new AllowlyProtocolError("policy.fields must be bounded");
    for (const [key, declared] of Object.entries(fields)) {
      text(key, "field");
      if (typeof declared !== "string" || !["string", "integer", "boolean", "null", "list"].includes(declared)) {
        throw new AllowlyProtocolError("policy field type is unsupported");
      }
    }
    if (!Array.isArray(policy.rules) || policy.rules.length > 32) throw new AllowlyProtocolError("policy.rules must contain at most 32 ordered rules");
    const ruleIds = new Set<string>();
    for (const item of policy.rules) {
      const rule = exact(item, ["id", "decision", "target", "conditions"], "rule");
      const id = text(rule.id, "rule.id");
      if (ruleIds.has(id)) throw new AllowlyProtocolError("rule IDs must be unique");
      ruleIds.add(id);
      target(rule.decision, rule.target);
      if (!Array.isArray(rule.conditions) || rule.conditions.length < 1 || rule.conditions.length > 10) {
        throw new AllowlyProtocolError("rule.conditions must contain 1 to 10 entries");
      }
      for (const item of rule.conditions) {
        const condition = exact(item, ["field", "op", "value"], "condition");
        const field = text(condition.field, "condition.field"), declared = fields[field];
        const op = condition.op, compared = condition.value;
        if (!Object.prototype.hasOwnProperty.call(fields, field) || typeof op !== "string" || !["eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "exists", "contains_any", "contains_none", "empty"].includes(op)) {
          throw new AllowlyProtocolError("condition requires a declared field and supported operator");
        }
        if (op === "exists") {
          if (typeof compared !== "boolean") throw new AllowlyProtocolError("exists requires a boolean value");
          continue;
        }
        if (op === "empty") {
          if (declared !== "list" || typeof compared !== "boolean") throw new AllowlyProtocolError("empty requires a list field and a boolean value");
          continue;
        }
        if (op === "contains_any" || op === "contains_none") {
          if (declared !== "list" || !Array.isArray(compared) || compared.length < 1 || compared.length > 64
              || compared.some(value => value !== null && !["string", "number", "boolean"].includes(typeof value))) {
            throw new AllowlyProtocolError("list overlap requires a list field and 1 to 64 scalar values");
          }
          continue;
        }
        if (declared === "list") throw new AllowlyProtocolError("list fields require list comparisons or exists");
        const membership = op === "in" || op === "not_in";
        if (membership !== Array.isArray(compared)) throw new AllowlyProtocolError("only membership comparisons use arrays");
        const values = membership ? compared as unknown[] : [compared];
        if (values.length > 64 || values.some(value => declared === "null" ? value !== null
            : declared === "integer" ? typeof value !== "number" || !Number.isSafeInteger(value)
            : typeof value !== declared)) {
          throw new AllowlyProtocolError("comparison values must match the declared field type");
        }
        if (["gt", "gte", "lt", "lte"].includes(op) && declared !== "integer") throw new AllowlyProtocolError("ordered comparisons require integer fields");
      }
    }
    const guards = exact(entry.guards, [], "guards", ["resource_pattern", "allowed_initiators", "max_per_day"]);
    if (Object.prototype.hasOwnProperty.call(guards, "resource_pattern")) text(guards.resource_pattern, "resource_pattern", 256);
    if (Object.prototype.hasOwnProperty.call(guards, "allowed_initiators")) strings(guards.allowed_initiators, "allowed_initiators", 128);
    if (Object.prototype.hasOwnProperty.call(guards, "max_per_day")) integer(guards.max_per_day, "max_per_day");
    if (!Array.isArray(entry.executable_operations) || entry.executable_operations.length > 100) {
      throw new AllowlyProtocolError("executable_operations must be a bounded array");
    }
    for (const item of entry.executable_operations) {
      const grant = exact(item, ["enabled_executable_id", "provider_id", "operation_id", "catalog_revision", "definition_fingerprint", "minimum_evidence_mode"], "executable grant");
      for (const key of ["enabled_executable_id", "provider_id", "operation_id", "catalog_revision"]) text(grant[key], key);
      if (typeof grant.definition_fingerprint !== "string" || !/^sha256:[0-9a-f]{64}$/.test(grant.definition_fingerprint)) throw new AllowlyProtocolError("executable definition_fingerprint is invalid");
      if (grant.minimum_evidence_mode !== "receipt" && grant.minimum_evidence_mode !== "witnessed") throw new AllowlyProtocolError("minimum_evidence_mode is unsupported");
      const identity = JSON.stringify([grant.enabled_executable_id, grant.operation_id]);
      if (operations.has(identity)) throw new AllowlyProtocolError("an executable operation may belong to only one action");
      operations.add(identity);
    }
  }
  function containsNul(value: unknown): boolean {
    if (typeof value === "string") return value.includes("\0");
    if (Array.isArray(value)) return value.some(containsNul);
    if (value !== null && typeof value === "object") return Object.entries(value).some(([key, value]) => containsNul(key) || containsNul(value));
    return false;
  }
  if (containsNul(raw)) throw new AllowlyProtocolError("definition cannot contain NUL characters");
  return raw as unknown as PolicyDefinition;
}
export function definitionDigest(definition: PolicyDefinition): string {
  return createHash("sha256").update(canonicalize(definition)).digest("hex");
}
export function parsePolicyEvaluation(value: unknown): PolicyEvalInfo {
  const raw = exact(document(value, "policy_eval", 32_768), ["input_sha256", "result"], "policy_eval");
  if (typeof raw.input_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(raw.input_sha256)) throw new AllowlyProtocolError("policy_eval.input_sha256 must be lowercase hex SHA-256");
  const result = exact(raw.result, ["profile", "status", "decision", "target", "matched_rule_id", "evaluated_fields"], "policy_eval.result");
  if (result.profile !== "allowly.basic.v1" || result.status !== "ok") throw new AllowlyProtocolError("policy_eval result profile or status is unsupported");
  target(result.decision, result.target);
  if (result.matched_rule_id !== null) text(result.matched_rule_id, "matched_rule_id");
  const fields = record(result.evaluated_fields, "evaluated_fields");
  Object.keys(fields).forEach(key => text(key, "evaluated field"));
  if (result.matched_rule_id === null && Object.keys(fields).length) throw new AllowlyProtocolError("action-level result must have empty evaluated_fields");
  return raw as unknown as PolicyEvalInfo;
}
function parsePolicy(value: unknown): PolicyResponse {
  const raw = exact(value, ["policy_ref", "definition"], "policy response", ["description", "created_by", "created_at", "deleted_at"]);
  const policyRef = parsePolicyReference(raw.policy_ref), definition = validatePolicyDefinition(raw.definition);
  if (policyRef.definition_sha256 !== definitionDigest(definition)) throw new AllowlyProtocolError("policy_ref definition digest does not match retained definition");
  function nullable(key: string): string | null {
    if (raw[key] === undefined || raw[key] === null) return null;
    if (typeof raw[key] !== "string") throw new AllowlyProtocolError(`${key} must be a string or null`);
    return raw[key];
  }
  return { policyRef, definition, description: nullable("description"), createdBy: nullable("created_by"), createdAt: nullable("created_at"), deletedAt: nullable("deleted_at") };
}
function body(req: PolicyCreateRequest): Record<string, unknown> {
  exact(req, ["policyId", "definition"], "policy request", ["description", "previousPolicyRef", "idempotencyKey"]);
  if (!/^[a-z0-9_-]+$/.test(text(req.policyId, "policyId"))) throw new Error("policyId must use lowercase letters, digits, underscore or hyphen");
  if (req.description !== undefined && (typeof req.description !== "string" || [...req.description].length > 2048)) throw new Error("description must be a bounded string");
  return { ...validatePolicyDefinition(req.definition), policy_id: req.policyId,
    ...(req.description !== undefined ? { description: req.description } : {}),
    ...(req.previousPolicyRef !== undefined ? { previous_policy_ref: parsePolicyReference(req.previousPolicyRef) } : {}) };
}
export class PoliciesResource {
  constructor(private readonly client: Allowly) {}
  async create(req: PolicyCreateRequest): Promise<PolicyResponse> {
    const data = body(req);
    const expectedId = data.policy_id;
    const expectedDigest = definitionDigest(validatePolicyDefinition({ profile: data.profile, agent_id: data.agent_id, actions: data.actions, default_expiry_days: data.default_expiry_days }));
    const response = parsePolicy(await this.client.request("POST", "/v1/policies", data, {
      headers: req.idempotencyKey !== undefined ? { "Idempotency-Key": req.idempotencyKey } : undefined, expectedStatus: 201,
    }));
    if (response.policyRef.policy_id !== expectedId || response.policyRef.definition_sha256 !== expectedDigest) throw new AllowlyProtocolError("created policy does not match the submitted definition");
    return response;
  }
  async get(policyId: string): Promise<PolicyResponse> {
    const response = parsePolicy(await this.client.request("GET", `/v1/policies/${encodeURIComponent(text(policyId, "policyId"))}`));
    if (response.policyRef.policy_id !== policyId) throw new AllowlyProtocolError("policy response does not match the requested logical ID");
    return response;
  }
  async list(opts: { limit?: number; cursor?: string } = {}): Promise<PolicyListResponse> {
    const query = new URLSearchParams({ limit: String(integer(opts.limit ?? 100, "limit", 1, 100)) });
    if (opts.cursor !== undefined) query.set("cursor", opts.cursor);
    const raw = exact(await this.client.request("GET", `/v1/policies?${query}`), ["items", "has_more"], "policy list", ["next_cursor"]);
    if (!Array.isArray(raw.items) || typeof raw.has_more !== "boolean" || (raw.next_cursor !== undefined && raw.next_cursor !== null && typeof raw.next_cursor !== "string")) throw new AllowlyProtocolError("policy list has invalid pagination fields");
    return { items: raw.items.map(parsePolicy), hasMore: raw.has_more, nextCursor: raw.next_cursor as string | null ?? null };
  }
  async archive(policyId: string, opts: { idempotencyKey?: string } = {}): Promise<void> {
    await this.client.request("DELETE", `/v1/policies/${encodeURIComponent(text(policyId, "policyId"))}`, undefined, {
      headers: opts.idempotencyKey !== undefined ? { "Idempotency-Key": opts.idempotencyKey } : undefined, expectedStatus: 204,
    });
  }
  async preview(req: PolicyPreviewRequest): Promise<PolicyPreviewResponse> {
    exact(req, ["definition", "action", "context"], "preview request");
    const definition = validatePolicyDefinition(req.definition);
    const action = text(req.action, "action", 64);
    const selected = definition.actions.find(entry => entry.policy.action === action)?.policy;
    if (selected === undefined) throw new Error("preview action must be declared in the complete definition");
    const context = document(req.context, "context", 4096);
    const inputSha256 = createHash("sha256").update(canonicalize({ policy: selected, action, context })).digest("hex");
    const raw = exact(await this.client.request("POST", "/v1/setup/policies/preview", { definition, action, context }), ["provisional", "definition_sha256", "action", "policy_eval"], "preview response");
    if (raw.provisional !== true || raw.action !== action || raw.definition_sha256 !== definitionDigest(definition)) throw new AllowlyProtocolError("preview response does not match the submitted provisional definition");
    const policyEval = parsePolicyEvaluation(raw.policy_eval);
    if (policyEval.input_sha256 !== inputSha256) throw new AllowlyProtocolError("preview input commitment does not match the submitted policy and context");
    return { provisional: true, definitionSha256: raw.definition_sha256 as string, action, policyEval };
  }
  async publish(req: PolicyCreateRequest & { idempotencyKey: string }): Promise<PolicyPublishResponse> {
    const data = body(req);
    const expectedId = data.policy_id;
    const expectedAgent = data.agent_id as string;
    const expectedDigest = definitionDigest(validatePolicyDefinition({ profile: data.profile, agent_id: data.agent_id, actions: data.actions, default_expiry_days: data.default_expiry_days }));
    text(req.idempotencyKey, "idempotencyKey");
    const raw = exact(await this.client.request("POST", "/v1/setup/policies/publish", data, { headers: { "Idempotency-Key": req.idempotencyKey }, expectedStatus: 201 }), ["policy_ref", "agent_id", "created_by", "created_at", "authorization_migrations", "archived_policy_ids", "revoked_confirmation_count"], "publish response");
    const policyRef = parsePolicyReference(raw.policy_ref);
    if (policyRef.policy_id !== expectedId || policyRef.definition_sha256 !== expectedDigest || raw.agent_id !== expectedAgent) throw new AllowlyProtocolError("published policy does not match the submitted definition");
    if (!Array.isArray(raw.authorization_migrations) || !Array.isArray(raw.archived_policy_ids)) throw new AllowlyProtocolError("publish summary lists are invalid");
    for (const migration of raw.authorization_migrations) {
      const item = exact(migration, ["user_id", "previous_authorization_id", "authorization_id"], "authorization migration");
      Object.entries(item).forEach(([key, value]) => text(value, key));
    }
    raw.archived_policy_ids.forEach(value => text(value, "archived_policy_id"));
    return { policyRef, agentId: expectedAgent, createdBy: text(raw.created_by, "created_by", 256), createdAt: text(raw.created_at, "created_at"), authorizationMigrations: raw.authorization_migrations as PolicyPublishResponse["authorizationMigrations"], archivedPolicyIds: raw.archived_policy_ids as string[], revokedConfirmationCount: integer(raw.revoked_confirmation_count, "revoked_confirmation_count", 0) };
  }
}
