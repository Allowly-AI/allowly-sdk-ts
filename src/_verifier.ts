/**
 * Allowly Receipt Verifier (TypeScript reference implementation).
 *
 * Verifies Allowly receipts per receipt-format.md v1.0.
 *
 * Dependencies: Node.js 20+ (uses built-in node:crypto and the WebCrypto API).
 * No external runtime dependencies.
 *
 * Usage:
 *   import { verifyReceipt, VerificationError, loadKeysFromJson } from "./verifier.js";
 *
 *   try {
 *     await verifyReceipt(receipt, publicKeys);
 *     console.log("valid");
 *   } catch (e) {
 *     if (e instanceof VerificationError) console.log(`invalid: ${e.message}`);
 *     else throw e;
 *   }
 *
 * Spec: https://github.com/allowly/receipt-format
 * License: Apache 2.0
 */

import { webcrypto } from "node:crypto";

const SPEC_VERSION = "1.0";
const ACTION_DECISIONS = new Set(["allow", "deny", "confirm", "escalate"]);
const EVENT_DECISIONS: Record<string, Set<string>> = {
  "authorization.create": new Set(["authorization_granted"]),
  "authorization.revoke": new Set(["authorization_revoked"]),
  "escalation.resolve": new Set(["escalation_approved", "escalation_rejected"]),
};
const AUTHORIZATION_LIFECYCLE_EVENTS = new Set(["authorization.create", "authorization.revoke"]);
const EVENT_ONLY_DECISIONS = new Set(Object.values(EVENT_DECISIONS).flatMap((decisions) => [...decisions]));
const REQUIRED_FIELDS = new Set([
  "version", "receipt_id", "workspace_id", "issued_at", "decision", "reason",
  "user_id", "agent_id", "resource", "context",
  "authorization_id", "policy_version", "signature",
]);
const OPTIONAL_FIELDS = new Set(["policy_eval"]);
const DISCRIMINATOR_FIELDS = new Set(["scope", "event"]);
const ALL_TOP_LEVEL_FIELDS = new Set([...REQUIRED_FIELDS, ...OPTIONAL_FIELDS, ...DISCRIMINATOR_FIELDS]);
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const B64URL_RE = /^[A-Za-z0-9_-]*$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

export class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationError";
  }
}

export interface PublicKey {
  keyId: string;
  alg: "Ed25519";
  publicKeyBytes: Uint8Array;  // 32 raw bytes
  activeFrom: Date;
  activeUntil: Date | null;
}

export interface Receipt {
  version: string;
  receipt_id: string;
  workspace_id: string;
  issued_at: string;
  decision: string;
  reason: string;
  user_id: string;
  agent_id: string;
  scope?: string;
  event?: string;
  resource: string | null;
  context: Record<string, unknown>;
  authorization_id: string | null;
  policy_version: string;
  policy_eval?: {
    matched_condition: {
      field: string;
      op: string;
      value: string | number | boolean | null | Array<string | number | boolean | null>;
    } | null;
    field_value: string | number | boolean | null;
  };
  signature: { alg: string; key_id: string; value: string };
}

// ---------------------------------------------------------------------------
// Base64url
// ---------------------------------------------------------------------------

function b64urlDecode(s: string): Uint8Array {
  if (!B64URL_RE.test(s)) {
    throw new VerificationError(`not unpadded base64url: ${JSON.stringify(s)}`);
  }
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const standard = padded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = Buffer.from(standard, "base64");
  return new Uint8Array(binary);
}

// ---------------------------------------------------------------------------
// Canonicalization (spec §4)
// ---------------------------------------------------------------------------

export function canonicalize(payload: unknown): Uint8Array {
  assertNoFloats(payload);
  const s = stringify(payload);
  return new TextEncoder().encode(s);
}

function assertNoFloats(obj: unknown): void {
  if (typeof obj === "number") {
    if (!Number.isInteger(obj)) {
      throw new VerificationError("v1 receipts must not contain non-integer numbers");
    }
    if (!Number.isSafeInteger(obj)) {
      throw new VerificationError(
        "integer exceeds the safe range ±(2^53-1); v1 receipts must not carry integers that lose precision in IEEE-754 doubles",
      );
    }
    return;
  }
  if (obj === null || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    obj.forEach(assertNoFloats);
  } else {
    Object.values(obj as Record<string, unknown>).forEach(assertNoFloats);
  }
}

function stringify(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    // Integers already validated by assertNoFloats.
    return String(v);
  }
  if (typeof v === "string") return encodeString(v);
  if (Array.isArray(v)) {
    return "[" + v.map(stringify).join(",") + "]";
  }
  if (typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>);
    // Lexicographic sort by UTF-16 code units (JS default).
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return (
      "{" +
      entries.map(([k, val]) => encodeString(k) + ":" + stringify(val)).join(",") +
      "}"
    );
  }
  throw new VerificationError(`unsupported type in payload: ${typeof v}`);
}

function encodeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (code < 0x20) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      // Non-ASCII passed through as UTF-8 per spec §4.2 rule 5.
      out += ch;
    }
  }
  out += '"';
  return out;
}

// ---------------------------------------------------------------------------
// Verification (spec §7)
// ---------------------------------------------------------------------------

export async function verifyReceipt(
  receipt: Record<string, unknown>,
  publicKeys: PublicKey[],
  opts: { now?: Date } = {},
): Promise<void> {
  const now = opts.now ?? new Date();

  // Step 1: version check
  if (receipt.version !== SPEC_VERSION) {
    throw new VerificationError(
      `unsupported version: ${JSON.stringify(receipt.version)} (want "${SPEC_VERSION}")`,
    );
  }

  // Step 2: schema check (includes signature.value shape — rejects placeholders)
  checkSchema(receipt);
  const r = receipt as unknown as Receipt;

  // Step 3: receipt kind and pairing
  const hasScope = "scope" in receipt;
  const hasEvent = "event" in receipt;

  if (hasScope && hasEvent) {
    throw new VerificationError(
      "receipt has both 'scope' and 'event'; exactly one must be present",
    );
  }
  if (!hasScope && !hasEvent) {
    throw new VerificationError(
      "receipt has neither 'scope' nor 'event'; exactly one must be present",
    );
  }

  if (hasEvent) {
    const event = receipt.event;
    if (typeof event !== "string") {
      throw new VerificationError("event must be a string");
    }
    if (!(event in EVENT_DECISIONS)) {
      throw new VerificationError(
        `event must be one of ["authorization.create","authorization.revoke","escalation.resolve"], got ${JSON.stringify(event)}`,
      );
    }
    const expectedDecisions = EVENT_DECISIONS[event];
    if (!expectedDecisions.has(r.decision)) {
      throw new VerificationError(
        `event receipt with event=${JSON.stringify(event)} must have ` +
          `decision in ${JSON.stringify([...expectedDecisions].sort())}, got ${JSON.stringify(r.decision)}`,
      );
    }
    if (r.authorization_id === null) {
      throw new VerificationError(
        `event receipt with event=${JSON.stringify(event)} must have non-null authorization_id`,
      );
    }
    if (AUTHORIZATION_LIFECYCLE_EVENTS.has(event) && r.resource !== null) {
      throw new VerificationError(
        `authorization lifecycle receipt with event=${JSON.stringify(event)} must have null resource`,
      );
    }
    if ("policy_eval" in receipt) {
      throw new VerificationError("policy_eval must be absent on event receipts");
    }
  } else {
    const scope = receipt.scope;
    if (typeof scope !== "string") {
      throw new VerificationError("scope must be a string");
    }
    if (EVENT_ONLY_DECISIONS.has(r.decision)) {
      throw new VerificationError(
        `decision=${JSON.stringify(r.decision)} requires an event receipt (event field), ` +
          `got a scope receipt with scope=${JSON.stringify(scope)}`,
      );
    }
    if (!ACTION_DECISIONS.has(r.decision)) {
      throw new VerificationError(
        `action receipt must have decision in ["allow","confirm","deny","escalate"], ` +
        `got ${JSON.stringify(r.decision)}`,
      );
    }
  }

  // Step 4: algorithm check
  if (r.signature.alg !== "Ed25519") {
    throw new VerificationError(`unsupported signature alg: ${JSON.stringify(r.signature.alg)}`);
  }

  // Step 5: timestamp sanity
  const issuedAt = parseRFC3339(r.issued_at);
  if (issuedAt.getTime() > now.getTime() + MAX_FUTURE_SKEW_MS) {
    throw new VerificationError(
      `receipt issued in the future: ${issuedAt.toISOString()} > ${now.toISOString()}`,
    );
  }

  // Step 6: canonicalize
  const { signature, ...payload } = r;
  const canonical = canonicalize(payload);

  // Step 7: signature verification
  const key = findKey(publicKeys, r.signature.key_id, issuedAt);
  const sigBytes = b64urlDecode(r.signature.value);  // length already validated in schema check

  const cryptoKey = await webcrypto.subtle.importKey(
    "raw",
    key.publicKeyBytes,
    { name: "Ed25519" },
    false,
    ["verify"],
  );

  const ok = await webcrypto.subtle.verify("Ed25519", cryptoKey, sigBytes, canonical);
  if (!ok) {
    throw new VerificationError("signature verification failed");
  }

  // Step 8: accept (implicit — no throw)
}

function checkSchema(receipt: Record<string, unknown>): void {
  const extra = Object.keys(receipt).filter((k) => !ALL_TOP_LEVEL_FIELDS.has(k));
  if (extra.length) {
    throw new VerificationError(`unknown top-level fields: ${JSON.stringify(extra.sort())}`);
  }
  const missing = [...REQUIRED_FIELDS].filter((k) => !(k in receipt));
  if (missing.length) {
    throw new VerificationError(`missing top-level fields: ${JSON.stringify(missing.sort())}`);
  }

  const stringFields = [
    "version", "receipt_id", "workspace_id", "issued_at", "decision", "reason",
    "user_id", "agent_id", "policy_version",
  ];
  for (const f of stringFields) {
    if (typeof receipt[f] !== "string") {
      throw new VerificationError(`${f} must be a string`);
    }
  }
  for (const f of ["resource", "authorization_id"]) {
    const v = receipt[f];
    if (v !== null && typeof v !== "string") {
      throw new VerificationError(`${f} must be string or null`);
    }
  }

  if (
    typeof receipt.context !== "object" ||
    receipt.context === null ||
    Array.isArray(receipt.context)
  ) {
    throw new VerificationError("context must be an object");
  }

  const sig = receipt.signature;
  if (typeof sig !== "object" || sig === null || Array.isArray(sig)) {
    throw new VerificationError("signature must be an object");
  }
  for (const f of ["alg", "key_id", "value"]) {
    const v = (sig as Record<string, unknown>)[f];
    if (typeof v !== "string") {
      throw new VerificationError(`signature.${f} must be a string`);
    }
  }

  // signature.value must decode from base64url to exactly 64 bytes.
  // This rejects placeholder strings ("pending", empty, anything malformed)
  // before the verification path even starts.
  const sigValue = (sig as Record<string, string>).value;
  let sigBytes: Uint8Array;
  try {
    sigBytes = b64urlDecode(sigValue);
  } catch {
    throw new VerificationError(`signature.value is not valid base64url: ${JSON.stringify(sigValue)}`);
  }
  if (sigBytes.length !== 64) {
    throw new VerificationError(
      `signature.value must decode to 64 bytes (Ed25519), got ${sigBytes.length}`,
    );
  }

  if ("policy_eval" in receipt) {
    checkPolicyEval(receipt.policy_eval);
  }
}

function isPolicyScalar(value: unknown): boolean {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isInteger(value))
  );
}

function isPolicyConditionValue(value: unknown): boolean {
  if (isPolicyScalar(value)) {
    return true;
  }
  return Array.isArray(value) && value.every((item) => isPolicyScalar(item));
}

function checkExactKeys(
  obj: Record<string, unknown>,
  expected: string[],
  prefix: string,
): void {
  const expectedSet = new Set(expected);
  const extra = Object.keys(obj).filter((key) => !expectedSet.has(key));
  const missing = expected.filter((key) => !(key in obj));
  if (extra.length) {
    throw new VerificationError(`${prefix} has unknown fields: ${JSON.stringify(extra.sort())}`);
  }
  if (missing.length) {
    throw new VerificationError(`${prefix} missing fields: ${JSON.stringify(missing.sort())}`);
  }
}

function checkPolicyEval(value: unknown): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new VerificationError("policy_eval must be an object");
  }
  const policyEval = value as Record<string, unknown>;
  checkExactKeys(policyEval, ["matched_condition", "field_value"], "policy_eval");

  const matched = policyEval.matched_condition;
  if (matched !== null) {
    if (typeof matched !== "object" || Array.isArray(matched)) {
      throw new VerificationError("policy_eval.matched_condition must be an object or null");
    }
    const condition = matched as Record<string, unknown>;
    checkExactKeys(condition, ["field", "op", "value"], "policy_eval.matched_condition");
    if (typeof condition.field !== "string") {
      throw new VerificationError("policy_eval.matched_condition.field must be a string");
    }
    if (typeof condition.op !== "string") {
      throw new VerificationError("policy_eval.matched_condition.op must be a string");
    }
    if (!isPolicyConditionValue(condition.value)) {
      throw new VerificationError(
        "policy_eval.matched_condition.value must be string, integer, boolean, null, or an array of those",
      );
    }
  }

  if (!isPolicyScalar(policyEval.field_value)) {
    throw new VerificationError("policy_eval.field_value must be string, integer, boolean, or null");
  }
}

function parseRFC3339(s: string): Date {
  if (typeof s !== "string" || !RFC3339_RE.test(s)) {
    throw new VerificationError(`not an RFC 3339 timestamp with timezone: ${JSON.stringify(s)}`);
  }
  const d = new Date(s);
  if (isNaN(d.getTime())) {
    throw new VerificationError(`invalid RFC 3339 timestamp: ${s}`);
  }
  return d;
}

function findKey(keys: PublicKey[], keyId: string, issuedAt: Date): PublicKey {
  for (const k of keys) {
    if (k.keyId !== keyId) continue;
    if (issuedAt < k.activeFrom) {
      throw new VerificationError(`key ${JSON.stringify(keyId)} not yet active at issued_at`);
    }
    if (k.activeUntil !== null && issuedAt >= k.activeUntil) {
      throw new VerificationError(`key ${JSON.stringify(keyId)} retired before issued_at`);
    }
    return k;
  }
  throw new VerificationError(`no public key found for key_id=${JSON.stringify(keyId)}`);
}

// ---------------------------------------------------------------------------
// Convenience loader
// ---------------------------------------------------------------------------

export interface KeyDocument {
  workspace_id: string;
  keys: Array<{
    key_id: string;
    alg: string;
    public_key: string;
    active_from: string;
    active_until: string | null;
  }>;
}

export function loadKeysFromJson(doc: KeyDocument): PublicKey[] {
  checkKeyDocument(doc as unknown as Record<string, unknown>);
  return doc.keys.map((k) => ({
    keyId: k.key_id,
    alg: "Ed25519" as const,
    publicKeyBytes: b64urlDecode(k.public_key),
    activeFrom: parseRFC3339(k.active_from),
    activeUntil: k.active_until ? parseRFC3339(k.active_until) : null,
  }));
}

function checkKeyDocument(doc: Record<string, unknown>): void {
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new VerificationError("key document must be an object");
  }
  if (typeof doc.workspace_id !== "string" || doc.workspace_id.length === 0) {
    throw new VerificationError("key document workspace_id must be a non-empty string");
  }
  if (!Array.isArray(doc.keys)) {
    throw new VerificationError("key document keys must be an array");
  }
  for (const [index, key] of doc.keys.entries()) {
    if (typeof key !== "object" || key === null || Array.isArray(key)) {
      throw new VerificationError(`keys[${index}] must be an object`);
    }
    const record = key as Record<string, unknown>;
    for (const field of ["key_id", "alg", "public_key", "active_from"]) {
      if (typeof record[field] !== "string" || (record[field] as string).length === 0) {
        throw new VerificationError(`keys[${index}].${field} must be a non-empty string`);
      }
    }
    if (record.alg !== "Ed25519") {
      throw new VerificationError(`keys[${index}].alg must be "Ed25519"`);
    }
    if (record.active_until !== null && typeof record.active_until !== "string") {
      throw new VerificationError(`keys[${index}].active_until must be string or null`);
    }
    const raw = b64urlDecode(record.public_key as string);
    if (raw.length !== 32) {
      throw new VerificationError(
        `keys[${index}].public_key must decode to 32 bytes, got ${raw.length}`,
      );
    }
    parseRFC3339(record.active_from as string);
    if (typeof record.active_until === "string") {
      parseRFC3339(record.active_until);
    }
  }
}
