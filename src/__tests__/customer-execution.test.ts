import { EventEmitter } from "node:events";
import { createECDH, createHash, generateKeyPairSync, sign } from "node:crypto";
import { access, chmod, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  dnsLookup: vi.fn(),
  httpsRequest: vi.fn(),
  tlsConnect: vi.fn(),
}));

vi.mock("node:dns/promises", () => ({ lookup: mocks.dnsLookup }));
vi.mock("node:https", () => ({
  Agent: class {
    createConnection?: (...args: unknown[]) => unknown;
    destroy = vi.fn();
  },
  request: mocks.httpsRequest,
}));
vi.mock("node:tls", () => ({ connect: mocks.tlsConnect }));

import {
  Allowly,
  canonicalize,
  commitCustomerHttpRequest,
  completeCustomerExecutionEvidence,
  hashSealValue,
  loadKeysFromJson,
} from "../index.js";

const URL = "https://api.vendor.example/v1/candidates/42?notify=true";
const BODY = JSON.stringify({ stage: "offer" });
const HEADERS = {
  authorization: "Bearer local-secret",
  "content-type": "application/json",
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function pendingReceipt() {
  return {
    status: "pending",
    receipt_id: "rcp_customer",
    ready_at_estimate: null,
    url: "https://api.example.com/v1/receipts/rcp_customer",
  };
}

function preparedResponse(overrides: Record<string, unknown> = {}) {
  const commitment = commitCustomerHttpRequest(URL, {
    method: "PATCH",
    headers: HEADERS,
    body: BODY,
  });
  const approval = {
    profile: "allowly.execution.approval.v1",
    workspace_id: "ws_1",
    operation_id: "op_customer_1",
    authorization_id: "auth_1",
    agent_id: "agent_1",
    action: "greenhouse.candidates.update",
    executable: {
      enabled_executable_id: "exe_1",
      provider_id: "greenhouse",
      catalog_operation_id: "greenhouse.candidates.update",
      catalog_revision: "catalog-2026-09-27",
      definition_fingerprint: "sha256:" + "5".repeat(64),
      origin: commitment.origin,
    },
    request: {
      method: commitment.method,
      origin: commitment.origin,
      path: commitment.path,
      query: commitment.query,
      headers: commitment.headers.map((item) => ({
        name: item.name,
        value_sha256: item.valueSha256,
      })),
      body_sha256: commitment.bodySha256,
      body_size: commitment.bodySize,
      content_type: commitment.contentType,
      provider_idempotency: { kind: "none" },
    },
    policy_input_sha256: `sha256:${hashSealValue({
      resource: "candidate:42",
      context: { stage: "offer" },
      estimated_cost_micros: 10,
    })}`,
    policy_input_source: "customer_runtime_reported",
    policy_input_request_semantics_verification: "not_performed",
    evidence_mode: "receipt",
    issued_at: "2020-01-01T00:00:00Z",
    expires_at: "2099-01-01T00:05:00Z",
  };
  const approvalSha256 = `sha256:${hashSealValue(approval)}`;
  return {
    operation_id: "op_customer_1",
    status: "approved",
    decision: "allow",
    reason: "authorization_granted_action_active",
    destination_id: "exe_1",
    action: "greenhouse.candidates.update",
    request_fingerprint_profile: "allowly.execution.request.v1",
    request_fingerprint: "sha256:" + "1".repeat(64),
    request_descriptor: {
      operation_id: "op_customer_1",
      authorization_id: "auth_1",
      destination_id: "exe_1",
      action: "greenhouse.candidates.update",
      method: commitment.method,
      origin: commitment.origin,
      path: commitment.path,
      query: commitment.query,
      headers: commitment.headers.map((item) => ({
        name: item.name,
        value_sha256: item.valueSha256,
      })),
      body_sha256: commitment.bodySha256,
      body_size: commitment.bodySize,
      content_type: commitment.contentType,
    },
    decision_receipt: pendingReceipt(),
    effective_evidence_mode: "receipt",
    approval,
    approval_sha256: approvalSha256,
    approval_expires_at: "2099-01-01T00:05:00Z",
    decision_state: "allowed",
    target_state: "not_started",
    evidence_state: "pending",
    ...overrides,
  };
}

function dispatchResponse(prepared = preparedResponse()) {
  return {
    operation_id: prepared.operation_id,
    dispatch_state: "claimed",
    approval: prepared.approval,
    approval_sha256: prepared.approval_sha256,
    approval_expires_at: prepared.approval_expires_at,
    effective_evidence_mode: prepared.effective_evidence_mode,
  };
}

function finalResponse(prepared = preparedResponse(), target: "response_observed" | "unknown" = "response_observed") {
  return {
    ...prepared,
    status: target === "response_observed" ? "succeeded" : "unknown",
    target_state: target,
    evidence_state: "customer_reported",
    downstream: target === "response_observed"
      ? {
        source: "customer_runtime",
        http_status: 202,
        response_fingerprint: "sha256:" + "2".repeat(64),
        response_fingerprint_scope: "complete",
        result: {},
        business_completion: "not_verified",
      }
      : {
        source: "customer_runtime",
        http_status: null,
        response_fingerprint: null,
        response_fingerprint_scope: "unavailable",
        result: {},
        business_completion: "not_verified",
      },
  };
}

function witnessedPrepared(fingerprint: string) {
  const prepared = preparedResponse({
    effective_evidence_mode: "witnessed",
    witness_session: {
      session_id: "wit_1",
      witness_url: "wss://witness.example/sessions/wit_1",
      expires_at: "2026-09-27T12:05:00Z",
      trusted_notary_key_fingerprint_sha256: fingerprint,
      native_profile: "customer_held_tlsn_bundle_v1",
      admission_token_delivery: "separate_one_time_endpoint",
    },
  });
  (prepared.approval as Record<string, unknown>).evidence_mode = "witnessed";
  prepared.approval_sha256 = `sha256:${hashSealValue(prepared.approval)}`;
  return prepared;
}

function customerOptions(directory: string) {
  return {
    operationId: "op_customer_1",
    authorizationId: "auth_1",
    enabledExecutableId: "exe_1",
    catalogOperationId: "greenhouse.candidates.update",
    action: "greenhouse.candidates.update",
    method: "PATCH" as const,
    headers: HEADERS,
    body: BODY,
    policyInput: {
      resource: "candidate:42",
      context: { stage: "offer" },
      estimatedCostMicros: 10,
    },
    clientTimestamp: "2026-09-27T12:00:00Z",
    journalDirectory: directory,
    agentToken: "agent-jwt",
  };
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function fakeWitness(directory: string, options: { corruptResponse?: boolean; omitAttestationHash?: boolean } = {}) {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const publicKey = ecdh.getPublicKey(undefined, "compressed");
  const trustedKeyPath = join(directory, "trusted-key.json");
  await writeFile(trustedKeyPath, JSON.stringify({ alg: 2, data: [...publicKey] }), { mode: 0o600 });
  const binaryPath = join(directory, "fake-witness.cjs");
  await writeFile(binaryPath, `#!/usr/bin/env node
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const optionsCorruptResponse = ${options.corruptResponse === true};
let input = "";
process.stdin.on("data", chunk => { input += chunk; });
process.stdin.on("end", async () => {
  const parsed = JSON.parse(input);
  const args = process.argv.slice(2);
  const output = args[args.indexOf("--output") + 1];
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(output, "args.json"), JSON.stringify(args));
  fs.writeFileSync(path.join(output, "witness.ready.json"), JSON.stringify({approval_sha256: parsed.approval_sha256}));
  while (!fs.existsSync(path.join(output, "dispatch.approved.json"))) {
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  fs.writeFileSync(path.join(output, "dispatch.started.json"), JSON.stringify({approval_sha256: parsed.approval_sha256}));
  const responseBody = Buffer.from("ok", "utf8");
  const response = {status: 200, headers: {}, framing: "content-length", body: "ok", body_bytes: responseBody.length, body_sha256: optionsCorruptResponse ? "0000000000000000000000000000000000000000000000000000000000000000" : crypto.createHash("sha256").update(responseBody).digest("hex")};
  fs.writeFileSync(path.join(output, "response.json"), JSON.stringify(response));
  const presentation = Buffer.from("full-proof", "utf8");
  const attestation = Buffer.from(JSON.stringify({compact: true}), "utf8");
  fs.writeFileSync(path.join(output, "presentation.json"), presentation);
  fs.writeFileSync(path.join(output, "attestation.json"), attestation);
  process.stdout.write(JSON.stringify({
    verified: true,
    profile: "customer_held_tlsn_bundle_v1",
    request_binding_verification: "verified_from_full_presentation",
    approval_sha256: parsed.approval_sha256,
    artifact_sha256: crypto.createHash("sha256").update(presentation).digest("hex"),
    ...(${options.omitAttestationHash === true} ? {} : {
      attestation_sha256: crypto.createHash("sha256").update(attestation).digest("hex"),
    }),
    evidence_path: path.join(output, "presentation.json"),
    attestation_path: path.join(output, "attestation.json"),
    response
  }));
});
`, { mode: 0o700 });
  await chmod(binaryPath, 0o700);
  return {
    binaryPath,
    trustedKeyPath,
    fingerprint: `sha256:${createHash("sha256").update(publicKey).digest("hex")}`,
  };
}

async function fakeClosingStdinWitness(directory: string) {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const publicKey = ecdh.getPublicKey(undefined, "compressed");
  const trustedKeyPath = join(directory, "trusted-key.json");
  await writeFile(trustedKeyPath, JSON.stringify({ alg: 2, data: [...publicKey] }), { mode: 0o600 });
  const binaryPath = join(directory, "fake-closing-stdin.cjs");
  await writeFile(binaryPath, `#!/usr/bin/env node
const fs = require("node:fs");
fs.closeSync(0);
setTimeout(() => {}, 2000);
`, { mode: 0o700 });
  await chmod(binaryPath, 0o700);
  return {
    binaryPath,
    trustedKeyPath,
    fingerprint: `sha256:${createHash("sha256").update(publicKey).digest("hex")}`,
  };
}

function signedDecisionReceipt(
  approvalSha256: string,
  overrides: Record<string, unknown> = {},
) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const keyId = "test-key/v1";
  const payload = {
    schema_version: "4",
    receipt_id: "rcp_customer",
    workspace_id: "ws_1",
    issued_at: "2026-09-27T12:00:01.000Z",
    decision: "allow",
    reason: "authorization_granted_action_active",
    user_id: "user_1",
    agent_id: "agent_1",
    action: "greenhouse.candidates.update",
    resource: "candidate:42",
    context: {
      execution: {
        operation_id: "op_customer_1",
        approval_sha256: approvalSha256,
      },
    },
    authorization_id: "auth_1",
    engine_version: "2026-09-27.1",
    alg: "Ed25519",
    key_id: keyId,
    ...overrides,
  };
  const receipt = {
    ...payload,
    signature: Buffer.from(sign(null, canonicalize(payload), privateKey)).toString("base64url"),
  };
  const keys = loadKeysFromJson({
    workspace_id: "ws_1",
    keys: [{
      key_id: keyId,
      alg: "Ed25519",
      public_key: Buffer.from(publicDer).subarray(-32).toString("base64url"),
      active_from: "2026-01-01T00:00:00.000Z",
      active_until: null,
    }],
  });
  return { receipt, keys };
}

function fetchSequence(...steps: Array<Response | Error | (() => Promise<Response>)>) {
  return vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
    const step = steps.shift();
    if (step === undefined) throw new Error("unexpected Allowly request");
    if (step instanceof Error) throw step;
    return typeof step === "function" ? step() : step;
  });
}

function mockProviderResponse(status = 202, body = '{"id":"provider-1"}') {
  mocks.httpsRequest.mockImplementation((_options, callback) => {
    const request = new EventEmitter() as EventEmitter & {
      end: (body?: string, encoding?: string) => void;
      destroy: (error?: Error) => void;
    };
    request.destroy = (error) => {
      if (error) queueMicrotask(() => request.emit("error", error));
    };
    request.end = () => queueMicrotask(() => {
      const response = new EventEmitter() as EventEmitter & { statusCode: number };
      response.statusCode = status;
      callback(response);
      response.emit("data", Buffer.from(body));
      response.emit("end");
    });
    return request;
  });
}

describe("customer-local HTTP execution", () => {
  beforeEach(() => {
    mocks.dnsLookup.mockReset();
    mocks.httpsRequest.mockReset();
    mocks.tlsConnect.mockReset();
    mocks.dnsLookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
  });

  it("reads only customer-local execution results", async () => {
    const response = preparedResponse();
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch: fetchSequence(jsonResponse(200, response)),
    });
    await expect(client.getExecution("op_customer_1")).resolves.toMatchObject({
      operationId: "op_customer_1",
    });

  });

  it.each([undefined, null, "complete"])("rejects invalid downstream completion %s", async (value) => {
    const response = finalResponse();
    const downstream = response.downstream as Record<string, unknown>;
    downstream.business_completion = value;
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch: fetchSequence(jsonResponse(200, response)),
    });
    await expect(client.getExecution("op_customer_1")).rejects.toThrow(
      "customer downstream business_completion is invalid",
    );
  });

  it("commits exact lowercase header names and UTF-8 bytes", () => {
    const committed = commitCustomerHttpRequest(URL, {
      method: "PATCH",
      headers: { Authorization: "Bearer local-secret", "Content-Type": "application/json" },
      body: "π",
    });

    expect(committed.headers.map((item) => item.name)).toEqual([
      "authorization",
      "content-type",
    ]);
    expect(committed.bodySize).toBe(2);
    expect(committed.bodySha256).toBe(
      `sha256:${createHash("sha256").update(Buffer.from("π", "utf8")).digest("hex")}`,
    );
    expect(committed.headers[0]?.valueSha256).toBe(`sha256:${createHash("sha256")
      .update(Buffer.concat([
        Buffer.from("allowly.execution.header.v1\0authorization\0", "utf8"),
        Buffer.from("Bearer local-secret", "utf8"),
      ]))
      .digest("hex")}`);
  });

  it("never resolves DNS or contacts the provider after a non-allow decision", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-deny-"));
    const denied = preparedResponse({
      status: "denied",
      decision: "deny",
      decision_state: "not_allowed",
      approval: undefined,
      approval_sha256: undefined,
      approval_expires_at: undefined,
    });
    const fetch = fetchSequence(jsonResponse(200, denied));
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch,
    });

    const result = await client.executeHttp(URL, customerOptions(directory));

    expect(result.state).toBe("not_allowed");
    expect(mocks.dnsLookup).not.toHaveBeenCalled();
    expect(mocks.httpsRequest).not.toHaveBeenCalled();
  });

  it("rejects a mixed approved response before dispatch", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-mixed-"));
    const prepared = preparedResponse({ target_state: "response_observed" });
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch: fetchSequence(jsonResponse(201, prepared)),
    });

    await expect(client.executeHttp(URL, customerOptions(directory))).rejects.toThrow(
      "did not produce an approved execution",
    );
    expect(mocks.dnsLookup).not.toHaveBeenCalled();
    expect(mocks.httpsRequest).not.toHaveBeenCalled();
  });

  it("binds the hashed approval to the requested executable origin", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-scope-"));
    const prepared = preparedResponse();
    const approval = prepared.approval as Record<string, unknown>;
    (approval.executable as Record<string, unknown>).origin = "https://other.vendor.example";
    prepared.approval_sha256 = `sha256:${hashSealValue(approval)}`;
    prepared.approval_expires_at = approval.expires_at as string;
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch: fetchSequence(jsonResponse(201, prepared)),
    });

    await expect(client.executeHttp(URL, customerOptions(directory))).rejects.toThrow(
      "approval scope does not match",
    );
    expect(mocks.httpsRequest).not.toHaveBeenCalled();
  });

  it("rejects a dispatch claim whose approval bytes differ from preparation", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-claim-"));
    const prepared = preparedResponse();
    const claim = dispatchResponse(prepared);
    claim.approval = structuredClone(prepared.approval);
    claim.approval.action = "greenhouse.candidates.delete";
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch: fetchSequence(jsonResponse(201, prepared), jsonResponse(200, claim)),
    });

    await expect(client.executeHttp(URL, customerOptions(directory))).rejects.toThrow(
      "dispatch claim differs",
    );
    expect(mocks.httpsRequest).not.toHaveBeenCalled();
  });

  it("refuses private DNS results before claiming dispatch", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-private-dns-"));
    const prepared = preparedResponse();
    const fetch = fetchSequence(jsonResponse(201, prepared));
    mocks.dnsLookup.mockResolvedValue([{ address: "127.0.0.1", family: 4 }]);
    const client = new Allowly({ apiKey: "test-key", baseUrl: "https://api.example.com", fetch });

    await expect(client.executeHttp(URL, customerOptions(directory))).rejects.toThrow(
      "non-public address",
    );
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(mocks.httpsRequest).not.toHaveBeenCalled();
  });

  it("reports redirects as the observed response without following them", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-redirect-"));
    const prepared = preparedResponse();
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      jsonResponse(200, dispatchResponse(prepared)),
      jsonResponse(201, finalResponse(prepared)),
    );
    mockProviderResponse(302, "");
    const client = new Allowly({ apiKey: "test-key", baseUrl: "https://api.example.com", fetch });

    const result = await client.executeHttp(URL, customerOptions(directory));

    expect(result.state).toBe("response_observed");
    expect(result).toMatchObject({
      outcomePending: false,
      providerResponse: { status: 302, body: Buffer.from("") },
    });
    expect(mocks.httpsRequest).toHaveBeenCalledTimes(1);
    expect(JSON.parse(fetch.mock.calls[2]![1]!.body as string)).toMatchObject({
      target_state: "response_observed",
      http_status: 302,
    });
  });

  it("sends once, stores an immutable outcome, and reports customer evidence", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-ok-"));
    const prepared = preparedResponse();
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      jsonResponse(200, dispatchResponse(prepared)),
      jsonResponse(201, finalResponse(prepared)),
    );
    mockProviderResponse();
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch,
    });

    const result = await client.executeHttp(URL, customerOptions(directory));

    expect(result.state).toBe("response_observed");
    expect(mocks.httpsRequest).toHaveBeenCalledTimes(1);
    const prepareBody = JSON.parse(fetch.mock.calls[0]![1]!.body as string);
    expect(prepareBody).not.toHaveProperty("payload");
    expect(prepareBody.http_request.headers).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "authorization", value_sha256: expect.stringMatching(/^sha256:/) }),
    ]));
    expect(JSON.stringify(prepareBody)).not.toContain("local-secret");
    const outcomeBody = JSON.parse(fetch.mock.calls[2]![1]!.body as string);
    expect(outcomeBody).toMatchObject({
      target_state: "response_observed",
      http_status: 202,
      response_size: 19,
    });
    expect(result.state === "response_observed"
      && result.evidencePackage.decisionReceiptVerification).toBe("pending");
  });

  it("completes and verifies a pending decision receipt only after dispatch", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-receipt-"));
    const prepared = preparedResponse();
    const signed = signedDecisionReceipt(prepared.approval_sha256 as string);
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      jsonResponse(200, dispatchResponse(prepared)),
      jsonResponse(201, finalResponse(prepared)),
      jsonResponse(200, { status: "signed", receipt: signed.receipt }),
    );
    mockProviderResponse();
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch,
    });
    const result = await client.executeHttp(URL, customerOptions(directory));
    if (result.state !== "response_observed") throw new Error("expected observed response");
    expect(fetch).toHaveBeenCalledTimes(3);

    const complete = await completeCustomerExecutionEvidence(
      client,
      result.evidencePackage,
      signed.keys,
      { expectedWorkspaceId: "ws_1", now: new Date("2026-09-27T12:01:00Z") },
    );

    expect(complete.decisionReceipt.status).toBe("signed");
    expect(complete.decisionReceiptVerification).toBe("verified");
    expect(mocks.httpsRequest).toHaveBeenCalledTimes(1);
  });

  it("enforces receipt key pins and the signed approval link", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-receipt-pin-"));
    const prepared = preparedResponse();
    const signed = signedDecisionReceipt(prepared.approval_sha256 as string);
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      jsonResponse(200, dispatchResponse(prepared)),
      jsonResponse(201, finalResponse(prepared)),
    );
    mockProviderResponse();
    const client = new Allowly({ apiKey: "test-key", baseUrl: "https://api.example.com", fetch });
    const result = await client.executeHttp(URL, customerOptions(directory));
    if (result.state !== "response_observed") throw new Error("expected observed response");
    const signedPackage = {
      ...result.evidencePackage,
      decisionReceipt: { status: "signed" as const, receipt: signed.receipt },
    };

    await expect(completeCustomerExecutionEvidence(
      client,
      signedPackage,
      signed.keys,
      {
        expectedWorkspaceId: "ws_1",
        trustedKeyFingerprints: new Set([`sha256:${"0".repeat(64)}`]),
        now: new Date("2026-09-27T12:01:00Z"),
      },
    )).rejects.toThrow();

    const wrongLink = signedDecisionReceipt(prepared.approval_sha256 as string, {
      authorization_id: "auth_other",
    });
    await expect(completeCustomerExecutionEvidence(
      client,
      {
        ...result.evidencePackage,
        decisionReceipt: { status: "signed", receipt: wrongLink.receipt },
      },
      wrongLink.keys,
      { expectedWorkspaceId: "ws_1", now: new Date("2026-09-27T12:01:00Z") },
    )).rejects.toThrow("does not bind the execution approval");
    expect(mocks.httpsRequest).toHaveBeenCalledTimes(1);
  });

  it("does not send after an ambiguous dispatch reply and only reconciles on resume", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-ambiguous-"));
    const prepared = preparedResponse();
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      new Error("lost dispatch reply"),
      jsonResponse(200, prepared),
      jsonResponse(200, prepared),
    );
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch,
    });

    const first = await client.executeHttp(URL, customerOptions(directory));
    const resumed = await client.executeHttp(URL, customerOptions(directory));

    expect(first.state).toBe("unknown");
    expect(resumed.state).toBe("unknown");
    if (first.state !== "unknown") throw new Error("expected unknown result");
    expect(first.evidencePackage.outcome).toMatchObject({ targetState: "unknown" });
    expect(mocks.httpsRequest).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(4);
    expect(fetch.mock.calls.filter(([url]) => String(url).endsWith("/v1/execute"))).toHaveLength(1);
  });

  it("retries a lost prepare response with the exact saved request", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-prepare-retry-"));
    const prepared = preparedResponse();
    const fetch = fetchSequence(
      new Error("lost prepare reply"),
      jsonResponse(201, prepared),
      jsonResponse(200, dispatchResponse(prepared)),
      jsonResponse(201, finalResponse(prepared)),
    );
    mockProviderResponse();
    const client = new Allowly({ apiKey: "test-key", baseUrl: "https://api.example.com", fetch });
    const options = { ...customerOptions(directory), clientTimestamp: undefined };

    await expect(client.executeHttp(URL, options)).rejects.toThrow(
      "Allowly request failed",
    );
    await expect(client.executeHttp(URL, {
      ...options,
      body: JSON.stringify({ stage: "hired" }),
    })).rejects.toThrow("different customer HTTP inputs");
    expect(fetch).toHaveBeenCalledTimes(1);

    const result = await client.executeHttp(URL, options);
    const prepares = fetch.mock.calls.filter(([url]) => String(url).endsWith("/v1/execute"));
    expect(result.state).toBe("response_observed");
    expect(prepares).toHaveLength(2);
    expect(prepares[0]![1]!.body).toBe(prepares[1]![1]!.body);
    expect(prepares[0]![1]!.headers).toEqual(prepares[1]![1]!.headers);
    expect(mocks.httpsRequest).toHaveBeenCalledTimes(1);
  });

  it("retries only the stored outcome upload after a failure", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-outbox-"));
    const prepared = preparedResponse();
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      jsonResponse(200, dispatchResponse(prepared)),
      new Error("outcome upload unavailable"),
      jsonResponse(503, { detail: "outcome upload still unavailable" }),
      jsonResponse(201, finalResponse(prepared)),
    );
    mockProviderResponse();
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch,
    });

    const first = await client.executeHttp(URL, customerOptions(directory));
    expect(first).toMatchObject({
      state: "response_observed", outcomePending: true, response: null,
      providerResponse: { status: 202, body: Buffer.from('{"id":"provider-1"}') },
    });
    const journalPath = join(directory, `${createHash("sha256").update("op_customer_1").digest("hex")}.json`);
    const saved = await readFile(journalPath, "utf8");
    expect(JSON.parse(saved).phase).toBe("outcome_pending");
    expect(saved).not.toContain("provider-1");
    expect(saved).not.toContain("local-secret");
    expect(JSON.parse(fetch.mock.calls[2]![1]!.body as string)).not.toHaveProperty("providerResponse");
    expect(fetch.mock.calls[2]![1]!.body).not.toContain("provider-1");

    const pending = await client.resumeHttpExecution({
      operationId: "op_customer_1",
      journalDirectory: directory,
      agentToken: "agent-jwt",
    });
    expect(pending).toMatchObject({
      state: "response_observed", outcomePending: true, response: null, providerResponse: null,
    });
    expect(JSON.parse(await readFile(journalPath, "utf8")).phase).toBe("outcome_pending");

    const result = await client.executeHttp(URL, customerOptions(directory));
    expect(result).toMatchObject({
      state: "response_observed", outcomePending: false, response: { status: "succeeded" },
      providerResponse: null,
    });
    expect(JSON.parse(await readFile(journalPath, "utf8")).phase).toBe("complete");
    expect(await client.resumeHttpExecution({
      operationId: "op_customer_1", journalDirectory: directory,
    })).toEqual(result);

    expect(mocks.httpsRequest).toHaveBeenCalledTimes(1);
    const outcomeCalls = fetch.mock.calls.filter(([url]) => String(url).endsWith("/outcome"));
    expect(outcomeCalls).toHaveLength(3);
    expect(outcomeCalls[0]![1]!.body).toBe(outcomeCalls[1]![1]!.body);
    expect(outcomeCalls[0]![1]!.body).toBe(outcomeCalls[2]![1]!.body);
    expect(outcomeCalls[0]![1]!.headers).toMatchObject(
      outcomeCalls[1]![1]!.headers as Record<string, string>,
    );
  });

  it("keeps an unknown provider outcome unknown when reporting fails", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-unknown-outbox-"));
    const prepared = preparedResponse();
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      jsonResponse(200, dispatchResponse(prepared)),
      new Error("outcome upload unavailable"),
    );
    mocks.httpsRequest.mockImplementation(() => { throw new Error("connection lost"); });
    const client = new Allowly({ apiKey: "test-key", baseUrl: "https://api.example.com", fetch });

    expect(await client.executeHttp(URL, customerOptions(directory))).toMatchObject({
      state: "unknown", outcomePending: true, response: null, providerResponse: null,
      evidencePackage: { outcome: { targetState: "unknown" } },
    });
    expect(mocks.httpsRequest).toHaveBeenCalledTimes(1);
    expect(JSON.parse(fetch.mock.calls[2]![1]!.body as string)).toMatchObject({
      target_state: "unknown",
    });
  });

  it("refuses changed inputs for an existing stable operation ID", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-conflict-"));
    const prepared = preparedResponse();
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      new Error("lost dispatch reply"),
      jsonResponse(200, prepared),
    );
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch,
    });
    await client.executeHttp(URL, customerOptions(directory));

    await expect(client.executeHttp(URL, {
      ...customerOptions(directory),
      body: JSON.stringify({ stage: "hired" }),
    })).rejects.toThrow("different customer HTTP inputs");
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("fails before dispatch when policy upgrades to witnessed and no witness is configured", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-upgrade-"));
    const prepared = preparedResponse({ effective_evidence_mode: "witnessed" });
    (prepared.approval as Record<string, unknown>).evidence_mode = "witnessed";
    prepared.approval_sha256 = `sha256:${hashSealValue(prepared.approval)}`;
    const fetch = fetchSequence(jsonResponse(201, prepared));
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch,
    });

    await expect(client.executeHttp(URL, customerOptions(directory))).rejects.toThrow(
      "policy requires witnessed execution",
    );
    expect(mocks.dnsLookup).not.toHaveBeenCalled();
    expect(mocks.httpsRequest).not.toHaveBeenCalled();
  });

  it("resumes an authorized witnessed call after witness options are supplied", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-witness-retry-"));
    const native = await fakeWitness(directory);
    const prepared = witnessedPrepared(native.fingerprint);
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      jsonResponse(200, {
        session_id: "wit_1",
        workspace_id: "ws_1",
        approval_sha256: prepared.approval_sha256,
        witness_url: "wss://witness.example/sessions/wit_1",
        admission_token: "one-time-secret",
        expires_at: "2099-01-01T00:05:00Z",
        trusted_notary_key_fingerprint_sha256: native.fingerprint,
        native_profile: "customer_held_tlsn_bundle_v1",
      }),
      jsonResponse(200, dispatchResponse(prepared)),
      jsonResponse(201, {
        ...finalResponse(prepared),
        effective_evidence_mode: "witnessed",
        evidence_state: "customer_held_witness_bundle",
      }),
    );
    const client = new Allowly({ apiKey: "test-key", baseUrl: "https://api.example.com", fetch });
    const options = {
      ...customerOptions(join(directory, "journal")),
      evidenceMode: "witnessed" as const,
      witness: {
        nativeBinaryPath: native.binaryPath,
        trustedNotaryKeyPath: native.trustedKeyPath,
        evidenceDirectory: join(directory, "evidence"),
      },
    };

    await expect(client.executeHttp(URL, { ...options, witness: undefined })).rejects.toThrow(
      "provide witness options",
    );
    expect(fetch).toHaveBeenCalledTimes(1);

    const result = await client.executeHttp(URL, options);
    expect(result.state).toBe("response_observed");
    expect(fetch.mock.calls.filter(([url]) => String(url).endsWith("/v1/execute"))).toHaveLength(1);
    expect(fetch.mock.calls.filter(([url]) => String(url).endsWith("/dispatch"))).toHaveLength(1);
  });

  it("does not allow a requested witnessed execution to downgrade to receipt", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-downgrade-"));
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch: fetchSequence(jsonResponse(201, preparedResponse())),
    });

    await expect(client.executeHttp(URL, {
      ...customerOptions(directory),
      evidenceMode: "witnessed",
    })).rejects.toThrow("approval scope does not match");
    expect(mocks.httpsRequest).not.toHaveBeenCalled();
  });

  it("rechecks approval expiry after TLS and before releasing provider bytes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-expiry-"));
    const prepared = preparedResponse();
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      jsonResponse(200, dispatchResponse(prepared)),
      jsonResponse(201, finalResponse(prepared, "unknown")),
    );
    const now = vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-27T12:00:00Z"));
    let providerBytesReleased = false;
    mocks.httpsRequest.mockImplementation((requestOptions, _callback) => {
      const request = new EventEmitter() as EventEmitter & {
        end: () => void;
        destroy: (error?: Error) => void;
      };
      request.destroy = (error) => { if (error) request.emit("error", error); };
      request.end = () => {
        const socket = new EventEmitter() as EventEmitter & {
          setTimeout: (timeout: number, callback: () => void) => void;
          destroy: (error?: Error) => void;
        };
        socket.setTimeout = () => {};
        socket.destroy = (error) => { if (error) queueMicrotask(() => socket.emit("error", error)); };
        mocks.tlsConnect.mockReturnValue(socket);
        const agent = (requestOptions as { agent: { createConnection: Function } }).agent;
        agent.createConnection({}, (error: Error | null) => {
          if (error) request.emit("error", error);
          else providerBytesReleased = true;
        });
        now.mockReturnValue(Date.parse("2100-01-01T00:00:00Z"));
        socket.emit("secureConnect");
      };
      return request;
    });
    const client = new Allowly({ apiKey: "test-key", baseUrl: "https://api.example.com", fetch });
    try {
      const result = await client.executeHttp(URL, customerOptions(directory));
      expect(result.state).toBe("unknown");
      expect(providerBytesReleased).toBe(false);
      expect(JSON.parse(fetch.mock.calls[2]![1]!.body as string)).toMatchObject({
        target_state: "unknown",
      });
    } finally {
      now.mockRestore();
    }
  });

  it("allows only one concurrent owner of a stable operation journal", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-concurrent-"));
    let release!: (response: Response) => void;
    const held = new Promise<Response>((resolve) => { release = resolve; });
    const fetch = fetchSequence(() => held);
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch,
    });
    const first = client.executeHttp(URL, customerOptions(directory));
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));

    await expect(client.executeHttp(URL, customerOptions(directory))).rejects.toThrow(
      "already active",
    );
    const denied = preparedResponse({
      status: "denied",
      decision: "deny",
      decision_state: "not_allowed",
      approval: undefined,
      approval_sha256: undefined,
      approval_expires_at: undefined,
    });
    release(jsonResponse(200, denied));
    await first;
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("recovers a lock only when its local owner process is proven dead", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-stale-lock-"));
    const denied = preparedResponse({
      status: "denied",
      decision: "deny",
      decision_state: "not_allowed",
      approval: undefined,
      approval_sha256: undefined,
      approval_expires_at: undefined,
    });
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch: fetchSequence(jsonResponse(200, denied)),
    });
    await client.executeHttp(URL, customerOptions(directory));
    const name = createHash("sha256").update("op_customer_1", "utf8").digest("hex");
    const lockPath = join(directory, `${name}.json.lock`);
    await writeFile(lockPath, JSON.stringify({
      version: 1,
      pid: 2_147_483_647,
      hostname: hostname(),
      token: "abandoned-owner",
      created_at: "2026-09-27T12:00:00Z",
    }), { mode: 0o600 });

    const result = await client.resumeHttpExecution({
      operationId: "op_customer_1",
      journalDirectory: directory,
    });

    expect(result.state).toBe("not_allowed");
    expect(await fileExists(lockPath)).toBe(false);
  });

  it.each([false, true])("returns native response after dispatch with outcomePending=%s", async (outcomePending) => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-witness-"));
    const native = await fakeWitness(directory);
    const witnessConfigDir = join(directory, "witness", "ws_1");
    await mkdir(witnessConfigDir, { recursive: true });
    const witnessCa = join(witnessConfigDir, "witness-ca.pem");
    const caBytes = Buffer.from("-----BEGIN CERTIFICATE-----\nlocal-test-ca\n-----END CERTIFICATE-----\n");
    await writeFile(witnessCa, caBytes);
    await writeFile(join(witnessConfigDir, "config.json"), JSON.stringify({
      version: 1,
      workspaceId: "ws_1",
      nativeBinaryPath: native.binaryPath,
      trustedNotaryKeyPath: native.trustedKeyPath,
      fingerprintSha256: native.fingerprint.slice("sha256:".length),
      trustedWitnessCaPath: witnessCa,
      witnessCaFingerprintSha256: createHash("sha256").update(caBytes).digest("hex"),
    }));
    const evidenceDirectory = join(directory, "evidence");
    const prepared = witnessedPrepared(native.fingerprint);
    let call = 0;
    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      call += 1;
      if (call === 1) return jsonResponse(201, prepared);
      if (call === 2) {
        return jsonResponse(200, {
          session_id: "wit_1",
          workspace_id: "ws_1",
          approval_sha256: prepared.approval_sha256,
          witness_url: "wss://witness.example/sessions/wit_1",
          admission_token: "one-time-secret",
          expires_at: "2026-09-27T12:05:00Z",
          trusted_notary_key_fingerprint_sha256: native.fingerprint,
          native_profile: "customer_held_tlsn_bundle_v1",
        });
      }
      if (call === 3) {
        expect(String(input)).toMatch(/\/dispatch$/);
        expect(await fileExists(join(evidenceDirectory, "witness.ready.json"))).toBe(true);
        expect(await fileExists(join(evidenceDirectory, "dispatch.started.json"))).toBe(false);
        return jsonResponse(200, dispatchResponse(prepared));
      }
      if (call === 4) {
        const outcome = JSON.parse(init!.body as string);
        expect(outcome).toMatchObject({
          target_state: "response_observed",
          evidence_bundle_sha256: `sha256:${createHash("sha256")
            .update("full-proof", "utf8")
            .digest("hex")}`,
          notary_attestation: { compact: true },
        });
        if (outcomePending) return jsonResponse(503, { detail: "outcome upload unavailable" });
        return jsonResponse(201, {
          ...finalResponse(prepared),
          effective_evidence_mode: "witnessed",
          evidence_state: "customer_held_witness_bundle",
        });
      }
      throw new Error("unexpected API call");
    });
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch,
    });

    const previousConfigDir = process.env.ALLOWLY_CONFIG_DIR;
    process.env.ALLOWLY_CONFIG_DIR = directory;
    let result;
    try {
      result = await client.executeHttp(URL, {
        ...customerOptions(join(directory, "journal")),
        evidenceMode: "witnessed",
        witness: { evidenceDirectory },
      });
    } finally {
      if (previousConfigDir === undefined) delete process.env.ALLOWLY_CONFIG_DIR;
      else process.env.ALLOWLY_CONFIG_DIR = previousConfigDir;
    }

    expect(result.state).toBe("response_observed");
    expect(result).toMatchObject({
      outcomePending, providerResponse: { status: 200, body: Buffer.from("ok") },
    });
    if (outcomePending && result.state === "response_observed") expect(result.response).toBeNull();
    expect(await fileExists(join(evidenceDirectory, "dispatch.approved.json"))).toBe(true);
    expect(await fileExists(join(evidenceDirectory, "dispatch.started.json"))).toBe(true);
    expect(JSON.parse(await readFile(join(evidenceDirectory, "args.json"), "utf8")))
      .toContain("--witness-ca-cert");
    expect(JSON.parse(await readFile(join(evidenceDirectory, "args.json"), "utf8")))
      .toContain(witnessCa);
    expect(JSON.stringify(await readFile(join(evidenceDirectory, "attestation.json"), "utf8")))
      .not.toContain("one-time-secret");
  });

  it("handles a native process that closes stdin without an uncaught EPIPE", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-witness-stdin-"));
    const native = await fakeClosingStdinWitness(directory);
    const evidenceDirectory = join(directory, "evidence");
    const prepared = witnessedPrepared(native.fingerprint);
    const approval = prepared.approval as Record<string, unknown>;
    approval.padding = "x".repeat(512 * 1024);
    prepared.approval_sha256 = `sha256:${hashSealValue(approval)}`;
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      jsonResponse(200, {
        session_id: "wit_1",
        workspace_id: "ws_1",
        approval_sha256: prepared.approval_sha256,
        witness_url: "wss://witness.example/sessions/wit_1",
        admission_token: "one-time-secret",
        expires_at: "2099-01-01T00:05:00Z",
        trusted_notary_key_fingerprint_sha256: native.fingerprint,
        native_profile: "customer_held_tlsn_bundle_v1",
      }),
    );
    const client = new Allowly({ apiKey: "test-key", baseUrl: "https://api.example.com", fetch });

    await expect(client.executeHttp(URL, {
      ...customerOptions(join(directory, "journal")),
      evidenceMode: "witnessed",
      witness: {
        nativeBinaryPath: native.binaryPath,
        trustedNotaryKeyPath: native.trustedKeyPath,
        evidenceDirectory,
        workspaceId: "ws_1",
        timeoutMs: 1_000,
      },
    })).rejects.toThrow("native witness rejected its request input");

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(await fileExists(join(evidenceDirectory, "dispatch.approved.json"))).toBe(false);
  });

  it("kills a ready native process and never writes its gate after an ambiguous dispatch reply", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-witness-lost-"));
    const native = await fakeWitness(directory);
    const evidenceDirectory = join(directory, "evidence");
    const prepared = witnessedPrepared(native.fingerprint);
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      jsonResponse(200, {
        session_id: "wit_1",
        workspace_id: "ws_1",
        approval_sha256: prepared.approval_sha256,
        witness_url: "wss://witness.example/sessions/wit_1",
        admission_token: "one-time-secret",
        expires_at: "2026-09-27T12:05:00Z",
        trusted_notary_key_fingerprint_sha256: native.fingerprint,
        native_profile: "customer_held_tlsn_bundle_v1",
      }),
      new Error("dispatch reply lost"),
      jsonResponse(200, prepared),
    );
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch,
    });

    const result = await client.executeHttp(URL, {
      ...customerOptions(join(directory, "journal")),
      evidenceMode: "witnessed",
      witness: {
        nativeBinaryPath: native.binaryPath,
        trustedNotaryKeyPath: native.trustedKeyPath,
        evidenceDirectory,
        workspaceId: "ws_1",
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 25));

    expect(result.state).toBe("unknown");
    expect(await fileExists(join(evidenceDirectory, "witness.ready.json"))).toBe(true);
    expect(await fileExists(join(evidenceDirectory, "dispatch.approved.json"))).toBe(false);
    expect(await fileExists(join(evidenceDirectory, "dispatch.started.json"))).toBe(false);
  });

  it.each([
    ["response commitments are corrupt", { corruptResponse: true }],
    ["attestation hash is missing", { omitAttestationHash: true }],
  ])("reports unknown without attestation when native %s", async (_reason, fault) => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-witness-corrupt-"));
    const native = await fakeWitness(directory, fault);
    const evidenceDirectory = join(directory, "evidence");
    const prepared = witnessedPrepared(native.fingerprint);
    const fetch = fetchSequence(
      jsonResponse(201, prepared),
      jsonResponse(200, {
        session_id: "wit_1",
        workspace_id: "ws_1",
        approval_sha256: prepared.approval_sha256,
        witness_url: "wss://witness.example/sessions/wit_1",
        admission_token: "one-time-secret",
        expires_at: "2099-01-01T00:05:00Z",
        trusted_notary_key_fingerprint_sha256: native.fingerprint,
        native_profile: "customer_held_tlsn_bundle_v1",
      }),
      jsonResponse(200, dispatchResponse(prepared)),
      jsonResponse(201, {
        ...finalResponse(prepared, "unknown"),
        effective_evidence_mode: "witnessed",
        evidence_state: "evidence_gap",
      }),
    );
    const client = new Allowly({ apiKey: "test-key", baseUrl: "https://api.example.com", fetch });

    const result = await client.executeHttp(URL, {
      ...customerOptions(join(directory, "journal")),
      evidenceMode: "witnessed",
      witness: {
        nativeBinaryPath: native.binaryPath,
        trustedNotaryKeyPath: native.trustedKeyPath,
        evidenceDirectory,
        workspaceId: "ws_1",
      },
    });

    expect(result.state).toBe("unknown");
    const outcome = JSON.parse(fetch.mock.calls[3]![1]!.body as string);
    expect(outcome).toMatchObject({ target_state: "unknown" });
    expect(outcome).not.toHaveProperty("evidence_bundle_sha256");
    expect(outcome).not.toHaveProperty("notary_attestation");
  });

  it("stores no provider credentials or request body in its durable journal", async () => {
    const directory = await mkdtemp(join(tmpdir(), "allowly-customer-private-"));
    const denied = preparedResponse({
      status: "denied",
      decision: "deny",
      decision_state: "not_allowed",
      approval: undefined,
      approval_sha256: undefined,
      approval_expires_at: undefined,
    });
    const client = new Allowly({
      apiKey: "test-key",
      baseUrl: "https://api.example.com",
      fetch: fetchSequence(jsonResponse(200, denied)),
    });
    await client.executeHttp(URL, customerOptions(directory));
    const files = await import("node:fs/promises").then(({ readdir }) => readdir(directory));
    const journal = await readFile(join(directory, files.find((name) => name.endsWith(".json"))!), "utf8");
    expect(journal).not.toContain("local-secret");
    expect(journal).not.toContain(BODY);
  });
});
