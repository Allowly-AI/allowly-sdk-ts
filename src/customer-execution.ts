import { ECDH, createHash } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lookup as dnsLookup } from "node:dns/promises";
import {
  access,
  chmod,
  link,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { hostname } from "node:os";
import { dirname, join, resolve } from "node:path";
import { connect as tlsConnect } from "node:tls";
import type { PublicKey } from "@allowly/verifier";

import type { Allowly } from "./client.js";
import { AllowlyProtocolError } from "./error.js";
import type {
  CustomerExecutionEvidencePackage,
  CustomerExecutionOutcome,
  CustomerExecutionResponse,
  CustomerHeaderCommitment,
  CustomerHttpExecutionResult,
  CustomerHttpOptions,
  CustomerHttpProviderResponse,
  CustomerHttpRequestCommitment,
  PrepareExecutionRequest,
  ResumeHttpExecutionRequest,
} from "./types.js";
import { hashSealValue, verifyReceipt } from "./verify.js";
import { loadInstalledWitnessConfig } from "./witness-config.js";

const HEADER_PROFILE = "allowly.execution.header.v1";
const JOURNAL_VERSION = 1;
const MAX_REQUEST_BODY_BYTES = 256 * 1024;
const MAX_RECEIPT_RESPONSE_BYTES = 1024 * 1024;
const MAX_WITNESSED_REQUEST_BYTES = 2 * 1024;
const MAX_WITNESSED_RESPONSE_BYTES = 16 * 1024;
const MAX_NATIVE_STDOUT_BYTES = 64 * 1024;
const MAX_NATIVE_STDERR_BYTES = 16 * 1024;
const DEFAULT_WITNESS_TIMEOUT_MS = 150_000;
const DEFAULT_EXECUTION_TIMEOUT_MS = 30_000;
const FORBIDDEN_HEADERS = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "keep-alive",
  "te",
  "trailer",
  "upgrade",
  "proxy-authorization",
  "proxy-connection",
  "accept-encoding",
  "expect",
]);

interface LocalRequest {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  url: URL;
  headers: Record<string, string>;
  body: string;
  commitment: CustomerHttpRequestCommitment;
}

interface JournalOutcome {
  idempotency_key: string;
  body: CustomerExecutionOutcome;
}

interface ExecutionJournal {
  version: 1;
  operation_id: string;
  request_sha256: string;
  phase: "prepared" | "waiting_for_review" | "authorized" | "dispatch_attempted" | "outcome_pending" | "complete";
  prepare_client_timestamp?: string;
  prepare_idempotency_key?: string;
  continue_idempotency_key?: string;
  authorization?: CustomerExecutionResponse;
  dispatch_attempted_at?: string;
  outcome?: JournalOutcome;
  final_response?: CustomerExecutionResponse;
  evidence_package?: CustomerExecutionEvidencePackage;
}

interface NativeResult {
  response: {
    status: number;
    body: string;
    body_bytes: number;
    body_sha256: string;
  };
  artifact_sha256: string;
  evidence_path: string;
  attestation_path: string;
  attestation: Record<string, unknown>;
}

interface NativeChildState {
  stdout: Buffer[];
  stderr: Buffer[];
  closed: Promise<number | null>;
  spawnError: Error | null;
  stdinError: Error | null;
  outputError: Error | null;
  stdoutBytes: number;
  stderrBytes: number;
}

interface JournalLockOwner {
  version: 1;
  pid: number;
  hostname: string;
  token: string;
  created_at: string;
}

const nativeChildStates = new WeakMap<ChildProcessWithoutNullStreams, NativeChildState>();

export async function executeHttp(
  client: Allowly,
  url: string | URL,
  options: CustomerHttpOptions,
): Promise<CustomerHttpExecutionResult> {
  return executeCustomerHttp(client, url, options, false);
}

/** Continue a reviewed operation using the exact original, customer-held request. */
export async function continueHttpExecution(
  client: Allowly,
  url: string | URL,
  options: CustomerHttpOptions,
): Promise<CustomerHttpExecutionResult> {
  return executeCustomerHttp(client, url, options, true);
}

async function executeCustomerHttp(
  client: Allowly,
  url: string | URL,
  options: CustomerHttpOptions,
  continueReview: boolean,
): Promise<CustomerHttpExecutionResult> {
  const request = commitHttpRequest(url, options);
  const requestSha256 = journalRequestSha256(request, options);
  const journalPath = operationJournalPath(options.journalDirectory, options.operationId);
  return withJournalLock(journalPath, async () => {
    const existing = await readJournal(journalPath);
    let journal: ExecutionJournal;
    let authorization: CustomerExecutionResponse;
    if (existing !== null) {
      assertJournalIdentity(existing, options.operationId, requestSha256);
      if (continueReview && existing.phase !== "waiting_for_review"
          && typeof existing.continue_idempotency_key !== "string") {
        throw new Error("operation is not waiting for review and has no continuation intent");
      }
      if (existing.phase !== "prepared" && existing.phase !== "authorized"
          && !(continueReview && existing.phase === "waiting_for_review")) {
        return resumeJournal(client, journalPath, existing, options.agentToken);
      }
      journal = existing;
    } else {
      if (continueReview) throw new Error("no durable journal exists for this operation ID");
      journal = {
        version: JOURNAL_VERSION,
        operation_id: options.operationId,
        request_sha256: requestSha256,
        phase: "prepared",
        prepare_client_timestamp: prepareClientTimestamp(options.clientTimestamp),
        prepare_idempotency_key: options.idempotencyKey ?? stableId("prepare", options.operationId),
      };
      await writeJournal(journalPath, journal);
    }

    if (journal.phase === "prepared" || journal.phase === "waiting_for_review") {
      if (typeof journal.prepare_client_timestamp !== "string"
          || typeof journal.prepare_idempotency_key !== "string") {
        throw new Error("prepared journal lacks retry inputs; reconcile with the low-level API");
      }
      const executionRequest = originalPrepareRequest(request, options, journal);
      if (journal.phase === "waiting_for_review") {
        const waiting = requireAuthorization(journal);
        validateWaitingResponse(waiting, request, options);
        const review = waiting.review!;
        journal = {
          ...journal,
          continue_idempotency_key: stableId(
            "continue", stableJson([options.operationId, review.id, review.sourceReceiptId]),
          ),
        };
        await writeJournal(journalPath, journal);
        authorization = await client.continueExecution({
          executionRequest,
          reviewId: review.id,
          sourceReceiptId: review.sourceReceiptId,
          idempotencyKey: journal.continue_idempotency_key!,
          agentToken: options.agentToken,
        });
      } else {
        authorization = await client.prepareExecution({
          ...executionRequest,
          idempotencyKey: journal.prepare_idempotency_key,
          agentToken: options.agentToken,
        });
      }
      if (authorization.status === "waiting_for_review") {
        validateWaitingResponse(authorization, request, options);
        const previousReview = journal.authorization?.review;
        const currentReview = authorization.review!;
        const changedReview = previousReview !== undefined && previousReview !== null
          && (previousReview.id !== currentReview.id
            || previousReview.sourceReceiptId !== currentReview.sourceReceiptId);
        journal = {
          ...journal, phase: "waiting_for_review",
          authorization: { ...authorization, confirmNonce: null },
          ...(changedReview ? { continue_idempotency_key: undefined } : {}),
        };
        await writeJournal(journalPath, journal);
        return waitingResult(authorization);
      }
      if (authorization.decision !== "allow") {
        journal = { ...journal, phase: "complete", authorization, final_response: authorization };
        await writeJournal(journalPath, journal);
        return { state: "not_allowed", authorization };
      }
      validateApprovedResponse(authorization, request, options);
      journal = {
        ...journal,
        phase: "authorized",
        authorization,
        evidence_package: evidencePackageFor(authorization, null, null),
      };
      await writeJournal(journalPath, journal);
    } else {
      authorization = requireAuthorization(journal);
      validateApprovedResponse(authorization, request, options);
    }

    if (authorization.effectiveEvidenceMode === "witnessed") {
      if (options.witness === undefined) {
        throw new Error(
          "policy requires witnessed execution; provide witness options before dispatch",
        );
      }
      validateWitnessRequestSize(request);
      return executeWitnessed(client, journalPath, journal, request, options);
    }

    const pinned = await resolvePublicAddress(request.url.hostname);
    journal = await markDispatchAttempt(
      journalPath,
      journal,
      options.outcomeIdempotencyKey ?? stableId("outcome", options.operationId),
      requireApprovalHash(authorization),
    );
    let claim;
    try {
      claim = await client.claimExecutionDispatch({
        operationId: options.operationId,
        approvalSha256: requireApprovalHash(authorization),
        agentToken: options.agentToken,
      });
    } catch {
      return reconcileAfterAmbiguousDispatch(client, journalPath, journal, options.agentToken);
    }
    validateDispatchClaim(claim, authorization);
    if (claim.effectiveEvidenceMode !== "receipt") {
      throw new AllowlyProtocolError("dispatch evidence mode changed after preparation");
    }
    journal = await markDispatchClaimed(journalPath, journal);

    const startedAt = dispatchStartedAt(journal);
    let outcome: CustomerExecutionOutcome;
    let providerResponse: CustomerHttpProviderResponse | null = null;
    try {
      providerResponse = await sendPinnedHttps(
        request,
        pinned.address,
        pinned.family,
        authorization.approval!,
        executionTimeout(options),
      );
      outcome = {
        approvalSha256: claim.approvalSha256,
        targetState: "response_observed",
        dispatchStartedAt: startedAt,
        completedAt: new Date(),
        httpStatus: providerResponse.status,
        responseSha256: digest(providerResponse.body),
        responseSize: providerResponse.body.byteLength,
      };
    } catch {
      outcome = {
        approvalSha256: claim.approvalSha256,
        targetState: "unknown",
        dispatchStartedAt: startedAt,
        completedAt: new Date(),
      };
    }
    journal = await storeOutcome(
      journalPath,
      journal,
      options.outcomeIdempotencyKey ?? stableId("outcome", options.operationId),
      outcome,
    );
    return uploadStoredOutcome(client, journalPath, journal, options.agentToken, providerResponse);
  });
}

export async function resumeHttpExecution(
  client: Allowly,
  req: ResumeHttpExecutionRequest,
): Promise<CustomerHttpExecutionResult> {
  const journalPath = operationJournalPath(req.journalDirectory, req.operationId);
  return withJournalLock(journalPath, async () => {
    const journal = await readJournal(journalPath);
    if (journal === null) {
      throw new Error("no durable journal exists for this operation ID");
    }
    if (journal.operation_id !== req.operationId) {
      throw new Error("journal operation ID does not match the requested operation");
    }
    return resumeJournal(client, journalPath, journal, req.agentToken);
  });
}

/**
 * Complete the asynchronous receipt portion of an evidence package. This never
 * contacts the provider and cannot repeat the business request.
 */
export async function completeCustomerExecutionEvidence(
  client: Allowly,
  evidencePackage: CustomerExecutionEvidencePackage,
  publicKeys: PublicKey[],
  opts: {
    expectedWorkspaceId: string;
    trustedKeyFingerprints?: ReadonlySet<string>;
    pollInterval?: number;
    timeout?: number;
    now?: Date;
  },
): Promise<CustomerExecutionEvidencePackage> {
  let receipt: Record<string, unknown>;
  if (evidencePackage.decisionReceipt.status === "pending") {
    receipt = await client.receipts.fetchSigned(evidencePackage.decisionReceipt.receiptId, {
      pollInterval: opts.pollInterval,
      timeout: opts.timeout,
    });
  } else {
    receipt = evidencePackage.decisionReceipt.receipt;
  }
  await verifyReceipt(receipt, publicKeys, {
    expectedWorkspaceId: opts.expectedWorkspaceId,
    trustedKeyFingerprints: opts.trustedKeyFingerprints,
    now: opts.now,
  });
  validateReceiptApprovalLink(receipt, evidencePackage);
  return {
    ...structuredClone(evidencePackage),
    decisionReceipt: { status: "signed", receipt },
    decisionReceiptVerification: "verified",
  };
}

export function commitCustomerHttpRequest(
  url: string | URL,
  init: Pick<CustomerHttpOptions, "method" | "headers" | "body"> = {},
): CustomerHttpRequestCommitment {
  return commitHttpRequest(url, init).commitment;
}

function commitHttpRequest(
  url: string | URL,
  init: Pick<CustomerHttpOptions, "method" | "headers" | "body">,
): LocalRequest {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.port !== "" || parsed.username || parsed.password) {
    throw new Error("customer execution URL must be an HTTPS DNS origin on port 443");
  }
  if (parsed.hash !== "" || isIP(parsed.hostname) !== 0 || !validDnsName(parsed.hostname)) {
    throw new Error("customer execution URL must use a normalized DNS name without a fragment");
  }
  const method = init.method ?? (init.body === undefined ? "GET" : "POST");
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    throw new Error("unsupported customer execution HTTP method");
  }
  const body = init.body ?? "";
  const bodyBytes = Buffer.from(body, "utf8");
  if (bodyBytes.byteLength > MAX_REQUEST_BODY_BYTES) {
    throw new Error("customer execution body exceeds 256 KiB");
  }
  const headers: Record<string, string> = {};
  for (const [rawName, value] of Object.entries(init.headers ?? {})) {
    const name = rawName.toLowerCase();
    if (!/^[a-z0-9-]+$/.test(name) || FORBIDDEN_HEADERS.has(name)) {
      throw new Error(`unsafe or derived customer execution header: ${rawName}`);
    }
    if (Object.prototype.hasOwnProperty.call(headers, name)) {
      throw new Error(`duplicate customer execution header: ${name}`);
    }
    if (!/^[\x20-\x7e]*$/.test(value)) {
      throw new Error(`customer execution header ${name} must use visible ASCII`);
    }
    headers[name] = value;
  }
  const contentType = headers["content-type"] ?? null;
  if (bodyBytes.byteLength > 0 && contentType === null) {
    throw new Error("a non-empty customer execution body requires a content-type header");
  }
  const path = parsed.pathname;
  const query = parsed.search.slice(1);
  if (!path.startsWith("/") || path.startsWith("//") || !encodedAscii(path + query)) {
    throw new Error("customer execution path and query must be encoded ASCII without fragments");
  }
  const commitments: CustomerHeaderCommitment[] = Object.keys(headers)
    .sort()
    .map((name) => ({ name, valueSha256: headerDigest(name, headers[name]!) }));
  return {
    method,
    url: parsed,
    headers,
    body,
    commitment: {
      method,
      origin: parsed.origin,
      path,
      query,
      headers: commitments,
      bodySha256: digest(bodyBytes),
      bodySize: bodyBytes.byteLength,
      contentType,
    },
  };
}

async function executeWitnessed(
  client: Allowly,
  journalPath: string,
  initialJournal: ExecutionJournal,
  request: LocalRequest,
  options: CustomerHttpOptions,
): Promise<CustomerHttpExecutionResult> {
  const authorization = requireAuthorization(initialJournal);
  const witness = options.witness!;
  const approvalSha256 = requireApprovalHash(authorization);
  const session = authorization.witnessSession;
  if (session === null) {
    throw new AllowlyProtocolError("witnessed approval did not include a witness session");
  }
  const workspaceId = stringField(authorization.approval, "workspace_id");
  if (witness.workspaceId !== undefined && witness.workspaceId !== workspaceId) {
    throw new Error("witness workspace ID does not match the approval");
  }
  const usesInstalledWitness = witness.nativeBinaryPath === undefined
    && witness.trustedNotaryKeyPath === undefined;
  if (!usesInstalledWitness
      && (witness.nativeBinaryPath === undefined || witness.trustedNotaryKeyPath === undefined)) {
    throw new Error("provide both witness paths or neither to use `allowly setup witness`");
  }
  const installed = usesInstalledWitness ? await loadInstalledWitnessConfig(workspaceId) : null;
  if (installed !== null
      && normalizeDigest(installed.fingerprintSha256)
        !== normalizeDigest(session.trustedNotaryKeyFingerprintSha256)) {
    throw new Error("installed witness fingerprint does not match the witness session");
  }
  const trustedNotaryKeyPath = witness.trustedNotaryKeyPath ?? installed!.trustedNotaryKeyPath;
  const nativeBinaryPath = witness.nativeBinaryPath ?? installed!.nativeBinaryPath;
  await assertTrustedNotaryKey(
    trustedNotaryKeyPath,
    session.trustedNotaryKeyFingerprintSha256,
  );
  await ensureNewDirectory(witness.evidenceDirectory);
  const token = await client.getExecutionWitnessToken({
    operationId: options.operationId,
    approvalSha256,
    agentToken: options.agentToken,
  });
  if (token.sessionId !== session.sessionId
      || token.witnessUrl !== session.witnessUrl
      || token.workspaceId !== workspaceId
      || normalizeDigest(token.trustedNotaryKeyFingerprintSha256)
        !== normalizeDigest(session.trustedNotaryKeyFingerprintSha256)) {
    throw new AllowlyProtocolError("witness token does not match the prepared session");
  }
  const child = startNativeWitness(
    nativeBinaryPath,
    trustedNotaryKeyPath,
    witness.evidenceDirectory,
    installed?.trustedWitnessCaPath,
    {
      approval_sha256: approvalSha256,
      approval: authorization.approval,
      request: { headers: request.headers, body: request.body },
      require_dispatch_ack: true,
      witness: {
        url: token.witnessUrl,
        session_id: token.sessionId,
        workspace_id: token.workspaceId,
        admission_token: token.admissionToken,
      },
    },
  );
  try {
    const timeoutMs = witnessTimeout(options);
    try {
      await waitForWitnessReady(child, witness.evidenceDirectory, approvalSha256, timeoutMs);
    } catch (error) {
      await stopNativeWitness(child);
      throw error;
    }

    let journal = await markDispatchAttempt(
      journalPath,
      initialJournal,
      options.outcomeIdempotencyKey ?? stableId("outcome", options.operationId),
      approvalSha256,
    );
    let claim;
    try {
      claim = await client.claimExecutionDispatch({
        operationId: options.operationId,
        approvalSha256,
        agentToken: options.agentToken,
      });
    } catch {
      await stopNativeWitness(child);
      return reconcileAfterAmbiguousDispatch(client, journalPath, journal, options.agentToken);
    }
    try {
      validateDispatchClaim(claim, authorization);
      if (claim.effectiveEvidenceMode !== "witnessed") {
        throw new AllowlyProtocolError("dispatch evidence mode changed after preparation");
      }
      journal = await markDispatchClaimed(journalPath, journal);
      assertApprovalLive(authorization.approval!);
    } catch (error) {
      await stopNativeWitness(child);
      throw error;
    }

    const startedAt = dispatchStartedAt(journal);
    await atomicWriteJson(join(witness.evidenceDirectory, "dispatch.approved.json"), {
      approval_sha256: approvalSha256,
    });
    const native = await finishNativeWitness(
      child,
      timeoutMs,
      approvalSha256,
      witness.evidenceDirectory,
    ).catch(() => null);
    let outcome: CustomerExecutionOutcome;
    let witnessPackage: CustomerExecutionEvidencePackage["witness"] = null;
    if (native !== null) {
      outcome = {
        approvalSha256,
        targetState: "response_observed",
        dispatchStartedAt: startedAt,
        completedAt: new Date(),
        httpStatus: native.response.status,
        responseSha256: normalizeDigest(native.response.body_sha256),
        responseSize: native.response.body_bytes,
        evidenceBundleSha256: normalizeDigest(native.artifact_sha256),
        notaryAttestation: native.attestation,
      };
      witnessPackage = {
        profile: "customer_held_tlsn_bundle_v1",
        evidencePath: native.evidence_path,
        attestationPath: native.attestation_path,
        trustedNotaryKeyPath,
      };
    } else {
      outcome = {
        approvalSha256,
        targetState: "unknown",
        dispatchStartedAt: startedAt,
        completedAt: new Date(),
      };
    }
    const currentPackage = journal.evidence_package!;
    journal = {
      ...journal,
      evidence_package: { ...currentPackage, outcome, witness: witnessPackage },
    };
    journal = await storeOutcome(
      journalPath,
      journal,
      options.outcomeIdempotencyKey ?? stableId("outcome", options.operationId),
      outcome,
    );
    const providerResponse = native === null ? null : {
      status: native.response.status,
      body: Buffer.from(native.response.body, "utf8"),
    };
    return uploadStoredOutcome(client, journalPath, journal, options.agentToken, providerResponse);
  } finally {
    await stopNativeWitness(child);
  }
}

async function resumeJournal(
  client: Allowly,
  journalPath: string,
  journal: ExecutionJournal,
  agentToken?: string,
): Promise<CustomerHttpExecutionResult> {
  const authorization = requireAuthorization(journal);
  if (journal.phase === "waiting_for_review") return waitingResult(authorization);
  if (authorization.decision !== "allow") {
    return { state: "not_allowed", authorization };
  }
  if (journal.outcome !== undefined && journal.phase === "outcome_pending") {
    return uploadStoredOutcome(client, journalPath, journal, agentToken);
  }
  if (journal.phase === "complete" && journal.final_response !== undefined) {
    return resultFromFinal(journal);
  }
  return reconcileAfterAmbiguousDispatch(client, journalPath, journal, agentToken);
}

async function uploadStoredOutcome(
  client: Allowly,
  journalPath: string,
  journal: ExecutionJournal,
  agentToken?: string,
  providerResponse: CustomerHttpProviderResponse | null = null,
): Promise<CustomerHttpExecutionResult> {
  const stored = journal.outcome;
  if (stored === undefined) throw new Error("journal has no stored outcome to upload");
  const evidencePackage = {
    ...journal.evidence_package!,
    outcome: stored.body,
  };
  let response: CustomerExecutionResponse;
  try {
    response = await client.reportExecutionOutcome({
      operationId: journal.operation_id,
      idempotencyKey: stored.idempotency_key,
      agentToken,
      ...stored.body,
    });
  } catch {
    // Dispatch already happened and the outcome is durable. Never resend the
    // provider request just because reporting could not be confirmed.
    return {
      state: stored.body.targetState,
      authorization: requireAuthorization(journal),
      response: null,
      evidencePackage,
      outcomePending: true,
      providerResponse,
    };
  }
  const completed: ExecutionJournal = {
    ...journal,
    phase: "complete",
    final_response: response,
    evidence_package: evidencePackage,
  };
  await writeJournal(journalPath, completed);
  return resultFromFinal(completed, providerResponse);
}

async function reconcileAfterAmbiguousDispatch(
  client: Allowly,
  journalPath: string,
  journal: ExecutionJournal,
  agentToken?: string,
): Promise<CustomerHttpExecutionResult> {
  const authorization = requireAuthorization(journal);
  let response: CustomerExecutionResponse | null = null;
  try {
    response = await client.getExecution(journal.operation_id, {
      agentToken,
    });
  } catch {
    // An in-progress or temporarily unavailable reconciliation result is still
    // ambiguous. The durable journal prevents any new business request.
  }
  if (response !== null && ["succeeded", "failed", "unknown"].includes(response.status)) {
    const completed = { ...journal, phase: "complete" as const, final_response: response };
    await writeJournal(journalPath, completed);
    return resultFromFinal(completed);
  }
  return {
    state: "unknown",
    authorization,
    response,
    evidencePackage: journal.evidence_package!,
    outcomePending: false,
    providerResponse: null,
  };
}

function resultFromFinal(
  journal: ExecutionJournal,
  providerResponse: CustomerHttpProviderResponse | null = null,
): CustomerHttpExecutionResult {
  const authorization = requireAuthorization(journal);
  const response = journal.final_response!;
  if (authorization.decision !== "allow") return { state: "not_allowed", authorization };
  return {
    state: response.targetState === "response_observed" ? "response_observed" : "unknown",
    authorization,
    response,
    evidencePackage: journal.evidence_package!,
    outcomePending: false,
    providerResponse,
  };
}

function evidencePackageFor(
  authorization: CustomerExecutionResponse,
  outcome: CustomerExecutionOutcome | null,
  witness: CustomerExecutionEvidencePackage["witness"],
): CustomerExecutionEvidencePackage {
  const approval = authorization.approval;
  const approvalSha256 = authorization.approvalSha256;
  if (approval === null || approvalSha256 === null) {
    throw new AllowlyProtocolError("allowed customer execution is missing approval metadata");
  }
  return {
    profile: "allowly.customer_execution.evidence.v1",
    operationId: authorization.operationId,
    approval,
    approvalSha256,
    decisionReceipt: authorization.decisionReceipt,
    decisionReceiptVerification: authorization.decisionReceipt.status === "pending"
      ? "pending"
      : "not_verified",
    requestDescriptor: authorization.requestDescriptor,
    outcome,
    witness,
  };
}

function validateApprovedResponse(
  response: CustomerExecutionResponse,
  request: LocalRequest,
  options: CustomerHttpOptions,
): void {
  if (response.decision !== "allow"
      || response.status !== "approved"
      || response.decisionState !== "allowed"
      || response.targetState !== "not_started"
      || response.evidenceState !== "pending"
      || response.downstream !== null) {
    throw new AllowlyProtocolError("allow decision did not produce an approved execution");
  }
  const approval = response.approval;
  const approvalSha256 = requireApprovalHash(response);
  if (approval === null) throw new AllowlyProtocolError("approval descriptor is missing");
  const computed = normalizeDigest(hashSealValue(approval));
  if (computed !== normalizeDigest(approvalSha256)) {
    throw new AllowlyProtocolError("approval descriptor hash does not match approval_sha256");
  }
  const expectedPolicyInput = {
    resource: options.policyInput?.resource ?? null,
    context: options.policyInput?.context ?? {},
    estimated_cost_micros: options.policyInput?.estimatedCostMicros ?? null,
  };
  const executable = recordField(approval, "executable");
  const approvedRequest = { ...recordField(approval, "request") };
  const providerIdempotency = approvedRequest.provider_idempotency;
  delete approvedRequest.provider_idempotency;
  const expectedRequest = {
    method: request.commitment.method,
    origin: request.commitment.origin,
    path: request.commitment.path,
    query: request.commitment.query,
    headers: request.commitment.headers.map((header) => ({
      name: header.name,
      value_sha256: header.valueSha256,
    })),
    body_sha256: request.commitment.bodySha256,
    body_size: request.commitment.bodySize,
    content_type: request.commitment.contentType,
  };
  if (approval.profile !== "allowly.execution.approval.v1"
      || typeof approval.workspace_id !== "string"
      || approval.workspace_id.length === 0
      || approval.operation_id !== options.operationId
      || approval.authorization_id !== options.authorizationId
      || typeof approval.agent_id !== "string"
      || approval.agent_id.length === 0
      || approval.action !== options.action
      || executable.enabled_executable_id !== options.enabledExecutableId
      || executable.catalog_operation_id !== options.catalogOperationId
      || executable.origin !== request.commitment.origin
      || typeof executable.provider_id !== "string"
      || executable.provider_id.length === 0
      || typeof executable.catalog_revision !== "string"
      || executable.catalog_revision.length === 0
      || typeof executable.definition_fingerprint !== "string"
      || !/^sha256:[0-9a-f]{64}$/.test(executable.definition_fingerprint)
      || approval.policy_input_sha256 !== normalizeDigest(hashSealValue(expectedPolicyInput))
      || approval.policy_input_source !== "customer_runtime_reported"
      || approval.policy_input_request_semantics_verification !== "not_performed"
      || stableJson(approvedRequest) !== stableJson(expectedRequest)
      || stableJson(providerIdempotency) !== stableJson({ kind: "none" })
      || approval.evidence_mode !== response.effectiveEvidenceMode
      || approval.expires_at !== response.approvalExpiresAt
      || ((options.evidenceMode ?? "receipt") === "witnessed"
        && response.effectiveEvidenceMode !== "witnessed")) {
    throw new AllowlyProtocolError("approval scope does not match the customer execution request");
  }
  validateRequestDescriptor(response, request, options);
  assertApprovalLive(approval);
}

function validateRequestDescriptor(
  response: CustomerExecutionResponse,
  request: LocalRequest,
  options: CustomerHttpOptions,
): void {
  const descriptor = response.requestDescriptor;
  if (descriptor.operationId !== options.operationId
      || descriptor.authorizationId !== options.authorizationId
      || descriptor.destinationId !== options.enabledExecutableId
      || descriptor.action !== options.action
      || stableJson({
        method: descriptor.method,
        origin: descriptor.origin,
        path: descriptor.path,
        query: descriptor.query,
        headers: descriptor.headers,
        bodySha256: descriptor.bodySha256,
        bodySize: descriptor.bodySize,
        contentType: descriptor.contentType,
      }) !== stableJson(request.commitment)) {
    throw new AllowlyProtocolError("approval request does not match the local HTTP request");
  }
}

function validateWaitingResponse(
  response: CustomerExecutionResponse,
  request: LocalRequest,
  options: CustomerHttpOptions,
): void {
  const review = response.review;
  if (response.operationId !== options.operationId
      || response.destinationId !== options.enabledExecutableId
      || response.action !== options.action
      || response.status !== "waiting_for_review"
      || (response.decision !== "confirm" && response.decision !== "escalate")
      || response.decisionState !== "not_allowed"
      || response.targetState !== "not_started"
      || response.evidenceState !== "pending"
      || response.approval !== null
      || response.approvalSha256 !== null
      || response.downstream !== null
      || review === undefined || review === null
      || review.kind !== response.decision
      || review.sourceReceiptId !== decisionReceiptId(response)) {
    throw new AllowlyProtocolError("waiting execution lacks a bound review");
  }
  validateRequestDescriptor(response, request, options);
}

function decisionReceiptId(response: CustomerExecutionResponse): string {
  return response.decisionReceipt.status === "pending"
    ? response.decisionReceipt.receiptId
    : stringField(response.decisionReceipt.receipt, "receipt_id");
}

function waitingResult(response: CustomerExecutionResponse): CustomerHttpExecutionResult {
  if (response.status !== "waiting_for_review" || response.review === undefined
      || response.review === null
      || response.review.kind !== response.decision
      || response.review.sourceReceiptId !== decisionReceiptId(response)) {
    throw new AllowlyProtocolError("waiting journal lacks a bound review");
  }
  return { state: "waiting_for_review", authorization: response, review: response.review };
}

function originalPrepareRequest(
  request: LocalRequest,
  options: CustomerHttpOptions,
  journal: ExecutionJournal,
): Omit<PrepareExecutionRequest, "idempotencyKey" | "agentToken"> {
  return {
    operationId: options.operationId,
    authorizationId: options.authorizationId,
    enabledExecutableId: options.enabledExecutableId,
    catalogOperationId: options.catalogOperationId,
    action: options.action,
    evidenceMode: options.evidenceMode ?? "receipt",
    httpRequest: request.commitment,
    policyInput: options.policyInput,
    clientTimestamp: journal.prepare_client_timestamp!,
  };
}

function assertApprovalLive(approval: Record<string, unknown>): void {
  const issuedAt = typeof approval.issued_at === "string" ? Date.parse(approval.issued_at) : NaN;
  const expiresAt = typeof approval.expires_at === "string" ? Date.parse(approval.expires_at) : NaN;
  const now = Date.now();
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)
      || issuedAt >= expiresAt || now < issuedAt || now >= expiresAt) {
    throw new AllowlyProtocolError("execution approval is not currently valid");
  }
}

function validateReceiptApprovalLink(
  receipt: Record<string, unknown>,
  evidencePackage: CustomerExecutionEvidencePackage,
): void {
  if (receipt.decision !== "allow") {
    throw new AllowlyProtocolError("execution decision receipt is not an allow receipt");
  }
  const context = recordField(receipt, "context");
  const execution = recordField(context, "execution");
  const approval = evidencePackage.approval;
  if (execution.approval_sha256 !== evidencePackage.approvalSha256
      || execution.operation_id !== evidencePackage.operationId
      || receipt.workspace_id !== approval.workspace_id
      || receipt.authorization_id !== approval.authorization_id
      || receipt.action !== approval.action
      || (approval.agent_id !== null && approval.agent_id !== undefined
        && receipt.agent_id !== approval.agent_id)) {
    throw new AllowlyProtocolError("decision receipt does not bind the execution approval");
  }
}

function validateDispatchClaim(
  claim: import("./types.js").ClaimExecutionDispatchResponse,
  authorization: CustomerExecutionResponse,
): void {
  if (authorization.approval === null
      || authorization.approvalExpiresAt === null
      || stableJson(claim.approval) !== stableJson(authorization.approval)
      || normalizeDigest(hashSealValue(claim.approval)) !== normalizeDigest(claim.approvalSha256)
      || normalizeDigest(claim.approvalSha256)
        !== normalizeDigest(requireApprovalHash(authorization))
      || claim.approvalExpiresAt !== authorization.approvalExpiresAt
      || claim.effectiveEvidenceMode !== authorization.effectiveEvidenceMode) {
    throw new AllowlyProtocolError("dispatch claim differs from the prepared approval");
  }
  assertApprovalLive(claim.approval);
}

function validateWitnessRequestSize(request: LocalRequest): void {
  const target = request.commitment.query
    ? `${request.commitment.path}?${request.commitment.query}`
    : request.commitment.path;
  let raw = `${request.method} ${target} HTTP/1.1\r\nHost: ${request.url.hostname}\r\n`
    + "Connection: close\r\nAccept-Encoding: identity\r\n";
  for (const name of Object.keys(request.headers).sort()) {
    raw += `${name}: ${request.headers[name]}\r\n`;
  }
  raw += `Content-Length: ${Buffer.byteLength(request.body, "utf8")}\r\n\r\n${request.body}`;
  if (Buffer.byteLength(raw, "utf8") > MAX_WITNESSED_REQUEST_BYTES) {
    throw new Error("request exceeds the 2 KiB native witness capability");
  }
}

async function sendPinnedHttps(
  request: LocalRequest,
  address: string,
  family: 4 | 6,
  approval: Record<string, unknown>,
  timeoutMs: number,
): Promise<CustomerHttpProviderResponse> {
  return new Promise((resolve, reject) => {
    const agent = new HttpsAgent({ keepAlive: false });
    (agent as unknown as { createConnection: (...args: any[]) => unknown }).createConnection = (
      options: Record<string, unknown>,
      callback: (error: Error | null, socket?: unknown) => void,
    ) => {
      const socket = tlsConnect({
        ...options,
        host: request.url.hostname,
        port: 443,
        servername: request.url.hostname,
        lookup: (_hostname, _options, done) => done(null, address, family),
      });
      let returned = false;
      socket.setTimeout(timeoutMs, () => socket.destroy(new Error("provider TLS timed out")));
      socket.once("secureConnect", () => {
        if (returned) return;
        try {
          // The HTTP agent receives the socket only after TLS completes and
          // the short-lived approval is checked again.
          assertApprovalLive(approval);
          returned = true;
          callback(null, socket);
        } catch (error) {
          returned = true;
          socket.destroy(error as Error);
          callback(error as Error);
        }
      });
      socket.once("error", (error) => {
        if (!returned) {
          returned = true;
          callback(error);
        }
      });
      return undefined;
    };
    const req = httpsRequest({
      protocol: "https:",
      hostname: request.url.hostname,
      port: 443,
      path: request.url.pathname + request.url.search,
      method: request.method,
      servername: request.url.hostname,
      headers: {
        ...request.headers,
        "accept-encoding": "identity",
        connection: "close",
        "content-length": String(Buffer.byteLength(request.body, "utf8")),
      },
      agent,
    }, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (chunk: Buffer) => {
        size += chunk.byteLength;
        if (size > MAX_RECEIPT_RESPONSE_BYTES) {
          req.destroy(new Error("provider response exceeds 1 MiB"));
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      res.once("end", () => {
        clearTimeout(deadline);
        agent.destroy();
        if (res.statusCode === undefined
            || !Number.isInteger(res.statusCode)
            || res.statusCode < 200
            || res.statusCode > 599) {
          reject(new Error("provider response has no supported final HTTP status"));
          return;
        }
        resolve({ status: res.statusCode, body: Buffer.concat(chunks) });
      });
      res.once("error", (error) => {
        clearTimeout(deadline);
        agent.destroy();
        reject(error);
      });
    });
    const deadline = setTimeout(() => {
      req.destroy(new Error("provider request timed out"));
    }, timeoutMs);
    req.once("error", (error) => {
      clearTimeout(deadline);
      agent.destroy();
      reject(error);
    });
    req.end(request.body, "utf8");
  });
}

function executionTimeout(options: CustomerHttpOptions): number {
  const value = options.timeoutMs ?? DEFAULT_EXECUTION_TIMEOUT_MS;
  if (!Number.isFinite(value) || !Number.isInteger(value) || value <= 0 || value > 150_000) {
    throw new Error("timeoutMs must be an integer from 1 to 150000");
  }
  return value;
}

function witnessTimeout(options: CustomerHttpOptions): number {
  const value = options.witness?.timeoutMs ?? options.timeoutMs ?? DEFAULT_WITNESS_TIMEOUT_MS;
  if (!Number.isFinite(value) || !Number.isInteger(value) || value <= 0 || value > 150_000) {
    throw new Error("witness timeoutMs must be an integer from 1 to 150000");
  }
  return value;
}

async function resolvePublicAddress(hostname: string): Promise<{ address: string; family: 4 | 6 }> {
  const addresses = await dnsLookup(hostname, { all: true, verbatim: true });
  if (addresses.length === 0 || addresses.some((entry) => !isPublicIp(entry.address))) {
    throw new Error("provider DNS includes a non-public address");
  }
  const selected = addresses[0]!;
  if (selected.family !== 4 && selected.family !== 6) {
    throw new Error("provider DNS returned an unsupported address family");
  }
  return { address: selected.address, family: selected.family };
}

function isPublicIp(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    const [a, b, c] = address.split(".").map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2))))
      || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
      || (a === 203 && b === 0 && c === 113));
  }
  if (family !== 6) return false;
  const segments = ipv6Segments(address);
  if (segments === null) return false;
  return (segments[0]! & 0xe000) === 0x2000
    && !(segments[0] === 0x2001 && segments[1]! <= 0x01ff)
    && !(segments[0] === 0x2001 && segments[1] === 0x0db8)
    && segments[0] !== 0x2002
    && !(segments[0] === 0x3fff && segments[1]! <= 0x0fff);
}

function ipv6Segments(address: string): number[] | null {
  const parts = address.split("::");
  if (parts.length > 2) return null;
  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((parts.length === 1 && missing !== 0) || missing < 0) return null;
  const raw = [...left, ...Array(parts.length === 2 ? missing : 0).fill("0"), ...right];
  const values = raw.map((part) => /^[0-9a-f]{1,4}$/i.test(part) ? Number.parseInt(part, 16) : -1);
  return values.length === 8 && values.every((value) => value >= 0) ? values : null;
}

function startNativeWitness(
  binary: string,
  trustedKey: string,
  outputDirectory: string,
  witnessCaCert: string | undefined,
  input: Record<string, unknown>,
): ChildProcessWithoutNullStreams {
  const env: NodeJS.ProcessEnv = {};
  for (const name of ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"]) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  const child = spawn(binary, [
    "prove-execute",
    "--output",
    outputDirectory,
    "--trusted-key",
    trustedKey,
    ...(witnessCaCert === undefined ? [] : ["--witness-ca-cert", witnessCaCert]),
  ], { stdio: ["pipe", "pipe", "pipe"], env });
  const state: NativeChildState = {
    stdout: [],
    stderr: [],
    closed: new Promise((resolve) => child.once("close", resolve)),
    spawnError: null,
    stdinError: null,
    outputError: null,
    stdoutBytes: 0,
    stderrBytes: 0,
  };
  child.stdout.on("data", (chunk: Buffer) => {
    state.stdoutBytes += chunk.byteLength;
    if (state.stdoutBytes > MAX_NATIVE_STDOUT_BYTES) {
      state.outputError ??= new Error("native witness stdout is too large");
      child.kill("SIGKILL");
      return;
    }
    state.stdout.push(Buffer.from(chunk));
  });
  child.stderr.on("data", (chunk: Buffer) => {
    state.stderrBytes += chunk.byteLength;
    if (state.stderrBytes > MAX_NATIVE_STDERR_BYTES) {
      state.outputError ??= new Error("native witness stderr is too large");
      child.kill("SIGKILL");
      return;
    }
    state.stderr.push(Buffer.from(chunk));
  });
  child.once("error", (error) => { state.spawnError = error; });
  child.stdin.once("error", (error) => {
    state.stdinError = error;
    if (child.exitCode === null) child.kill("SIGKILL");
  });
  nativeChildStates.set(child, state);
  try {
    child.stdin.end(JSON.stringify(input));
  } catch (error) {
    state.stdinError = error as Error;
    if (child.exitCode === null) child.kill("SIGKILL");
  }
  return child;
}

async function waitForWitnessReady(
  child: ChildProcessWithoutNullStreams,
  directory: string,
  approvalSha256: string,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const state = nativeChildStates.get(child);
  if (state === undefined) throw new Error("native witness process state is missing");
  while (Date.now() < deadline) {
    if (state.spawnError !== null) throw state.spawnError;
    if (state.stdinError !== null) {
      throw new Error("native witness rejected its request input");
    }
    if (state.outputError !== null) throw state.outputError;
    if (child.exitCode !== null) throw new Error("native witness stopped before readiness");
    try {
      const raw = JSON.parse(await readFile(join(directory, "witness.ready.json"), "utf8"));
      if (raw?.approval_sha256 !== approvalSha256) {
        throw new Error("native witness readiness does not match the approval");
      }
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await delay(25);
  }
  throw new Error("native witness readiness timed out");
}

async function finishNativeWitness(
  child: ChildProcessWithoutNullStreams,
  timeoutMs: number,
  approvalSha256: string,
  evidenceDirectory: string,
): Promise<NativeResult> {
  const state = nativeChildStates.get(child);
  if (state === undefined) throw new Error("native witness process state is missing");
  const timeout = Symbol("native witness timeout");
  let timer: NodeJS.Timeout | undefined;
  let code: number | null;
  try {
    const winner = await Promise.race([
      state.closed,
      new Promise<typeof timeout>((resolveTimeout) => {
        timer = setTimeout(() => resolveTimeout(timeout), timeoutMs);
      }),
    ]);
    if (winner === timeout) {
      child.kill("SIGKILL");
      await state.closed;
      throw new Error("native witness timed out");
    }
    code = winner;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
  if (state.spawnError !== null) throw state.spawnError;
  if (state.stdinError !== null) throw new Error("native witness rejected its request input");
  if (state.outputError !== null) throw state.outputError;
  if (code !== 0) {
    throw new Error(`native witness failed with exit code ${code ?? "unknown"}`);
  }
  const encoded = Buffer.concat(state.stdout);
  const raw = JSON.parse(encoded.toString("utf8")) as Record<string, unknown>;
  if (raw.verified !== true
      || raw.profile !== "customer_held_tlsn_bundle_v1"
      || raw.request_binding_verification !== "verified_from_full_presentation"
      || normalizeDigest(stringField(raw, "approval_sha256"))
        !== normalizeDigest(approvalSha256)) {
    throw new Error("native witness output did not verify the full request");
  }
  const response = validateNativeResponse(recordField(raw, "response"));
  const expectedEvidencePath = await realpath(join(evidenceDirectory, "presentation.json"));
  const expectedAttestationPath = await realpath(join(evidenceDirectory, "attestation.json"));
  const reportedEvidencePath = await realpath(resolve(stringField(raw, "evidence_path")));
  const reportedAttestationPath = await realpath(resolve(stringField(raw, "attestation_path")));
  if (reportedEvidencePath !== expectedEvidencePath
      || reportedAttestationPath !== expectedAttestationPath) {
    throw new Error("native witness returned an unexpected artifact path");
  }
  const artifactBytes = await readFile(expectedEvidencePath);
  const attestationBytes = await readFile(expectedAttestationPath);
  if (normalizeDigest(stringField(raw, "artifact_sha256")) !== digest(artifactBytes)) {
    throw new Error("native witness presentation hash does not match the artifact");
  }
  if (normalizeDigest(stringField(raw, "attestation_sha256")) !== digest(attestationBytes)) {
    throw new Error("native witness attestation hash does not match the artifact");
  }
  const attestation = JSON.parse(attestationBytes.toString("utf8")) as unknown;
  if (attestation === null || typeof attestation !== "object" || Array.isArray(attestation)) {
    throw new Error("native witness attestation is not a JSON object");
  }
  return {
    response,
    artifact_sha256: stringField(raw, "artifact_sha256"),
    evidence_path: expectedEvidencePath,
    attestation_path: expectedAttestationPath,
    attestation: attestation as Record<string, unknown>,
  };
}

function validateNativeResponse(raw: Record<string, unknown>): NativeResult["response"] {
  const status = numberField(raw, "status");
  const body = stringField(raw, "body");
  const bytes = Buffer.from(body, "utf8");
  const bodyBytes = numberField(raw, "body_bytes");
  const bodySha256 = stringField(raw, "body_sha256");
  if (!Number.isInteger(status) || status < 200 || status > 599) {
    throw new Error("native witness response has an unsupported final HTTP status");
  }
  if (!Number.isInteger(bodyBytes)
      || bodyBytes !== bytes.byteLength
      || bytes.byteLength > MAX_WITNESSED_RESPONSE_BYTES
      || normalizeDigest(bodySha256) !== digest(bytes)) {
    throw new Error("native witness response body commitments do not match its UTF-8 bytes");
  }
  return { status, body, body_bytes: bodyBytes, body_sha256: normalizeDigest(bodySha256) };
}

async function stopNativeWitness(child: ChildProcessWithoutNullStreams): Promise<void> {
  const state = nativeChildStates.get(child);
  if (state === undefined) return;
  if (child.exitCode === null) child.kill("SIGKILL");
  await state.closed;
}

async function assertTrustedNotaryKey(path: string, expectedFingerprint: string): Promise<void> {
  const raw = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
  if (raw.alg !== 2 || !Array.isArray(raw.data)
      || !raw.data.every((value) => Number.isInteger(value) && value >= 0 && value <= 255)) {
    throw new Error("trusted notary key must be a TLSNotary P-256 key");
  }
  const compressed = ECDH.convertKey(
    Buffer.from(raw.data),
    "prime256v1",
    undefined,
    undefined,
    "compressed",
  ) as Buffer;
  const actual = digest(compressed);
  if (normalizeDigest(actual) !== normalizeDigest(expectedFingerprint)) {
    throw new Error("trusted notary key fingerprint does not match the witness session");
  }
}

async function ensureNewDirectory(path: string): Promise<void> {
  try {
    await access(path);
    throw new Error("witness evidence directory must not already exist");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
}

async function markDispatchAttempt(
  path: string,
  journal: ExecutionJournal,
  outcomeIdempotencyKey: string,
  approvalSha256: string,
): Promise<ExecutionJournal> {
  const startedAt = new Date().toISOString();
  const body: CustomerExecutionOutcome = {
    approvalSha256,
    targetState: "unknown",
    dispatchStartedAt: startedAt,
    completedAt: startedAt,
  };
  const updated: ExecutionJournal = {
    ...journal,
    phase: "dispatch_attempted",
    dispatch_attempted_at: startedAt,
    outcome: {
      idempotency_key: outcomeIdempotencyKey,
      body,
    },
    evidence_package: { ...journal.evidence_package!, outcome: body },
  };
  await writeJournal(path, updated);
  return updated;
}

async function storeOutcome(
  path: string,
  journal: ExecutionJournal,
  idempotencyKey: string,
  body: CustomerExecutionOutcome,
): Promise<ExecutionJournal> {
  const updated: ExecutionJournal = {
    ...journal,
    phase: "outcome_pending",
    outcome: { idempotency_key: idempotencyKey, body },
    evidence_package: { ...journal.evidence_package!, outcome: body },
  };
  await writeJournal(path, updated);
  return updated;
}

async function markDispatchClaimed(
  path: string,
  journal: ExecutionJournal,
): Promise<ExecutionJournal> {
  if (journal.outcome === undefined || journal.dispatch_attempted_at === undefined) {
    throw new Error("dispatch claim cannot be stored without the durable unknown outcome");
  }
  const updated: ExecutionJournal = { ...journal, phase: "outcome_pending" };
  await writeJournal(path, updated);
  return updated;
}

function dispatchStartedAt(journal: ExecutionJournal): Date {
  if (journal.dispatch_attempted_at === undefined) {
    throw new Error("dispatch start time is missing from the durable journal");
  }
  const value = new Date(journal.dispatch_attempted_at);
  if (Number.isNaN(value.getTime())) throw new Error("dispatch start time is invalid");
  return value;
}

function operationJournalPath(directory: string, operationId: string): string {
  const name = createHash("sha256").update(operationId, "utf8").digest("hex");
  return join(directory, `${name}.json`);
}

async function readJournal(path: string): Promise<ExecutionJournal | null> {
  try {
    const raw = JSON.parse(await readFile(path, "utf8")) as ExecutionJournal;
    if (raw.version !== JOURNAL_VERSION || typeof raw.operation_id !== "string"
        || typeof raw.request_sha256 !== "string") {
      throw new Error("customer execution journal is invalid");
    }
    return raw;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

async function writeJournal(path: string, journal: ExecutionJournal): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(path), 0o700);
  await atomicWriteJson(path, journal);
}

async function atomicWriteJson(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  const file = await open(temporary, "wx", 0o600);
  try {
    await file.writeFile(JSON.stringify(value));
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temporary, path);
  const directory = await open(dirname(path), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

async function withJournalLock<T>(path: string, work: () => Promise<T>): Promise<T> {
  const lockPath = `${path}.lock`;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const owner: JournalLockOwner = {
    version: 1,
    pid: process.pid,
    hostname: hostname(),
    token: createHash("sha256")
      .update(`${process.pid}\0${Date.now()}\0${Math.random()}`, "utf8")
      .digest("hex"),
    created_at: new Date().toISOString(),
  };
  await acquireJournalLock(lockPath, owner);
  try {
    return await work();
  } finally {
    await releaseJournalLock(lockPath, owner);
  }
}

async function acquireJournalLock(path: string, owner: JournalLockOwner): Promise<void> {
  const candidate = `${path}.${owner.token}.candidate`;
  const file = await open(candidate, "wx", 0o600);
  try {
    await file.writeFile(JSON.stringify(owner));
    await file.sync();
  } finally {
    await file.close();
  }
  try {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        await link(candidate, path);
        return;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const existing = await readJournalLockOwner(path);
        if (!isProvenDeadLocalOwner(existing)) {
          throw new Error("this customer execution operation is already active");
        }
        const quarantine = `${path}.${owner.token}.stale`;
        try {
          await rename(path, quarantine);
          await unlink(quarantine);
        } catch (recoveryError) {
          if ((recoveryError as NodeJS.ErrnoException).code !== "ENOENT") throw recoveryError;
        }
      }
    }
    throw new Error("this customer execution operation is already active");
  } finally {
    await unlink(candidate).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
  }
}

async function releaseJournalLock(path: string, owner: JournalLockOwner): Promise<void> {
  let existing: JournalLockOwner;
  try {
    existing = await readJournalLockOwner(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (existing.token !== owner.token) {
    throw new Error("customer execution journal lock ownership changed unexpectedly");
  }
  await unlink(path);
}

async function readJournalLockOwner(path: string): Promise<JournalLockOwner> {
  const value = JSON.parse(await readFile(path, "utf8")) as Partial<JournalLockOwner>;
  if (value.version !== 1
      || !Number.isInteger(value.pid)
      || (value.pid ?? 0) <= 0
      || typeof value.hostname !== "string"
      || typeof value.token !== "string"
      || typeof value.created_at !== "string") {
    throw new Error("customer execution journal lock metadata is invalid");
  }
  return value as JournalLockOwner;
}

function isProvenDeadLocalOwner(owner: JournalLockOwner): boolean {
  if (owner.hostname !== hostname()) return false;
  try {
    process.kill(owner.pid, 0);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH";
  }
}

function journalRequestSha256(request: LocalRequest, options: CustomerHttpOptions): string {
  return digest(Buffer.from(stableJson({
    operationId: options.operationId,
    authorizationId: options.authorizationId,
    enabledExecutableId: options.enabledExecutableId,
    catalogOperationId: options.catalogOperationId,
    action: options.action,
    evidenceMode: options.evidenceMode ?? "receipt",
    httpRequest: request.commitment,
    policyInput: {
      resource: options.policyInput?.resource ?? null,
      context: options.policyInput?.context ?? {},
      estimatedCostMicros: options.policyInput?.estimatedCostMicros ?? null,
    },
  }), "utf8"));
}

function prepareClientTimestamp(value: Date | string | undefined): string {
  if (value === undefined) return new Date().toISOString();
  if (value instanceof Date) return value.toISOString();
  if (typeof value !== "string" || !/(?:Z|[+-]\d{2}:\d{2})$/i.test(value)
      || Number.isNaN(Date.parse(value))) {
    throw new Error("clientTimestamp must be a valid timezone-aware timestamp");
  }
  return value;
}

function assertJournalIdentity(
  journal: ExecutionJournal,
  operationId: string,
  requestSha256: string,
): void {
  if (journal.operation_id !== operationId || journal.request_sha256 !== requestSha256) {
    throw new Error("operation ID was already used with different customer HTTP inputs");
  }
}

function requireAuthorization(journal: ExecutionJournal): CustomerExecutionResponse {
  if (journal.authorization === undefined) {
    throw new Error(
      "operation stopped before its authorization was stored; reconcile with the low-level API",
    );
  }
  return journal.authorization;
}

function requireApprovalHash(response: CustomerExecutionResponse): string {
  if (response.approvalSha256 === null) {
    throw new AllowlyProtocolError("allowed customer execution is missing approval_sha256");
  }
  return response.approvalSha256;
}

function headerDigest(name: string, value: string): string {
  return digest(Buffer.concat([
    Buffer.from(`${HEADER_PROFILE}\0${name}\0`, "utf8"),
    Buffer.from(value, "utf8"),
  ]));
}

function digest(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function normalizeDigest(value: string): string {
  return value.startsWith("sha256:") ? value : `sha256:${value}`;
}

function stableId(scope: string, operationId: string): string {
  return `${scope}:${createHash("sha256").update(operationId, "utf8").digest("hex")}`;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`)
    .join(",")}}`;
}

function validDnsName(hostname: string): boolean {
  return hostname.length <= 253
    && hostname.includes(".")
    && hostname === hostname.toLowerCase()
    && hostname.split(".").every((label) => label.length > 0
      && label.length <= 63
      && !label.startsWith("-")
      && !label.endsWith("-")
      && /^[a-z0-9-]+$/.test(label));
}

function encodedAscii(value: string): boolean {
  return value.length > 0 && [...value].every((character) => {
    const code = character.charCodeAt(0);
    return code >= 0x21 && code <= 0x7e && character !== "#";
  });
}

function recordField(raw: Record<string, unknown>, key: string): Record<string, unknown> {
  const value = raw[key];
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AllowlyProtocolError(`${key} must be an object`);
  }
  return value as Record<string, unknown>;
}

function stringField(raw: Record<string, unknown> | null, key: string): string {
  const value = raw?.[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new AllowlyProtocolError(`${key} must be a non-empty string`);
  }
  return value;
}

function numberField(raw: Record<string, unknown>, key: string): number {
  const value = raw[key];
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new AllowlyProtocolError(`${key} must be a finite number`);
  }
  return value;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
