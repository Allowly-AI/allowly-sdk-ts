/** Captured action reporting; no permission or automatic retries. */
import { AllowlyProtocolError } from "./error.js";
import { document, exact, parsePolicyReference, record, text } from "./policies.js";
import type { Allowly } from "./client.js";
import type { ObserveEventStatus, ObserveSubmitRequest } from "./types.js";

const EXECUTION = ["accepted", "sent", "failed", "unknown"] as const;
function eventId(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    throw new AllowlyProtocolError("eventId must be 1 to 128 safe ASCII characters");
  }
  return value;
}
function choice<T extends string>(value: unknown, choices: readonly T[], name: string): T {
  if (typeof value !== "string" || !choices.includes(value as T)) throw new AllowlyProtocolError(`${name} is unsupported`);
  return value as T;
}
function nullable(value: unknown, name: string, limit = 128): string | null {
  return value === null ? null : text(value, name, limit);
}
function status(value: unknown, id: string, submitted?: Record<string, unknown>): ObserveEventStatus {
  const raw = exact(document(value, "Observe status", 16 * 1024), [
    "event_id", "agent_id", "action", "policy_ref", "mode", "intervention", "reported_execution",
    "processing_status", "assessment_status", "signing_status", "observed_action_id", "assessment_id", "dashboard_url", "last_error",
  ], "Observe status");
  const reference = parsePolicyReference(raw.policy_ref);
  if (eventId(raw.event_id) !== id || (submitted && (
    ["agent_id", "action", "reported_execution"].some(key => raw[key] !== submitted[key])
    || ["policy_id", "policy_version", "definition_sha256"].some(key => reference[key as keyof typeof reference] !== (submitted.policy_ref as Record<string, unknown>)[key])
  ))) throw new AllowlyProtocolError("Observe response does not match the submitted event");
  return {
    eventId: id, agentId: text(raw.agent_id, "agent_id"), action: text(raw.action, "action", 64), policyRef: reference,
    mode: choice(raw.mode, ["observe"], "mode"), intervention: choice(raw.intervention, ["none"], "intervention"),
    reportedExecution: choice(raw.reported_execution, EXECUTION, "reported_execution"),
    processingStatus: choice(raw.processing_status, ["pending", "processing", "complete", "failed"], "processing_status"),
    assessmentStatus: choice(raw.assessment_status, ["not_assessed", "no_violation_found", "violation_detected", "insufficient_evidence"], "assessment_status"),
    signingStatus: choice(raw.signing_status, ["unavailable", "pending", "signed"], "signing_status"),
    observedActionId: nullable(raw.observed_action_id, "observed_action_id"), assessmentId: nullable(raw.assessment_id, "assessment_id"),
    dashboardUrl: nullable(raw.dashboard_url, "dashboard_url", 2048), lastError: nullable(raw.last_error, "last_error"),
  };
}

export class ObserveResource {
  constructor(private readonly client: Allowly) {}

  async submit(request: ObserveSubmitRequest): Promise<ObserveEventStatus> {
    exact(request, ["eventId", "agentId", "action", "policyRef", "occurredAt", "reportedExecution", "sources"], "Observe event");
    const sources = record(request.sources, "sources");
    if (Object.keys(sources).length < 1 || Object.keys(sources).length > 32 || Object.entries(sources).some(([name, value]) =>
      [...name].length < 1 || [...name].length > 64 || name.includes("\0") || typeof value !== "string" || value.includes("\0")
    )) throw new AllowlyProtocolError("Observe requires 1 to 32 bounded string sources");
    if (typeof request.occurredAt !== "string" || !request.occurredAt.includes("T") || !/(?:Z|[+-]\d{2}:\d{2})$/.test(request.occurredAt) || Number.isNaN(Date.parse(request.occurredAt))) {
      throw new AllowlyProtocolError("occurredAt must be a timezone-aware ISO8601 timestamp");
    }
    const body = document({
      event_id: eventId(request.eventId), agent_id: text(request.agentId, "agentId"), action: text(request.action, "action", 64),
      policy_ref: parsePolicyReference(request.policyRef), occurred_at: request.occurredAt,
      reported_execution: choice(request.reportedExecution, EXECUTION, "reportedExecution"), sources,
    }, "Observe event", 40 * 1024);
    const raw = await this.client.request<unknown>("POST", "/v1/observe/events", body, { expectedStatus: 202 });
    return status(raw, body.event_id as string, body);
  }

  async get(id: string): Promise<ObserveEventStatus> {
    const raw = await this.client.request<unknown>("GET", `/v1/observe/events/${encodeURIComponent(eventId(id))}`, undefined, { expectedStatus: 200 });
    return status(raw, id);
  }
}
