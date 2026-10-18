import { describe, expect, it, vi } from "vitest";
import { Allowly, AllowlyProtocolError } from "../index.js";
import type { ObserveSubmitRequest } from "../index.js";

const reference = { policy_id: "published", policy_version: 1, definition_sha256: "a".repeat(64) };
const event: ObserveSubmitRequest = { eventId: "operation:1", agentId: "agent_demo", action: "email.send", policyRef: reference,
  occurredAt: "2026-10-18T20:00:00Z", reportedExecution: "sent", sources: { body: "Fictional capture" } };
const wire = { event_id: event.eventId, agent_id: event.agentId, action: event.action, policy_ref: reference,
  occurred_at: event.occurredAt, reported_execution: event.reportedExecution, sources: event.sources };
const pending = { event_id: event.eventId, agent_id: event.agentId, action: event.action, policy_ref: reference,
  reported_execution: "sent", mode: "observe", intervention: "none", processing_status: "pending", assessment_status: "not_assessed",
  signing_status: "unavailable", observed_action_id: null, assessment_id: null, dashboard_url: null, last_error: null };
function client(fetch: ReturnType<typeof vi.fn>) {
  return new Allowly({ apiKey: "runtime-key", baseUrl: "https://api.test", fetch: fetch as typeof globalThis.fetch,
    fallbackByAction: { "email.send": "fail_open" } });
}
function response(status: number, value: unknown) { return new Response(JSON.stringify(value), { status }); }

describe("Observe reports", () => {
  it("uses the runtime bearer, strict202/200 and encoded event ID with typed results", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(response(202, pending)).mockResolvedValueOnce(response(200, { ...pending,
      processing_status: "complete", assessment_status: "violation_detected", signing_status: "signed", observed_action_id: "action_test", assessment_id: "assessment_test" }));
    const sdk = client(fetch);
    const result = await sdk.observe.submit(event);
    expect(result).toMatchObject({ eventId: event.eventId, mode: "observe", intervention: "none", reportedExecution: "sent",
      processingStatus: "pending", assessmentStatus: "not_assessed", signingStatus: "unavailable", assessmentId: null });
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual(wire);
    expect(fetch.mock.calls[0][1].headers.Authorization).toBe("Bearer runtime-key");
    expect(await sdk.observe.get(event.eventId)).toMatchObject({ assessmentStatus: "violation_detected", signingStatus: "signed" });
    expect(fetch.mock.calls[1][0]).toBe("https://api.test/v1/observe/events/operation%3A1");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it.each([200, 201, 204])("rejects HTTP%s for a submission", async status => {
    const fetch = vi.fn().mockResolvedValue(status === 204 ? new Response(null, { status }) : response(status, pending));
    await expect(client(fetch).observe.submit(event)).rejects.toThrow(AllowlyProtocolError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("requires HTTP200 for status", async () => {
    await expect(client(vi.fn().mockResolvedValue(response(202, pending))).observe.get(event.eventId)).rejects.toThrow(AllowlyProtocolError);
  });

  it.each([
    { event_id: "other" }, { agent_id: "other" }, { action: "email.read" }, { policy_ref: { ...reference, policy_version: 2 } },
    { reported_execution: "unknown" }, { mode: "enforce" }, { intervention: "deny" }, { assessment_status: "allow" },
    { sources: { body: "private" } }, { signing_status: null }, { policy_ref: { ...reference, policy_version: true } },
  ])("rejects malformed or unbound response %j", async change => {
    await expect(client(vi.fn().mockResolvedValue(response(202, { ...pending, ...change }))).observe.submit(event)).rejects.toThrow(AllowlyProtocolError);
  });
  it("requires all nullable fields and status event binding", async () => {
    const { assessment_id, ...missing } = pending;
    await expect(client(vi.fn().mockResolvedValue(response(200, missing))).observe.get(event.eventId)).rejects.toThrow(AllowlyProtocolError);
    await expect(client(vi.fn().mockResolvedValue(response(200, { ...pending, event_id: "other" }))).observe.get(event.eventId)).rejects.toThrow(AllowlyProtocolError);
  });

  it.each([
    { eventId: "../escape" }, { sources: { body: true } }, { sources: {} }, { sources: { ["x".repeat(65)]: "text" } },
    { sources: { body: "x".repeat(40960) } }, { sources: { body: "\0" } }, { occurredAt: "2026-10-18T20:00:00" },
    { langfuseSecret: "secret" }, { policyRef: { ...reference, policy_version: true } },
  ])("rejects invalid capture before network %j", async change => {
    const fetch = vi.fn();
    await expect(client(fetch).observe.submit({ ...event, ...change } as ObserveSubmitRequest)).rejects.toThrow(AllowlyProtocolError);
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each(["timeout", "conflict", "invalid_json"])("does not retry or fail open after %s", async kind => {
    const fetch = vi.fn();
    if (kind === "timeout") fetch.mockRejectedValue(new Error("ambiguous"));
    else if (kind === "conflict") fetch.mockResolvedValue(response(409, { error: { code: "event_conflict", message: "Different content" } }));
    else fetch.mockResolvedValue(new Response("invalid-json", { status: 202 }));
    await expect(client(fetch).observe.submit(event)).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("freezes input identity before awaiting the API", async () => {
    const mutable = structuredClone(event);
    const fetch = vi.fn(async () => { mutable.eventId = "changed"; mutable.policyRef.policy_version = 2; return response(202, pending); });
    expect((await client(fetch).observe.submit(mutable)).eventId).toBe(event.eventId);
  });
});
