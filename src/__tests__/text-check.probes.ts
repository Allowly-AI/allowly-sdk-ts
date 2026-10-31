import { Allowly, type AgentTextCheckRequest, type TextCheckResponse, type PolicyRequestParsing,
  type ParsedTextRequest, type ActionCheckResultConfirm, type ActionCheckResultEscalate } from "../index.js";

export async function textCheckSnippet(client: Allowly): Promise<TextCheckResponse> {
  const request: AgentTextCheckRequest = {
    agentName: "Support agent", request: "Reply to ticket:one with a refund of 0 dollars.",
    idempotencyKey: "ticket-one-initial", estimatedCostMicros: 0, timeoutMs: 35_000,
  };
  const checked = await client.checkTextByAgent(request);
  const action: string = checked.parse.parsedRequest.actions[0];
  const guidance: PolicyRequestParsing = { description: "Reply to a ticket", resource: "Ticket ID", fields: { amount_micros: "Refund in micro-USD" } };
  void action; void guidance;
  // @ts-expect-error every parse requires a stable idempotency key
  await client.checkTextByAgent({ agentName: "Support agent", request: "Reply" });
  // @ts-expect-error text checks do not accept an enrolled agent identity
  await client.checkTextByAgent({ ...request, agentToken: "identity" });
  // @ts-expect-error resume cannot accept changed text or caller-selected structured facts
  await client.recheckTextByAgent({ agentName: request.agentName, parseId: checked.parse.id, idempotencyKey: "resume", request: "Changed" });
  return client.recheckTextByAgent({ agentName: request.agentName, parseId: checked.parse.id, idempotencyKey: "ticket-one-resume" });
}

export async function documentedTextCheckSnippet(
  client: Allowly,
  waitForApprovedSlackStatus: (result: ActionCheckResultConfirm | ActionCheckResultEscalate) => Promise<void>,
  executeParsedRequest: (request: ParsedTextRequest) => Promise<void>,
): Promise<void> {
  let checked = await client.checkTextByAgent({
    agentName: "Support agent",
    request: "Reply to ticket:one with a refund of 0 dollars.",
    idempotencyKey: "ticket-one-initial",
    estimatedCostMicros: 0,
    timeoutMs: 35_000,
  });
  const action = checked.parse.parsedRequest.actions[0];
  const result = checked.results[action];
  if (result.decision === "confirm" || result.decision === "escalate") {
    await waitForApprovedSlackStatus(result);
    checked = await client.recheckTextByAgent({
      agentName: "Support agent", parseId: checked.parse.id,
      idempotencyKey: "ticket-one-resume",
    });
  }
  if (checked.results[action].decision === "allow") {
    await executeParsedRequest(checked.parse.parsedRequest);
  }
}
