import { Allowly, type AgentCheckRequest, type CheckResponse } from "../index.js";

export async function nameRoutedCheckSnippet(client: Allowly): Promise<CheckResponse> {
  const request: AgentCheckRequest = {
    expectedPolicyRef: { policy_id: "support", policy_version: 1, definition_sha256: "a".repeat(64) },
    agentName: "Support agent", actions: ["ticket.reply"], resource: "ticket:one",
    context: { external: true }, idempotencyKey: "support-ticket-one", wait: true,
  };
  // @ts-expect-error the exact policy reference is required
  await client.checkByAgent({ agentName: request.agentName, actions: request.actions });
  const result = await client.checkByAgent(request);
  await client.checkByAgent({ ...request, idempotencyKey: "support-ticket-one-after-review" });
  const resolvedAuthorizationId: string = result.authorizationId;
  void resolvedAuthorizationId;
  // @ts-expect-error name routing does not accept a caller-held authorization
  await client.checkByAgent({ ...request, authorizationId: "auth_other" });
  // @ts-expect-error verified identity uses the original check method
  await client.checkByAgent({ ...request, agentToken: "identity-token" });
  return result;
}
