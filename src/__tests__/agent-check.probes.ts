import { Allowly, type AgentCheckRequest, type CheckResponse } from "../index.js";

export async function nameRoutedCheckSnippet(client: Allowly): Promise<CheckResponse> {
  const request: AgentCheckRequest = {
    agentName: "Support agent", actions: ["ticket.reply"], resource: "ticket:one",
    context: { external: true }, idempotencyKey: "support-ticket-one", wait: true,
  };
  const result = await client.checkByAgent(request);
  const resolvedAuthorizationId: string = result.authorizationId;
  void resolvedAuthorizationId;
  // @ts-expect-error name routing does not accept a caller-held authorization
  await client.checkByAgent({ ...request, authorizationId: "auth_other" });
  // @ts-expect-error verified identity uses the original check method
  await client.checkByAgent({ ...request, agentToken: "identity-token" });
  return result;
}
