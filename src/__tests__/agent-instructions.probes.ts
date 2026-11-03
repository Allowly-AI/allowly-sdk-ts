import { Allowly, type AgentInstructionsRequest } from "../index.js";

export async function hostedInstructionsSnippet(client: Allowly): Promise<string> {
  const request: AgentInstructionsRequest = { agentName: "Support agent" };
  const instructions: string = await client.agentInstructions(request);
  // @ts-expect-error the configured name is required
  await client.agentInstructions({});
  // @ts-expect-error public SDK inputs use camelCase
  await client.agentInstructions({ agent_name: "Support agent" });
  return instructions;
}
