/**
 * Allowly middleware for MCP servers.
 *
 * McpServer (high-level) usage:
 *   const mcp = new McpServer({ name: "my-agent", version: "1.0" });
 *   const allowly = new AllowlyMCPMiddleware({
 *     apiKey: process.env.ALLOWLY_KEY!,
 *     authorizationIdFn: (userId) => db.getAuthorizationId(userId),
 *   });
 *   allowly.attach(mcp.server);
 *
 * Low-level Server usage:
 *   const server = new Server({ name: "my-agent", version: "1.0" });
 *   const allowly = new AllowlyMCPMiddleware({ ... });
 *   allowly.attach(server);
 */
import { Allowly } from "./client.js";
import type { ScopeCheckResultConfirm, ScopeCheckResultEscalate } from "./types.js";

type AuthorizationIdFn = (userId: string) => string | null | Promise<string | null>;

export interface AllowlyMCPMiddlewareOptions {
  apiKey: string;
  authorizationIdFn: AuthorizationIdFn;
  baseUrl?: string;
}

export class AllowlyMCPMiddleware {
  readonly client: Allowly;
  private readonly authorizationIdFn: AuthorizationIdFn;

  constructor(opts: AllowlyMCPMiddlewareOptions) {
    this.client = new Allowly({
      apiKey: opts.apiKey,
      ...(opts.baseUrl ? { baseUrl: opts.baseUrl } : {}),
    });
    this.authorizationIdFn = opts.authorizationIdFn;
  }

  private async resolveAuthorizationId(userId: string): Promise<string | null> {
    return this.authorizationIdFn(userId);
  }

  /**
   * Attach to a low-level MCP `Server` instance.
   *
   * Wraps the existing `CallToolRequestSchema` handler so every tool call is
   * gated on an Allowly check before the original handler runs.
   */
  attach(server: {
    setRequestHandler: (schema: unknown, handler: (req: unknown) => Promise<unknown>) => void;
    _requestHandlers?: Map<string, unknown>;
  }): void {
    // Import lazily so the module loads cleanly in environments without @modelcontextprotocol/sdk
    const { CallToolRequestSchema } = require("@modelcontextprotocol/sdk/types.js");

    const originalHandlers: Map<string, (req: unknown) => Promise<unknown>> =
      (server as any)._requestHandlers ?? new Map();
    const originalHandler = originalHandlers.get("tools/call") as
      | ((req: unknown) => Promise<unknown>)
      | undefined;

    server.setRequestHandler(CallToolRequestSchema, async (req: unknown) => {
      const r = req as { params: { name: string; arguments?: Record<string, unknown> } };
      const args = r.params.arguments ?? {};
      const userId = (args["user_id"] as string) ?? "";

      const authorizationId = await this.resolveAuthorizationId(userId);
      if (authorizationId === null) {
        return {
          content: [{ type: "text", text: JSON.stringify({ decision: "deny", reason: "authorization_not_found" }) }],
          isError: true,
        };
      }

      const result = await this.client.check({ authorizationId, scopes: [r.params.name] });
      const scopeResult = result.results[r.params.name];

      if (scopeResult.decision === "allow") {
        if (originalHandler) return originalHandler(req);
        return { content: [], isError: false };
      }

      if (scopeResult.decision === "confirm") {
        const c = scopeResult as ScopeCheckResultConfirm;
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              decision: "confirm",
              reason: c.reason,
              confirm_nonce: c.confirmNonce,
              confirm_prompt_hint: c.confirmPromptHint,
            }),
          }],
          isError: true,
        };
      }

      if (scopeResult.decision === "escalate") {
        const e = scopeResult as ScopeCheckResultEscalate;
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              decision: "escalate",
              reason: e.reason,
              escalation_id: e.escalationId,
              escalation_to: e.escalationTo,
              escalation_expires_at: e.escalationExpiresAt,
            }),
          }],
          isError: true,
        };
      }

      return {
        content: [{ type: "text", text: JSON.stringify({ decision: scopeResult.decision, reason: scopeResult.reason }) }],
        isError: true,
      };
    });
  }
}
