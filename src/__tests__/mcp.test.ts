import { describe, it, expect, vi, beforeEach } from "vitest";
import { AllowlyMCPMiddleware } from "../mcp.js";
import { Allowly } from "../client.js";

const BASE = "https://api.example.com";

const PENDING_RECEIPT = {
  status: "pending" as const,
  receipt_id: "rcp_abc",
  ready_at_estimate: "2026-04-21T14:32:18.482Z",
  url: `${BASE}/v1/receipts/rcp_abc`,
};

function makeAllowResponse() {
  return {
    userId: "u1", agentId: "gmail-tools", authorizationId: "auth_1",
    authorizationExpiresAt: "2026-12-31T00:00:00Z", policyVersion: "2026-04-19.1",
    results: {
      read_email: {
        decision: "allow" as const,
        reason: "authorization_granted_scope_active",
        receipt: { status: "pending" as const, receiptId: "rcp_abc", readyAtEstimate: "", url: "" },
        isFallback: false,
        fallbackMode: null,
        budget: null,
      },
      send_email: {
        decision: "allow" as const,
        reason: "authorization_granted_scope_active",
        receipt: { status: "pending" as const, receiptId: "rcp_abc", readyAtEstimate: "", url: "" },
        isFallback: false,
        fallbackMode: null,
        budget: null,
      },
    },
  };
}

function makeDenyResponse() {
  return {
    userId: "u1", agentId: "gmail-tools", authorizationId: "auth_1",
    authorizationExpiresAt: "2026-12-31T00:00:00Z", policyVersion: "2026-04-19.1",
    results: {
      send_email: {
        decision: "deny" as const,
        reason: "authorization_not_found",
        receipt: { status: "pending" as const, receiptId: "rcp_abc", readyAtEstimate: "", url: "" },
        isFallback: false,
        fallbackMode: null,
        budget: null,
      },
    },
  };
}

function makeConfirmResponse() {
  return {
    userId: "u1", agentId: "gmail-tools", authorizationId: "auth_1",
    authorizationExpiresAt: "2026-12-31T00:00:00Z", policyVersion: "2026-04-19.1",
    results: {
      send_email: {
        decision: "confirm" as const,
        reason: "scope_requires_user_confirmation",
        receipt: { status: "pending" as const, receiptId: "rcp_abc", readyAtEstimate: "", url: "" },
        isFallback: false,
        fallbackMode: null,
        budget: null,
        confirmNonce: "cnf_abc", confirmExpiresAt: "2026-04-20T00:15:00Z",
        confirmPromptHint: "email.send",
      },
    },
  };
}

function makeCallToolReq(name: string, args: Record<string, unknown> = {}) {
  return { params: { name, arguments: args } };
}

function makeMiddleware(authorizationIdFn = (userId: string) => userId ? "auth_1" : null) {
  const mw = new AllowlyMCPMiddleware({
    apiKey: "test-key",
    baseUrl: BASE,
    authorizationIdFn,
  });
  return mw;
}

// Minimal mock Server that tracks registered handlers
function makeServer() {
  const handlers = new Map<string, (req: unknown) => Promise<unknown>>();
  const originalHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "tool result" }] });
  handlers.set("tools/call", originalHandler);
  return {
    _requestHandlers: handlers,
    setRequestHandler: vi.fn((schema: unknown, handler: (req: unknown) => Promise<unknown>) => {
      handlers.set("tools/call", handler);
    }),
    originalHandler,
    handlers,
  };
}

describe("AllowlyMCPMiddleware — low-level Server", () => {
  it("allows tool call and delegates to original handler", async () => {
    const mw = makeMiddleware();
    vi.spyOn(mw.client, "check").mockResolvedValue(makeAllowResponse());

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    const result = await handler(makeCallToolReq("read_email", { user_id: "u1" })) as any;

    expect(server.originalHandler).toHaveBeenCalledWith(makeCallToolReq("read_email", { user_id: "u1" }));
    expect(result.isError).toBeFalsy();
  });

  it("blocks tool call on deny", async () => {
    const mw = makeMiddleware();
    vi.spyOn(mw.client, "check").mockResolvedValue(makeDenyResponse());

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    const result = await handler(makeCallToolReq("send_email", { user_id: "u1" })) as any;

    expect(server.originalHandler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.decision).toBe("deny");
    expect(body.reason).toBe("authorization_not_found");
  });

  it("returns confirm nonce and prompt hint", async () => {
    const mw = makeMiddleware();
    vi.spyOn(mw.client, "check").mockResolvedValue(makeConfirmResponse());

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    const result = await handler(makeCallToolReq("send_email", { user_id: "u1" })) as any;

    expect(server.originalHandler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.decision).toBe("confirm");
    expect(body.confirm_nonce).toBe("cnf_abc");
    expect(body.confirm_prompt_hint).toBe("email.send");
  });

  it("denies when user_id is missing", async () => {
    const mw = makeMiddleware();
    const checkSpy = vi.spyOn(mw.client, "check");

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    const result = await handler(makeCallToolReq("read_email", {})) as any;

    expect(checkSpy).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.decision).toBe("deny");
  });

  it("calls check with resolved authorization_id", async () => {
    const mw = makeMiddleware();
    const checkSpy = vi.spyOn(mw.client, "check").mockResolvedValue(makeAllowResponse());

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    await handler(makeCallToolReq("read_email", { user_id: "u1" }));

    expect(checkSpy).toHaveBeenCalledWith({ authorizationId: "auth_1", scopes: ["read_email"] });
  });
});
