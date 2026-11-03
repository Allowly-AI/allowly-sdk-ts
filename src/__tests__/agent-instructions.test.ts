import { describe, expect, it, vi } from "vitest";
import { Allowly, AllowlyProtocolError } from "../index.js";

const GUIDANCE = "# Support agent\nUse ticket.reply with real facts. Policy edition: 2.\n";
const OPTIONS = { apiKey: "runtime-secret", baseUrl: "https://api.example.com", fallbackByAction: { x: "fail_open" as const } };

describe("Allowly.agentInstructions", () => {
  it("preserves exact names, text, runtime auth and subsequent JSON requests", async () => {
    const name = "Support /?&=# + café 🧭";
    const fetch = vi.fn().mockResolvedValueOnce(new Response(GUIDANCE, { headers: { "Content-Type": "text/plain; charset=utf-8" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ status: "ready" })));
    const client = new Allowly({ ...OPTIONS, fetch, edgeToken: "edge-secret", requestTimeoutMs: 250 });
    await expect(client.agentInstructions({ agentName: name })).resolves.toBe(GUIDANCE);
    const [url, request] = fetch.mock.calls[0];
    expect(new URL(url).searchParams.getAll("agent_name")).toEqual([name]);
    expect([...new URL(url).searchParams.keys()]).toEqual(["agent_name"]);
    expect(new URL(url).hash).toBe("");
    expect(request).toMatchObject({ method: "GET", redirect: "manual", headers: {
      Authorization: "Bearer runtime-secret", "X-Allowly-Edge-Token": "edge-secret", Accept: "text/plain",
    } });
    expect(request.headers["X-Allowly-Agent-Token"]).toBeUndefined();
    expect(request.signal).toBeInstanceOf(AbortSignal);
    await expect(client.readiness()).resolves.toBe(true);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it.each([false, true])("rejects configured identity without calling its supplier: %s", async useSupplier => {
    const fetch = vi.fn();
    const supplier = vi.fn(() => "identity-secret");
    const client = new Allowly({ ...OPTIONS, fetch,
      ...(useSupplier ? { agentTokenSupplier: supplier } : { agentToken: "identity-secret" }),
    });
    await expect(client.agentInstructions({ agentName: "Support agent" })).rejects.toThrow("configured agent identity");
    expect(fetch).not.toHaveBeenCalled();
    expect(supplier).not.toHaveBeenCalled();
  });

  it.each(["", " ", " padded", "padded ", "a\0b", "a".repeat(129), null])("rejects invalid names before HTTP: %j", async name => {
    const fetch = vi.fn();
    const client = new Allowly({ ...OPTIONS, fetch });
    await expect(client.agentInstructions({ agentName: name as string })).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("counts Unicode code points at the name limit", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(GUIDANCE, { headers: { "Content-Type": "text/plain" } }));
    await expect(new Allowly({ ...OPTIONS, fetch }).agentInstructions({ agentName: "🧭".repeat(128) })).resolves.toBe(GUIDANCE);
  });

  it.each([
    [200, "application/json", '{"instructions":"text"}'], [200, "text/html", "<html>error</html>"],
    [200, "", "guidance"], [200, "text/plain", " \n"], [200, "text/plain", '{"error":"proxy error"}'],
    [200, "text/plain", "<html>error</html>"], [200, "text/plain", "echo runtime-secret"],
    [201, "text/plain", "guidance"], [204, "", null],
  ])("rejects invalid successful responses %s %s %s", async (status, mime, body) => {
    const fetch = vi.fn().mockResolvedValue(new Response(body, { status, headers: { "Content-Type": mime } }));
    await expect(new Allowly({ ...OPTIONS, fetch }).agentInstructions({ agentName: "Support agent" })).rejects.toBeInstanceOf(AllowlyProtocolError);
  });

  it("rejects invalid UTF-8 and already-followed redirects", async () => {
    const response = new Response(new Uint8Array([0xff]), { headers: { "Content-Type": "text/plain" } });
    const fetch = vi.fn().mockResolvedValueOnce(response);
    const client = new Allowly({ ...OPTIONS, fetch });
    await expect(client.agentInstructions({ agentName: "Support agent" })).rejects.toThrow("UTF-8");
    const redirected = new Response(GUIDANCE, { headers: { "Content-Type": "text/plain" } });
    Object.defineProperty(redirected, "redirected", { value: true });
    fetch.mockResolvedValueOnce(redirected);
    await expect(client.agentInstructions({ agentName: "Support agent" })).rejects.toThrow("redirected");
  });

  it.each([302, 401, 404, 409, 429, 503])("preserves structured HTTP %s errors and never falls back", async status => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: {
      code: "named_agent_not_found", message: "runtime-secret invalid", fields: [{ field: "agent_name", message: "exact name required" }],
    } }), { status, headers: { "Retry-After": "3", Location: "https://other.example/" } }));
    await expect(new Allowly({ ...OPTIONS, fetch }).agentInstructions({ agentName: "Support agent" })).rejects.toMatchObject({
      name: "AllowlyAPIError", status, code: "named_agent_not_found", message: "[REDACTED] invalid", retryAfterSeconds: 3,
      fields: [{ field: "agent_name", message: "exact name required" }],
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("preserves timeout and transport failures without fallback", async () => {
    const timeout = new DOMException("timed out", "TimeoutError");
    const fetch = vi.fn().mockRejectedValueOnce(timeout).mockRejectedValueOnce(new Error("runtime-secret offline"));
    const client = new Allowly({ ...OPTIONS, fetch });
    await expect(client.agentInstructions({ agentName: "Support agent" })).rejects.toBe(timeout);
    await expect(client.agentInstructions({ agentName: "Support agent" })).rejects.toMatchObject({
      name: "AllowlyTransportError", cause: { message: "[REDACTED] offline" },
    });
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
