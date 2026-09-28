import { describe, expect, it, vi } from "vitest";
import { Allowly, AllowlyProtocolError } from "../index.js";

function responseBody() {
  return {
    enabled_executable_id: "exe_custom",
    provider_id: "customer-defined-123",
    provider_name: "Update customer",
    category: "customer_defined",
    origin: "https://api.example.com",
    catalog_revision: "customer-defined.v1:sha256:" + "a".repeat(64),
    status: "customer_defined",
    credential_location: "customer_runtime",
    connection_status: "not_verified",
    allowly_live_tested: false,
    tls_witness_tested: false,
    operations: [{
      provider_id: "customer-defined-123", operation_id: "custom.123",
      label: "Update customer", method: "PATCH", path: "/v1/customers/{customer_id}",
      effect: "write", request_content_type: "application/json", required_headers: ["authorization", "content-type"],
      status: "customer_defined", definition_fingerprint: "sha256:" + "b".repeat(64),
      capabilities: {
        customer_reported_receipt: { available: true, evidence_source: "customer_reported" },
        tls_witness: { available: false, evidence_source: "independent_allowly_witness", profile: "customer_held_tlsn_bundle_v1", reason: "online_witness_service_not_configured", api_request_match_verification: "not_performed" },
      },
      allowly_live_tested: false, tls_witness_tested: false,
    }],
    operation_count: 1, enabled_at: "2026-09-28T00:00:00Z", disabled_at: null,
  };
}

const request = {
  name: "Update customer", url: "https://api.example.com/v1/customers/{customer_id}",
  method: "PATCH" as const, requestContentType: "application/json" as const,
  requiredHeaders: ["authorization"],
};

describe("custom executable setup", () => {
  it("serializes only setup fields and preserves exact operation pins and evidence flags", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(responseBody()), { status: 201 }));
    const client = new Allowly({ apiKey: "setup-key", fetch });
    const result = await client.createCustomExecutable(request);
    expect(fetch.mock.calls[0][0]).toBe("https://api.allowly.ai/v1/setup/custom-executables");
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({
      name: request.name, url: request.url, method: "PATCH",
      request_content_type: "application/json", required_headers: ["authorization"],
    });
    expect(result.enabledExecutableId).toBe("exe_custom");
    expect(result.catalogRevision).toBe(responseBody().catalog_revision);
    expect(result.operations[0].definitionFingerprint).toBe("sha256:" + "b".repeat(64));
    expect(result.operations[0].capabilities.tlsWitness).toEqual({
      available: false, evidenceSource: "independent_allowly_witness", profile: "customer_held_tlsn_bundle_v1",
      reason: "online_witness_service_not_configured", apiRequestMatchVerification: "not_performed",
    });
    expect(result.status).toBe("customer_defined");
    expect(result.connectionStatus).toBe("not_verified");
    expect(result.allowlyLiveTested).toBe(false);
    expect(result.tlsWitnessTested).toBe(false);
  });

  it.each([
    { operation_count: 2 },
    { operations: [] },
    { allowly_live_tested: "false" },
    { credential_location: "allowly" },
    { operations: [{ ...responseBody().operations[0], definition_fingerprint: "invalid" }] },
    { operations: [{ ...responseBody().operations[0], provider_id: "another-provider" }] },
    { operations: [{ ...responseBody().operations[0], capabilities: { tls_witness: {} } }] },
  ])("rejects malformed response fields %j", async (override) => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...responseBody(), ...override }), { status: 201 }));
    await expect(new Allowly({ apiKey: "setup-key", fetch }).createCustomExecutable(request))
      .rejects.toBeInstanceOf(AllowlyProtocolError);
  });

  it("propagates setup-key rejection without fallback or retry", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: "setup_key_required", message: "Setup key required" } }), { status: 403 }));
    await expect(new Allowly({ apiKey: "runtime-key", fetch }).createCustomExecutable(request))
      .rejects.toMatchObject({ code: "setup_key_required" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
