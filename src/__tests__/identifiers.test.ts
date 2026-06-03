import { describe, expect, it } from "vitest";
import { identifiers } from "../index.js";

describe("identifiers", () => {
  it("normalizes email with trim and lowercase only", () => {
    expect(identifiers.normalizeEmail(" John.Doe@Example.COM ")).toBe("john.doe@example.com");
    expect(identifiers.normalizeEmail("j.o.h.n+sales@gmail.com")).toBe("j.o.h.n+sales@gmail.com");
  });

  it("returns a versioned HMAC identifier", () => {
    expect(identifiers.fromEmail(" John.Doe@Example.COM ", { pepper: "pepper-secret" })).toBe(
      "email_hmac:v1:joGNnOl733jVwFo68Eh9yBii-N5CkEOwKDyTFZTKpVI",
    );
  });

  it("accepts a byte pepper", () => {
    const pepper = new TextEncoder().encode("pepper");
    expect(identifiers.fromEmail("user@example.com", { pepper })).toMatch(/^email_hmac:v1:/);
  });

  it("requires a permanent pepper", () => {
    expect(() => identifiers.fromEmail("user@example.com", { pepper: "" })).toThrow("pepper");
  });

  it("rejects an empty email", () => {
    expect(() => identifiers.fromEmail("  ", { pepper: "pepper" })).toThrow("email");
  });

  it("rejects an unsupported version", () => {
    expect(() =>
      identifiers.fromEmail("user@example.com", { pepper: "pepper", version: "v2" as "v1" }),
    ).toThrow("version");
  });
});
