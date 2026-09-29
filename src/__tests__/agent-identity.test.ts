import { generateKeyPairSync, verify } from "node:crypto";
import { expect, test } from "vitest";

import { NativeAgentCredential } from "../agent-identity.js";

test("native credential signs a short-lived agent token", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const credential = new NativeAgentCredential({
    version: 1,
    provider: "allowly",
    workspace_id: "ws_123",
    agent_id: "agent_123",
    binding_id: "bind_123",
    key_id: "key_123",
    private_key_jwk: privateKey.export({ format: "jwk" }),
  });
  const [first, second, third] = credential.token().split(".");
  expect(JSON.parse(Buffer.from(first, "base64url").toString())).toEqual({
    alg: "EdDSA", typ: "JWT", kid: "key_123",
  });
  const claims = JSON.parse(Buffer.from(second, "base64url").toString());
  expect(claims).toMatchObject({
    iss: "allowly-agent", aud: "ws_123", sub: "agent_123", bid: "bind_123",
  });
  expect(claims.exp - claims.iat).toBe(60);
  expect(verify(null, Buffer.from(`${first}.${second}`), publicKey, Buffer.from(third, "base64url"))).toBe(true);
});

test("native credential rejects a mismatched private and public key", () => {
  const first = generateKeyPairSync("ed25519");
  const second = generateKeyPairSync("ed25519");
  const jwk = { ...first.privateKey.export({ format: "jwk" }), d: second.privateKey.export({ format: "jwk" }).d };
  expect(() => new NativeAgentCredential({
    version: 1, provider: "allowly", workspace_id: "ws", agent_id: "agent",
    binding_id: "binding", key_id: "key", private_key_jwk: jwk,
  })).toThrow("Invalid Allowly agent credential");
});
