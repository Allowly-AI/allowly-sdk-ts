import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { decodeReceipt, jwsReceipt, jwsSigningInput } from "@allowly/verifier";

/** Synthetic evidence only. The envelope is kept separate from decoded claims. */
export function signedReceipt(claims: Record<string, unknown>, key?: KeyObject) {
  const { alg: _, key_id: keyId = "test-key/v1", signature: __, ...fields } = claims;
  const payload = {
    schema_version: "5", receipt_id: "rcp_test", workspace_id: "ws_test",
    issued_at: "2026-04-21T14:32:17.482Z", decision: "allow",
    reason: "authorization_granted_action_active", user_id: "allowly:seal",
    agent_id: "allowly.seal", action: "record.seal", resource: null,
    context: {}, authorization_id: "auth_seal", engine_version: "sha256:" + "a".repeat(64),
    policy_ref: { policy_id: "pol_fixture", policy_version: 1, definition_sha256: "b".repeat(64) },
    ...fields,
  };
  const privateKey = key ?? generateKeyPairSync("ed25519").privateKey;
  return { ...jwsReceipt(payload, String(keyId), sign(null, jwsSigningInput(payload, String(keyId)), privateKey)) };
}

/** Alters signed bytes without re-signing, to check rejection. */
export function changedReceipt(receipt: Record<string, unknown>, fields: Record<string, unknown>) {
  return { ...receipt, payload: Buffer.from(JSON.stringify({ ...decodeReceipt(receipt), ...fields })).toString("base64url") };
}
