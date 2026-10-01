import { createPrivateKey, createPublicKey, sign, type JsonWebKey } from "node:crypto";
import { readFile } from "node:fs/promises";

export interface NativeAgentCredentialData {
  version: 1;
  provider: "allowly";
  workspace_id: string;
  agent_id: string;
  binding_id: string;
  key_id: string;
  private_key_jwk: JsonWebKey;
}

function encoded(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

/** Signs short-lived tokens for Allowly-native agent identity. */
export class NativeAgentCredential {
  private readonly key: ReturnType<typeof createPrivateKey>;
  private readonly data: NativeAgentCredentialData;

  constructor(value: NativeAgentCredentialData) {
    if (value.version !== 1 || value.provider !== "allowly"
        || !value.workspace_id || !value.agent_id || !value.binding_id || !value.key_id
        || value.private_key_jwk?.kty !== "OKP" || value.private_key_jwk.crv !== "Ed25519"
        || !value.private_key_jwk.x || !value.private_key_jwk.d) {
      throw new Error("Invalid Allowly agent credential");
    }
    this.key = createPrivateKey({ key: value.private_key_jwk, format: "jwk" });
    const publicJwk = createPublicKey(this.key).export({ format: "jwk" });
    if (publicJwk.x !== value.private_key_jwk.x) throw new Error("Invalid Allowly agent credential");
    this.data = value;
  }

  static fromJson(value: string): NativeAgentCredential {
    return new NativeAgentCredential(JSON.parse(value) as NativeAgentCredentialData);
  }

  static async fromFile(path: string): Promise<NativeAgentCredential> {
    return NativeAgentCredential.fromJson(await readFile(path, "utf8"));
  }

  token = (): string => {
    const now = Math.floor(Date.now() / 1000);
    const header = encoded(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: this.data.key_id }));
    const payload = encoded(JSON.stringify({
      iss: "allowly-agent",
      aud: this.data.workspace_id,
      sub: this.data.agent_id,
      bid: this.data.binding_id,
      iat: now,
      nbf: now,
      exp: now + 60,
    }));
    const input = `${header}.${payload}`;
    return `${input}.${encoded(sign(null, Buffer.from(input, "ascii"), this.key))}`;
  };
}
