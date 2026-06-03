import { createHmac } from "node:crypto";

const EMAIL_HMAC_VERSION = "v1";
const EMAIL_HMAC_PREFIX = "email_hmac";

export interface FromEmailOptions {
  pepper: string | Uint8Array;
  version?: typeof EMAIL_HMAC_VERSION;
}

export function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (!normalized) {
    throw new Error("email must not be empty");
  }
  return normalized;
}

export function fromEmail(email: string, options: FromEmailOptions): string {
  const version = options.version ?? EMAIL_HMAC_VERSION;
  if (version !== EMAIL_HMAC_VERSION) {
    throw new Error("unsupported email identifier version");
  }

  const pepper = pepperBytes(options.pepper);
  const digest = createHmac("sha256", pepper)
    .update(normalizeEmail(email), "utf8")
    .digest("base64url");
  return `${EMAIL_HMAC_PREFIX}:${version}:${digest}`;
}

function pepperBytes(pepper: string | Uint8Array): string | Uint8Array {
  if (typeof pepper === "string") {
    if (!pepper) {
      throw new Error("pepper must not be empty");
    }
    return pepper;
  }
  if (pepper.byteLength === 0) {
    throw new Error("pepper must not be empty");
  }
  return pepper;
}
