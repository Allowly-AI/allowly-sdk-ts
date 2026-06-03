import {
  canonicalize,
  type KeyDocument,
  loadKeysFromJson,
  VerificationError,
  verifyReceipt,
} from "./_verifier.js";

/**
 * Offline Ed25519 receipt verification.
 *
 * No network call needed — fetch the workspace public keys once, cache them,
 * verify locally forever.
 *
 *   import { verifyReceipt, loadKeysFromJson } from "@allowly/sdk/verify";
 *
 *   const keysDoc = await fetchKeysDoc(workspaceId);
 *   const keys = loadKeysFromJson(keysDoc);
 *   await verifyReceipt(signedReceipt, keys); // throws VerificationError if invalid
 */
export {
  canonicalize,
  loadKeysFromJson,
  VerificationError,
  verifyReceipt,
} from "./_verifier.js";

export type {
  PublicKey,
  Receipt,
  KeyDocument,
} from "./_verifier.js";

export interface FetchKeysDocOptions {
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
  cacheTtlMs?: number;
  expectedSha256?: string;
}

const DEFAULT_BASE_URL = "https://api.allowly.ai";
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
const _keysDocCache = new Map<string, { expiresAt: number; doc: KeyDocument }>();

export async function fetchKeysDoc(
  workspaceId: string,
  opts: FetchKeysDocOptions = {},
): Promise<KeyDocument> {
  const baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
  const url = `${baseUrl}/v1/workspaces/${workspaceId}/keys`;
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new VerificationError(`keys document URL must use HTTPS: ${url}`);
  }

  const ttlMs = opts.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  const cacheKey = `${url}|${opts.expectedSha256 ?? ""}|${ttlMs}`;
  const cached = _keysDocCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return structuredClone(cached.doc);
  }

  const fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const res = await fetchImpl(url);
  if (!res.ok) {
    throw new VerificationError(`failed to fetch keys document: HTTP ${res.status}`);
  }
  const text = await res.text();
  if (opts.expectedSha256) {
    const digest = await sha256Hex(text);
    if (digest.toLowerCase() !== opts.expectedSha256.toLowerCase()) {
      throw new VerificationError("keys document SHA-256 hash did not match expected pin");
    }
  }

  let doc: KeyDocument;
  try {
    doc = JSON.parse(text) as KeyDocument;
  } catch {
    throw new VerificationError("keys document was not valid JSON");
  }
  if (doc.workspace_id !== workspaceId) {
    throw new VerificationError(
      `keys document workspace_id mismatch: got ${JSON.stringify(doc.workspace_id)}, want ${JSON.stringify(workspaceId)}`,
    );
  }
  loadKeysFromJson(doc);
  _keysDocCache.set(cacheKey, { expiresAt: Date.now() + ttlMs, doc });
  return structuredClone(doc);
}

export function clearKeysDocCache(): void {
  _keysDocCache.clear();
}

async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
