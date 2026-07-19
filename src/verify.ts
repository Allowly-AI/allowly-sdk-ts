import {
  canonicalize,
  type KeyDocument,
  loadKeysFromJson,
  type PublicKey,
  VerificationError,
  verifyReceipt as verifyReceiptReference,
} from "@allowly/verifier";

export {
  canonicalize,
  loadKeysFromJson,
  VerificationError,
};

export type {
  PublicKey,
  Receipt,
  KeyDocument,
} from "@allowly/verifier";

export interface FetchKeysDocOptions {
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
  cacheTtlMs?: number;
  expectedSha256?: string;
  timeoutMs?: number;
}

const DEFAULT_BASE_URL = "https://api.allowly.ai";
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 10_000;
const _keysDocCache = new Map<string, { expiresAt: number; doc: KeyDocument }>();

export async function fetchKeysDoc(
  workspaceId: string,
  opts: FetchKeysDocOptions = {},
): Promise<KeyDocument> {
  const baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
  const url = `${baseUrl}/v1/workspaces/${encodeURIComponent(workspaceId)}/keys`;
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new VerificationError(`keys document URL must use HTTPS: ${url}`);
  }
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (timeoutMs <= 0) throw new VerificationError("timeoutMs must be positive");

  const ttlMs = opts.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  const cacheKey = `${url}|${opts.expectedSha256 ?? ""}|${ttlMs}`;
  const cached = _keysDocCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return structuredClone(cached.doc);
  }

  const fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) {
    throw new VerificationError(`failed to fetch keys document: HTTP ${res.status}`);
  }
  const bytes = new Uint8Array(await res.arrayBuffer());
  if (opts.expectedSha256) {
    const digest = await sha256Hex(bytes);
    if (digest.toLowerCase() !== opts.expectedSha256.toLowerCase()) {
      throw new VerificationError("keys document SHA-256 hash did not match expected pin");
    }
  }

  let doc: KeyDocument;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
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

export async function verifyReceipt(
  receipt: Record<string, unknown>,
  publicKeys: PublicKey[],
  opts: { expectedWorkspaceId: string; now?: Date },
): Promise<void> {
  return verifyReceiptReference(receipt, publicKeys, opts);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
