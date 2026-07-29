/**
 * Compile-time mirror of the published TypeScript doc snippets
 * (verify.md, sdk/typescript.md, integration.md). `npm run typecheck` is the
 * assertion that the documented shapes match the SDK's real signatures.
 */
import { Allowly, fetchKeysDoc, loadKeysFromJson, verifyReceipt, VerificationError } from "../index.js";

export async function docsVerifySnippet(receiptId: string): Promise<void> {
  const client = new Allowly({ apiKey: "allowly_l1_s001_..." });

  const workspaceId = process.env.ALLOWLY_WORKSPACE_ID!;

  const keysDoc = await fetchKeysDoc(workspaceId);
  const keys = loadKeysFromJson(keysDoc);

  // fetchSigned polls until signed and returns the signed receipt object itself
  const signedReceipt = await client.receipts.fetchSigned(receiptId);

  try {
    await verifyReceipt(signedReceipt, keys, { expectedWorkspaceId: workspaceId });
  } catch (e) {
    if (e instanceof VerificationError) throw new Error(`Invalid receipt: ${e.message}`);
  }

  // sdk/typescript.md custom polling shape
  await client.receipts.fetchSigned(receiptId, { pollInterval: 2, timeout: 180 });
}
