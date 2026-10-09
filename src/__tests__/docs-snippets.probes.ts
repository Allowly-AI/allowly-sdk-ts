/**
 * Compile-time mirror of the published TypeScript doc snippets
 * (verify.md, sdk/typescript.md, integration.md). `npm run typecheck` is the
 * assertion that the documented shapes match the SDK's real signatures.
 */
import { Allowly, fetchKeysDoc, loadKeysFromJson, SealWebhookClient, verifyReceipt, VerificationError, verifyResolutionWebhook } from "../index.js";
import type { ConfirmationStatus, EscalationStatus, PromptStatus, ConfirmationAuthorityStatus, EscalationAuthorityStatus } from "../index.js";

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

export async function docsConfirmationSnippet(nonce: string, approved: boolean): Promise<void> {
  const client = new Allowly({ apiKey: "allowly_l1_s001_..." });
  const resolution = await client.confirmations.approve(nonce, { approved, idempotencyKey: "confirmation-1" });
  if (resolution.decision === "approved") {
    const childAuthorizationId: string = resolution.authorizationId;
    void childAuthorizationId;
  } else {
    const childAuthorizationId: null = resolution.authorizationId;
    const declined: "not_approved" | "denied_by_user" = resolution.decision;
    void childAuthorizationId;
    void declined;
  }
  if (resolution.receipt) await client.receipts.fetchSigned(resolution.receipt.receiptId);
}

export async function docsPromptStatusSnippet(confirmationId: string, escalationId: string): Promise<void> {
  const client = new Allowly({ apiKey: "allowly_l1_s001_..." });
  const confirmation: ConfirmationStatus = await client.confirmations.get(confirmationId);
  const escalation: EscalationStatus = await client.escalations.get(escalationId);
  const choice: PromptStatus = confirmation.status;
  const confirmationAuthority: ConfirmationAuthorityStatus = confirmation.authorityStatus;
  const escalationAuthority: EscalationAuthorityStatus = escalation.authorityStatus;
  const child: string | null = confirmation.childAuthorizationId;
  const consumedAt: string | null = escalation.consumedAt;
  console.log(choice, confirmationAuthority, escalationAuthority, child, consumedAt);

  const checked = await client.check({ authorizationId: confirmation.authorizationId, actions: [confirmation.action] });
  const result = checked.results[confirmation.action];
  if (result.decision === "confirm" && result.confirmationId) {
    await client.confirmations.get(result.confirmationId);
  }
}

export async function docsResolutionWebhookSnippet(rawBody: Uint8Array, requestHeaders: Record<string, string>): Promise<void> {
  const setup = new Allowly({ apiKey: process.env.ALLOWLY_SETUP_KEY! });
  const configured = await setup.resolutionWebhook.configure("https://customer.example/allowly-resolution");
  const signingSecret: string = configured.signingSecret;
  const current = await setup.resolutionWebhook.get();
  const recent = await setup.resolutionWebhook.deliveries();
  const rotated = await setup.resolutionWebhook.rotate();
  const disabled = await setup.resolutionWebhook.disable();
  const event = verifyResolutionWebhook(rawBody, requestHeaders, {
    signingSecret: process.env.ALLOWLY_RESOLUTION_SIGNING_SECRET!,
    expectedWorkspaceId: process.env.ALLOWLY_WORKSPACE_ID!,
  });
  const workspaceId: string = event.workspaceId;
  const sourceReceiptId: string | null = event.data.sourceReceiptId;
  const resolutionReceiptId: string = event.data.resolutionReceiptId;
  const choice: "approved" | "rejected" = event.data.status;
  void [signingSecret, current, recent, rotated, disabled, workspaceId, sourceReceiptId, resolutionReceiptId, choice];
  // @ts-expect-error get() does not return a signing secret.
  void current.signingSecret;
  // @ts-expect-error Verification requires bytes, never already-parsed JSON.
  verifyResolutionWebhook("{}", requestHeaders, { signingSecret, expectedWorkspaceId: workspaceId });
}

export async function docsSealWebhookSnippet(rawJson: string, eventId: string): Promise<void> {
  const webhook = new SealWebhookClient(process.env.ALLOWLY_SEAL_WEBHOOK_URL!);
  let delivery = await webhook.send(rawJson, {
    idempotencyKey: eventId,
    type: "invoice",
    reference: "INV-1042",
    statement: "Approved for payment",
  });
  while (delivery.status === "received" || delivery.status === "signing") {
    delivery = await webhook.getDelivery(delivery.attemptId);
  }
  if (delivery.status !== "sealed") throw new Error(delivery.errorCode ?? "SEAL failed");
  await webhook.getReceipt(delivery.receiptId!);
  await webhook.getKeys();
}
