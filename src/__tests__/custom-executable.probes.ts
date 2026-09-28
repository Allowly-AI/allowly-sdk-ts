import { Allowly } from "../index.js";
import type { CustomExecutableCreateRequest, EnabledExecutableResponse } from "../index.js";

const setupClient = new Allowly({ apiKey: "allowly-setup-key" });
const request = {
  name: "Update customer", url: "https://api.example.com/v1/customers/{customer_id}",
  method: "PATCH", requestContentType: "application/json", requiredHeaders: ["authorization"],
} satisfies CustomExecutableCreateRequest;
const created: Promise<EnabledExecutableResponse> = setupClient.createCustomExecutable(request);
void created;
