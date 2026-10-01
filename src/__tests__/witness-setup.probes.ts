import { Allowly } from "../index.js";
import type { CustomerHttpOptions } from "../index.js";

const client = new Allowly({ apiKey: "runtime-key" });
const options: CustomerHttpOptions = {
  operationId: "operation-1",
  authorizationId: "auth_1",
  enabledExecutableId: "exe_1",
  catalogOperationId: "vendor.items.list",
  action: "vendor.items.list",
  evidenceMode: "witnessed",
  journalDirectory: "/var/lib/agent/journals",
  witness: { evidenceDirectory: "/var/lib/agent/evidence/operation-1" },
};
void client;
void options;
