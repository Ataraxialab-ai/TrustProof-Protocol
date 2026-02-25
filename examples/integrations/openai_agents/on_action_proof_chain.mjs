import { createRequire } from "node:module";

import {
  createTrustProofAgentHook,
  verify,
  verifyChain
} from "../../../packages/js/dist/index.js";

const requireFromSdk = createRequire(new URL("../../../packages/js/package.json", import.meta.url));
const { exportPKCS8, exportSPKI, generateKeyPair } = requireFromSdk("jose");

const { privateKey, publicKey } = await generateKeyPair("EdDSA");
const privateKeyPem = await exportPKCS8(privateKey);
const publicKeyPem = await exportSPKI(publicKey);

const hook = createTrustProofAgentHook({
  privateKeyPem,
  subject: { type: "agent", id: "agent_demo_1", parent: { humanId: "user_demo_1" } },
  policy: {
    policy_v: "v0",
    scopes: ["tools:invoke"],
    constraints: {}
  },
  chain: { enabled: true }
});

const event1 = {
  tool_name: "payout.quote",
  input: { amount_cents: 125000, currency: "USD", destination: "acct_001" },
  output: { quote_id: "qt_001", fee_cents: 250, total_cents: 125250, currency: "USD" },
  resource: { type: "payout", id: "po_demo_001" },
  decision: "allow",
  reason_codes: ["within_policy"],
  timestamp: "2026-02-25T16:00:00Z"
};

const event2 = {
  tool_name: "payout.initiate",
  input: { quote_id: "qt_001", amount_cents: 125000, currency: "USD" },
  output: { payout_id: "po_demo_001", status: "queued" },
  resource: { type: "payout", id: "po_demo_001" },
  decision: "allow",
  reason_codes: ["quote_valid", "risk_checks_passed"],
  timestamp: "2026-02-25T16:00:05Z"
};

const proof1 = await hook.onToolEnd(event1);
const proof2 = await hook.onToolEnd(event2);

const verify1 = await verify(proof1.proof_jwt, publicKeyPem);
const verify2 = await verify(proof2.proof_jwt, publicKeyPem);
const chain = verifyChain([proof1.proof_jwt, proof2.proof_jwt], publicKeyPem);

console.log("event1 output:", JSON.stringify(event1.output));
console.log("proof1 prefix:", `${proof1.proof_jwt.slice(0, 60)}...`);
console.log("verify proof1 ok:", verify1.ok);
console.log("event2 output:", JSON.stringify(event2.output));
console.log("proof2 prefix:", `${proof2.proof_jwt.slice(0, 60)}...`);
console.log("verify proof2 ok:", verify2.ok);
console.log("action1:", proof1.claims.action);
console.log("action2:", proof2.claims.action);
console.log("verifyChain ok:", (await chain).ok);
