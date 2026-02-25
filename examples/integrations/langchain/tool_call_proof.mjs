import { createRequire } from "node:module";

import { verify, verifyChain, wrapToolWithTrustProof } from "../../../packages/js/dist/index.js";

const requireFromSdk = createRequire(new URL("../../../packages/js/package.json", import.meta.url));
const { DynamicTool } = requireFromSdk("@langchain/core/tools");
const { exportPKCS8, exportSPKI, generateKeyPair } = requireFromSdk("jose");

const { publicKey, privateKey } = await generateKeyPair("EdDSA");
const privateKeyPem = await exportPKCS8(privateKey);
const publicKeyPem = await exportSPKI(publicKey);

const fxConvert = new DynamicTool({
  name: "fx_convert",
  description: "Converts a USD amount string into integer cents in EUR (demo only).",
  func: async (input) => {
    const amount = Number.parseFloat(input);
    if (!Number.isFinite(amount)) {
      return { error: "invalid_amount", input };
    }

    return {
      amount_cents: Math.round(amount * 100),
      currency: "EUR"
    };
  }
});

const wrappedTool = wrapToolWithTrustProof(fxConvert, {
  privateKeyPem,
  subject: { type: "agent", id: "agent_demo_1" },
  action: "tool.fx_convert",
  resource: { type: "tool", id: "fx_convert" },
  policy: { policy_v: "v0", scopes: ["tools:invoke"], constraints: {} },
  decision: "allow",
  reasonCodes: ["demo_execution"],
  chain: { enabled: true }
});

const firstCall = await wrappedTool.invoke("12.34");
const secondCall = await wrappedTool.invoke("20.50");

const verifyFirst = await verify(firstCall.proof_jwt, publicKeyPem);
const verifySecond = await verify(secondCall.proof_jwt, publicKeyPem);
const chainResult = await verifyChain([firstCall.proof_jwt, secondCall.proof_jwt], publicKeyPem);

const linked = firstCall.claims.chain.entry_hash === secondCall.claims.chain.prev_hash;

console.log("first output:", JSON.stringify(firstCall.output));
console.log("first proof_jwt:", `${firstCall.proof_jwt.slice(0, 60)}...`);
console.log("first verify ok:", verifyFirst.ok);
console.log("second output:", JSON.stringify(secondCall.output));
console.log("second proof_jwt:", `${secondCall.proof_jwt.slice(0, 60)}...`);
console.log("second verify ok:", verifySecond.ok);
console.log("chain linked:", linked);
console.log("verifyChain ok:", chainResult.ok);

if (!verifyFirst.ok || !verifySecond.ok || !linked || !chainResult.ok) {
  process.exitCode = 1;
}
