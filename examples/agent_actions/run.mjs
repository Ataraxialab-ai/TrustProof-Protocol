import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";

import {
  append,
  canonicalJson,
  computeCanonicalEventMaterial,
  computeEntryHash,
  generate,
  sha256Hex,
  verify,
  verifyChain
} from "../../packages/js/dist/index.js";

const GENESIS_PREV_HASH = "0".repeat(64);

function loadActions() {
  const fileUrl = new URL("./actions.json", import.meta.url);
  return JSON.parse(readFileSync(fileUrl, "utf8"));
}

function buildClaims({ subject, policy, action }) {
  const hashes = {
    input_hash: sha256Hex(canonicalJson(action.input)),
    output_hash: sha256Hex(canonicalJson(action.output))
  };

  const claims = {
    subject,
    action: `agent.tool.${action.tool_name}`,
    resource: {
      type: "tool",
      id: action.tool_name
    },
    policy,
    result: {
      decision: "allow",
      reason_codes: ["tool_call_ok"]
    },
    hashes,
    timestamp: action.timestamp,
    jti: action.jti,
    chain: {
      prev_hash: GENESIS_PREV_HASH,
      entry_hash: GENESIS_PREV_HASH
    }
  };

  const canonicalEventMaterial = computeCanonicalEventMaterial(claims);
  claims.chain.entry_hash = computeEntryHash(claims.chain.prev_hash, canonicalEventMaterial);

  return claims;
}

function tamperOneChar(token) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Expected compact JWT.");
  }

  const signature = parts[2];
  const index = Math.min(10, signature.length - 1);
  const replacement = signature[index] === "a" ? "b" : "a";
  parts[2] = `${signature.slice(0, index)}${replacement}${signature.slice(index + 1)}`;

  return parts.join(".");
}

function verifySummaryLine(name, verifyResult) {
  return verifyResult.ok ? `✅ Verified ${name}` : `❌ Not Verified ${name}`;
}

async function main() {
  const actionsDoc = loadActions();

  const { publicKey, privateKey } = await generateKeyPair("EdDSA");
  const privateKeyPem = await exportPKCS8(privateKey);
  const publicKeyPem = await exportSPKI(publicKey);

  const action1 = actionsDoc.actions[0];
  const action2 = actionsDoc.actions[1];

  const claims1 = buildClaims({
    subject: actionsDoc.subject,
    policy: actionsDoc.policy,
    action: action1
  });
  const proof1 = await generate(claims1, privateKeyPem);
  const verify1 = await verify(proof1, publicKeyPem);

  const claims2 = buildClaims({
    subject: actionsDoc.subject,
    policy: actionsDoc.policy,
    action: action2
  });
  const proof2 = await append(proof1, claims2, privateKeyPem);
  const verify2 = await verify(proof2, publicKeyPem);

  const chainResult = await verifyChain([proof1, proof2], publicKeyPem);

  const tamperedProof2 = tamperOneChar(proof2);
  const tamperedChainResult = await verifyChain([proof1, tamperedProof2], publicKeyPem);

  const proofs = [
    {
      name: action1.name,
      jwt: proof1,
      claims: verify1.claims ?? claims1,
      verify_result: {
        ok: verify1.ok,
        errors: verify1.errors
      }
    },
    {
      name: action2.name,
      jwt: proof2,
      claims: verify2.claims ?? claims2,
      verify_result: {
        ok: verify2.ok,
        errors: verify2.errors
      }
    }
  ];

  const summaryLines = [
    "TrustProof Example: agent_actions",
    "",
    "Simulated tool calls:",
    "- payout.quote",
    "- payout.initiate",
    "",
    verifySummaryLine(action1.name, verify1),
    `  action=${claims1.action} resource=${claims1.resource.id} jti=${claims1.jti}`,
    verifySummaryLine(action2.name, verify2),
    `  action=${claims2.action} resource=${claims2.resource.id} jti=${claims2.jti}`,
    "",
    chainResult.ok
      ? "✅ Verified chain agent_tool_quote -> agent_tool_initiate"
      : "❌ Chain failed agent_tool_quote -> agent_tool_initiate",
    !tamperedChainResult.ok
      ? "✅ Tamper => OK (failed as expected)"
      : "❌ Tamper => FAIL (unexpectedly verified)",
    `  tamper_error=${tamperedChainResult.errors[0]?.code ?? "NONE"}`
  ];

  const outputDir = new URL("../output/agent_actions/", import.meta.url);
  mkdirSync(outputDir, { recursive: true });

  writeFileSync(new URL("./proofs.json", outputDir), `${JSON.stringify(proofs, null, 2)}\n`, "utf8");
  writeFileSync(new URL("./summary.txt", outputDir), `${summaryLines.join("\n")}\n`, "utf8");

  console.log(summaryLines.join("\n"));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
