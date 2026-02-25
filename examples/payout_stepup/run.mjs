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

function loadScenario() {
  const fileUrl = new URL("./scenario.json", import.meta.url);
  return JSON.parse(readFileSync(fileUrl, "utf8"));
}

function buildClaims({ subject, policy, caseData }) {
  const hashes = {
    input_hash: sha256Hex(canonicalJson(caseData.input)),
    output_hash: sha256Hex(canonicalJson(caseData.output))
  };

  const claims = {
    subject,
    action: "payout.initiate",
    resource: {
      type: "payout",
      id: caseData.resource_id
    },
    policy,
    result: caseData.result,
    hashes,
    timestamp: caseData.timestamp,
    jti: caseData.jti,
    chain: {
      prev_hash: GENESIS_PREV_HASH,
      entry_hash: GENESIS_PREV_HASH
    }
  };

  const canonicalEventMaterial = computeCanonicalEventMaterial(claims);
  claims.chain.entry_hash = computeEntryHash(claims.chain.prev_hash, canonicalEventMaterial);

  return claims;
}

function buildStepUpApprovalClaims({ subject, policy }) {
  const input = {
    step_up_for_jti: "demo_payout_stepup",
    factor: "mfa"
  };
  const output = {
    status: "approved",
    approved_by: "user_001"
  };

  return {
    subject,
    action: "payout.step_up.approve",
    resource: {
      type: "payout",
      id: "po_demo_2"
    },
    policy,
    result: {
      decision: "allow",
      reason_codes: ["step_up_approved"]
    },
    hashes: {
      input_hash: sha256Hex(canonicalJson(input)),
      output_hash: sha256Hex(canonicalJson(output))
    },
    timestamp: "2026-02-24T12:00:20Z",
    jti: "demo_payout_stepup_approved",
    chain: {
      prev_hash: GENESIS_PREV_HASH,
      entry_hash: GENESIS_PREV_HASH
    }
  };
}

function verifySummaryLine(name, verifyResult) {
  return verifyResult.ok ? `✅ Verified ${name}` : `❌ Not Verified ${name}`;
}

async function main() {
  const scenario = loadScenario();

  const { publicKey, privateKey } = await generateKeyPair("EdDSA");
  const privateKeyPem = await exportPKCS8(privateKey);
  const publicKeyPem = await exportSPKI(publicKey);

  const proofs = [];
  const summaryLines = [
    "TrustProof Example: payout_stepup",
    "",
    "Cases:",
    "- payout 25.00 USD to m_alpha => allow",
    "- payout 7500.00 USD to m_alpha => step_up",
    ""
  ];

  let stepUpProofJwt = null;

  for (const caseData of scenario.cases) {
    const claims = buildClaims({
      subject: scenario.subject,
      policy: scenario.policy,
      caseData
    });

    const jwt = await generate(claims, privateKeyPem);
    const verifyResult = await verify(jwt, publicKeyPem);

    proofs.push({
      name: caseData.name,
      jwt,
      claims: verifyResult.claims ?? claims,
      verify_result: {
        ok: verifyResult.ok,
        errors: verifyResult.errors
      }
    });

    summaryLines.push(
      verifySummaryLine(caseData.name, verifyResult),
      `  action=${claims.action} decision=${claims.result.decision} jti=${claims.jti}`
    );

    if (caseData.name === "payout_stepup") {
      stepUpProofJwt = jwt;
    }
  }

  if (!stepUpProofJwt) {
    throw new Error("Missing payout_stepup proof; cannot append step-up approval proof.");
  }

  const approvalClaims = buildStepUpApprovalClaims({
    subject: scenario.subject,
    policy: scenario.policy
  });

  const approvalJwt = await append(stepUpProofJwt, approvalClaims, privateKeyPem);
  const approvalVerify = await verify(approvalJwt, publicKeyPem);
  const stepUpChainVerify = await verifyChain([stepUpProofJwt, approvalJwt], publicKeyPem);

  proofs.push({
    name: "payout_stepup_approved",
    jwt: approvalJwt,
    claims: approvalVerify.claims ?? approvalClaims,
    verify_result: {
      ok: approvalVerify.ok,
      errors: approvalVerify.errors
    }
  });

  summaryLines.push(
    verifySummaryLine("payout_stepup_approved", approvalVerify),
    `  action=${approvalClaims.action} decision=${approvalClaims.result.decision} jti=${approvalClaims.jti}`,
    "",
    stepUpChainVerify.ok
      ? "✅ Verified chain payout_stepup -> payout_stepup_approved"
      : "❌ Chain failed payout_stepup -> payout_stepup_approved"
  );

  const outputDir = new URL("../output/payout_stepup/", import.meta.url);
  mkdirSync(outputDir, { recursive: true });

  writeFileSync(new URL("./proofs.json", outputDir), `${JSON.stringify(proofs, null, 2)}\n`, "utf8");
  writeFileSync(new URL("./summary.txt", outputDir), `${summaryLines.join("\n")}\n`, "utf8");

  console.log(summaryLines.join("\n"));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
