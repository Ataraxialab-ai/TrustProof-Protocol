import { readFileSync } from "node:fs";

import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

import {
  append,
  computeCanonicalEventMaterial,
  computeEntryHash,
  generate,
  verify,
  verifyChain
} from "../src";

type Claims = Record<string, unknown>;

type PemKeyPair = {
  privateKeyPem: string;
  publicKeyPem: string;
};

function readJsonFile<T>(relativePath: string): T {
  const fileUrl = new URL(relativePath, import.meta.url);
  return JSON.parse(readFileSync(fileUrl, "utf8")) as T;
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function assertRecord(value: unknown, message: string): asserts value is Claims {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(message);
  }
}

function getChain(claims: Claims): Claims {
  const chain = claims.chain;
  assertRecord(chain, "Claims must include a chain object.");
  return chain;
}

async function createPemKeyPair(): Promise<PemKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA");

  return {
    privateKeyPem: await exportPKCS8(privateKey),
    publicKeyPem: await exportSPKI(publicKey)
  };
}

function buildDeterministicClaims(
  baseClaims: Claims,
  {
    jti,
    resourceId,
    timestamp
  }: {
    jti: string;
    resourceId: string;
    timestamp: string;
  }
): Claims {
  const claims = deepClone(baseClaims);
  claims.jti = jti;
  claims.timestamp = timestamp;

  assertRecord(claims.resource, "Claims must include a resource object.");
  claims.resource = {
    ...claims.resource,
    id: resourceId
  };

  claims.chain = {
    prev_hash: "0".repeat(64),
    entry_hash: "0".repeat(64)
  };

  const canonicalEventMaterial = computeCanonicalEventMaterial(claims);
  const entryHash = computeEntryHash("0".repeat(64), canonicalEventMaterial);

  claims.chain = {
    prev_hash: "0".repeat(64),
    entry_hash: entryHash
  };

  return claims;
}

function tamperOneBase64UrlCharInSignature(token: string): string {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Token must be compact JWS.");
  }

  const signature = parts[2];
  const index = Math.min(10, signature.length - 1);
  const originalChar = signature[index];
  const replacementChar = originalChar === "a" ? "b" : "a";
  const tamperedSignature =
    signature.slice(0, index) + replacementChar + signature.slice(index + 1);

  return `${parts[0]}.${parts[1]}.${tamperedSignature}`;
}

describe("chain tamper regression suite", () => {
  let keyPair: PemKeyPair;
  let baseAllowClaims: Claims;

  beforeAll(async () => {
    keyPair = await createPemKeyPair();
    baseAllowClaims = readJsonFile<Claims>("../../../spec/examples/allow.json");
  });

  it("happy chain validates for two linked proofs", async () => {
    const claims1 = buildDeterministicClaims(baseAllowClaims, {
      jti: "jti_chain_happy_001",
      resourceId: "po_chain_happy_001",
      timestamp: "2026-02-24T12:10:00Z"
    });

    const claims2 = buildDeterministicClaims(baseAllowClaims, {
      jti: "jti_chain_happy_002",
      resourceId: "po_chain_happy_002",
      timestamp: "2026-02-24T12:11:00Z"
    });

    const token1 = await generate(claims1, keyPair.privateKeyPem);
    const token2 = await append(token1, claims2, keyPair.privateKeyPem);

    const chainResult = await verifyChain([token1, token2], keyPair.publicKeyPem);

    expect(chainResult.ok).toBe(true);
    expect(chainResult.errors).toEqual([]);
  });

  it("fails with INVALID_PROOF when one token byte is tampered", async () => {
    const claims1 = buildDeterministicClaims(baseAllowClaims, {
      jti: "jti_chain_tamper_sig_001",
      resourceId: "po_chain_tamper_sig_001",
      timestamp: "2026-02-24T12:20:00Z"
    });

    const claims2 = buildDeterministicClaims(baseAllowClaims, {
      jti: "jti_chain_tamper_sig_002",
      resourceId: "po_chain_tamper_sig_002",
      timestamp: "2026-02-24T12:21:00Z"
    });

    const token1 = await generate(claims1, keyPair.privateKeyPem);
    const token2 = await append(token1, claims2, keyPair.privateKeyPem);
    const token2Tampered = tamperOneBase64UrlCharInSignature(token2);

    const chainResult = await verifyChain([token1, token2Tampered], keyPair.publicKeyPem);

    expect(chainResult.ok).toBe(false);
    expect(chainResult.errors[0]?.index).toBe(1);
    expect(chainResult.errors[0]?.code).toBe("INVALID_PROOF");
  });

  it("fails with CHAIN_ENTRY_HASH_MISMATCH when prev_hash is altered but entry_hash is not updated", async () => {
    const claims1 = buildDeterministicClaims(baseAllowClaims, {
      jti: "jti_chain_prev_mismatch_001",
      resourceId: "po_chain_prev_mismatch_001",
      timestamp: "2026-02-24T12:30:00Z"
    });

    const claims2 = buildDeterministicClaims(baseAllowClaims, {
      jti: "jti_chain_prev_mismatch_002",
      resourceId: "po_chain_prev_mismatch_002",
      timestamp: "2026-02-24T12:31:00Z"
    });

    const token1 = await generate(claims1, keyPair.privateKeyPem);
    const token2 = await append(token1, claims2, keyPair.privateKeyPem);

    const verifiedToken2 = await verify(token2, keyPair.publicKeyPem);
    expect(verifiedToken2.ok).toBe(true);
    assertRecord(verifiedToken2.claims, "Expected verified claims for token2.");

    const tamperedClaims = deepClone(verifiedToken2.claims);
    const tamperedChain = getChain(tamperedClaims);
    tamperedChain.prev_hash = "f".repeat(64);

    const tamperedToken2 = await generate(tamperedClaims, keyPair.privateKeyPem);
    const chainResult = await verifyChain([token1, tamperedToken2], keyPair.publicKeyPem);

    expect(chainResult.ok).toBe(false);
    expect(chainResult.errors[0]?.index).toBe(1);
    expect(chainResult.errors[0]?.code).toBe("CHAIN_ENTRY_HASH_MISMATCH");
  });

  it("fails with CHAIN_LINK_MISMATCH when prev_hash is altered and entry_hash is recomputed for the wrong link", async () => {
    const claims1 = buildDeterministicClaims(baseAllowClaims, {
      jti: "jti_chain_link_mismatch_001",
      resourceId: "po_chain_link_mismatch_001",
      timestamp: "2026-02-24T12:40:00Z"
    });

    const claims2 = buildDeterministicClaims(baseAllowClaims, {
      jti: "jti_chain_link_mismatch_002",
      resourceId: "po_chain_link_mismatch_002",
      timestamp: "2026-02-24T12:41:00Z"
    });

    const token1 = await generate(claims1, keyPair.privateKeyPem);
    const token2 = await append(token1, claims2, keyPair.privateKeyPem);

    const verifiedToken2 = await verify(token2, keyPair.publicKeyPem);
    expect(verifiedToken2.ok).toBe(true);
    assertRecord(verifiedToken2.claims, "Expected verified claims for token2.");

    const tamperedClaims = deepClone(verifiedToken2.claims);
    const tamperedChain = getChain(tamperedClaims);
    const wrongPrevHash = "f".repeat(64);
    tamperedChain.prev_hash = wrongPrevHash;

    const wrongCanonicalEventMaterial = computeCanonicalEventMaterial(tamperedClaims);
    tamperedChain.entry_hash = computeEntryHash(wrongPrevHash, wrongCanonicalEventMaterial);

    const tamperedToken2 = await generate(tamperedClaims, keyPair.privateKeyPem);
    const chainResult = await verifyChain([token1, tamperedToken2], keyPair.publicKeyPem);

    expect(chainResult.ok).toBe(false);
    expect(chainResult.errors[0]?.index).toBe(1);
    expect(chainResult.errors[0]?.code).toBe("CHAIN_LINK_MISMATCH");
  });

  it("fails with CHAIN_ENTRY_HASH_MISMATCH when entry_hash is replaced", async () => {
    const claims1 = buildDeterministicClaims(baseAllowClaims, {
      jti: "jti_chain_entry_mismatch_001",
      resourceId: "po_chain_entry_mismatch_001",
      timestamp: "2026-02-24T12:50:00Z"
    });

    const claims2 = buildDeterministicClaims(baseAllowClaims, {
      jti: "jti_chain_entry_mismatch_002",
      resourceId: "po_chain_entry_mismatch_002",
      timestamp: "2026-02-24T12:51:00Z"
    });

    const token1 = await generate(claims1, keyPair.privateKeyPem);
    const token2 = await append(token1, claims2, keyPair.privateKeyPem);

    const verifiedToken2 = await verify(token2, keyPair.publicKeyPem);
    expect(verifiedToken2.ok).toBe(true);
    assertRecord(verifiedToken2.claims, "Expected verified claims for token2.");

    const tamperedClaims = deepClone(verifiedToken2.claims);
    const tamperedChain = getChain(tamperedClaims);
    tamperedChain.entry_hash = "0".repeat(64);

    const tamperedToken2 = await generate(tamperedClaims, keyPair.privateKeyPem);
    const chainResult = await verifyChain([token1, tamperedToken2], keyPair.publicKeyPem);

    expect(chainResult.ok).toBe(false);
    expect(chainResult.errors[0]?.index).toBe(1);
    expect(chainResult.errors[0]?.code).toBe("CHAIN_ENTRY_HASH_MISMATCH");
  });
});
