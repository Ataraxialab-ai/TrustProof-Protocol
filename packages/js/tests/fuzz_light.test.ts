import { readFileSync } from "node:fs";

import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

import { generate, verify, verifyChain } from "../src";

type Claims = Record<string, unknown>;

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function loadAllowClaims(): Claims {
  const fileUrl = new URL("../../../spec/examples/allow.json", import.meta.url);
  return JSON.parse(readFileSync(fileUrl, "utf8")) as Claims;
}

function createLargeValidClaims(baseClaims: Claims): Claims {
  const claims = deepClone(baseClaims);

  const subject =
    claims.subject && typeof claims.subject === "object" && !Array.isArray(claims.subject)
      ? (claims.subject as Claims)
      : {};
  claims.subject = {
    ...subject,
    id: "a".repeat(10_000)
  };

  const resource =
    claims.resource && typeof claims.resource === "object" && !Array.isArray(claims.resource)
      ? (claims.resource as Claims)
      : {};
  claims.resource = {
    ...resource,
    id: "x".repeat(20_000)
  };

  const policy =
    claims.policy && typeof claims.policy === "object" && !Array.isArray(claims.policy)
      ? (claims.policy as Claims)
      : {};
  claims.policy = {
    ...policy,
    scopes: Array.from({ length: 200 }, (_, i) => `scope:${i}`)
  };

  const result =
    claims.result && typeof claims.result === "object" && !Array.isArray(claims.result)
      ? (claims.result as Claims)
      : {};
  claims.result = {
    ...result,
    reason_codes: Array.from({ length: 200 }, (_, i) => `reason_${i}`)
  };

  return claims;
}

describe("fuzz-light: weird sizes and malformed tokens", () => {
  let privateKeyPem: string;
  let publicKeyPem: string;
  let baseClaims: Claims;
  let validToken: string;

  beforeAll(async () => {
    baseClaims = loadAllowClaims();

    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    privateKeyPem = await exportPKCS8(privateKey);
    publicKeyPem = await exportSPKI(publicKey);

    validToken = await generate(baseClaims, privateKeyPem);
  });

  it("throws for schema-invalid claims (additionalProperties and missing required fields)", async () => {
    const invalidExtraField = deepClone(baseClaims);
    invalidExtraField.input = {
      oversized_blob: "z".repeat(4096),
      nested: Array.from({ length: 200 }, (_, i) => ({ id: i, value: `v_${i}` }))
    };

    await expect(generate(invalidExtraField, privateKeyPem)).rejects.toThrow(
      "Invalid TrustProof envelope"
    );

    const missingRequired = deepClone(baseClaims);
    missingRequired.action = undefined;

    await expect(generate(missingRequired, privateKeyPem)).rejects.toThrow(
      "Invalid TrustProof envelope"
    );
  });

  it("handles large but schema-valid claims without crashing", async () => {
    const largeClaims = createLargeValidClaims(baseClaims);
    const token = await generate(largeClaims, privateKeyPem);

    const verifyResult = await verify(token, publicKeyPem);

    expect(typeof verifyResult.ok).toBe("boolean");
    expect(Array.isArray(verifyResult.errors)).toBe(true);
    if (verifyResult.ok) {
      expect(verifyResult.errors).toEqual([]);
    } else {
      expect(verifyResult.errors.length).toBeGreaterThan(0);
    }
  });

  it("returns structured errors for malformed JWT tokens without throwing", async () => {
    const malformedTokens = [
      "",
      "abc",
      "a.b",
      "a.b.c",
      "....",
      `${validToken.split(".").slice(0, 2).join(".")}.`,
      "a.b.c$"
    ];

    for (const token of malformedTokens) {
      const result = await verify(token, publicKeyPem);
      expect(result.ok).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]?.code).toBe("INVALID_SIGNATURE");
    }
  });

  it("verifyChain empty list returns ok=true (vacuous chain)", async () => {
    const result = await verifyChain([], publicKeyPem);
    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("verifyChain reports index on invalid token", async () => {
    const result = await verifyChain(["a.b.c"], publicKeyPem);
    expect(result.ok).toBe(false);
    expect(result.errors[0]?.code).toBe("INVALID_PROOF");
    expect(result.errors[0]?.index).toBe(0);
  });

  it("verifyChain fails on mixed valid+malformed tokens without throwing", async () => {
    const result = await verifyChain([validToken, "a.b.c"], publicKeyPem);
    expect(result.ok).toBe(false);
    expect(result.errors[0]?.code).toBe("INVALID_PROOF");
    expect(result.errors[0]?.index).toBe(1);
  });
});
