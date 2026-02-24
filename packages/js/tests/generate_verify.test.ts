import { readFileSync } from "node:fs";

import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

import { generate, validateEnvelopeSchema, verify } from "../src";

type PemKeyPair = {
  privateKeyPem: string;
  publicKeyPem: string;
};

type AllowVector = {
  input: unknown;
  output: unknown;
};

// Quick demo (local):
// node --input-type=module -e 'import {generateKeyPairSync} from "node:crypto";import {readFileSync} from "node:fs";import {generate,verify} from "./packages/js/dist/index.js";const c=JSON.parse(readFileSync("./spec/examples/allow.json","utf8"));const {privateKey,publicKey}=generateKeyPairSync("ed25519");const p8=privateKey.export({format:"pem",type:"pkcs8"}).toString();const spki=publicKey.export({format:"pem",type:"spki"}).toString();const t=await generate(c,p8);console.log(await verify(t,spki));'

function readJsonFile<T>(relativePath: string): T {
  const fileUrl = new URL(relativePath, import.meta.url);
  return JSON.parse(readFileSync(fileUrl, "utf8")) as T;
}

async function createPemKeyPair(): Promise<PemKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA");

  return {
    privateKeyPem: await exportPKCS8(privateKey),
    publicKeyPem: await exportSPKI(publicKey)
  };
}

describe("generate/verify", () => {
  let keyPairA: PemKeyPair;
  let keyPairB: PemKeyPair;
  let allowEnvelope: Record<string, unknown>;
  let allowVector: AllowVector;

  beforeAll(async () => {
    keyPairA = await createPemKeyPair();
    keyPairB = await createPemKeyPair();

    allowEnvelope = readJsonFile<Record<string, unknown>>(
      "../../../spec/examples/allow.json"
    );
    allowVector = readJsonFile<AllowVector>("../../../spec/vectors/v001_allow_basic.json");
  });

  it("happy path signs and verifies allow claims", async () => {
    const schemaValidation = validateEnvelopeSchema(allowEnvelope);
    expect(schemaValidation.valid).toBe(true);

    const token = await generate(allowEnvelope, keyPairA.privateKeyPem);
    const result = await verify(token, keyPairA.publicKeyPem);

    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.claims).toBeDefined();
    expect((result.claims as Record<string, unknown>).action).toBe("payout.initiate");
  });

  it("returns INVALID_SIGNATURE when verified with a different public key", async () => {
    const token = await generate(allowEnvelope, keyPairA.privateKeyPem);
    const result = await verify(token, keyPairB.publicKeyPem);

    expect(result.ok).toBe(false);
    expect(result.errors.some((error) => error.code === "INVALID_SIGNATURE")).toBe(true);
  });

  it("throws on invalid schema before signing", async () => {
    const { action: _omittedAction, ...invalidEnvelope } = allowEnvelope;
    void _omittedAction;

    await expect(generate(invalidEnvelope, keyPairA.privateKeyPem)).rejects.toThrow(
      /Invalid TrustProof envelope/
    );
  });

  it("throws on missing jti before signing", async () => {
    const missingJtiEnvelope = {
      ...allowEnvelope,
      jti: ""
    };

    await expect(generate(missingJtiEnvelope, keyPairA.privateKeyPem)).rejects.toThrow(
      /Invalid TrustProof envelope/
    );
  });

  it("returns INPUT_HASH_MISMATCH when expectedInput does not match token hashes", async () => {
    const token = await generate(allowEnvelope, keyPairA.privateKeyPem);
    const mismatchedInput = {
      ...(allowVector.input as Record<string, unknown>),
      resource: {
        ...((allowVector.input as Record<string, unknown>).resource as Record<string, unknown>),
        id: "po_tampered"
      }
    };

    const result = await verify(token, keyPairA.publicKeyPem, {
      expectedInput: mismatchedInput,
      expectedOutput: allowVector.output
    });

    expect(result.ok).toBe(false);
    expect(result.errors.some((error) => error.code === "INPUT_HASH_MISMATCH")).toBe(true);
  });

  it("returns OUTPUT_HASH_MISMATCH when expectedOutput does not match token hashes", async () => {
    const token = await generate(allowEnvelope, keyPairA.privateKeyPem);
    const mismatchedOutput = {
      ...(allowVector.output as Record<string, unknown>),
      reason_codes: ["tampered_reason"]
    };

    const result = await verify(token, keyPairA.publicKeyPem, {
      expectedInput: allowVector.input,
      expectedOutput: mismatchedOutput
    });

    expect(result.ok).toBe(false);
    expect(result.errors.some((error) => error.code === "OUTPUT_HASH_MISMATCH")).toBe(true);
  });

  it("verifies successfully when expectedInput and expectedOutput match", async () => {
    const token = await generate(allowEnvelope, keyPairA.privateKeyPem);

    const result = await verify(token, keyPairA.publicKeyPem, {
      expectedInput: allowVector.input,
      expectedOutput: allowVector.output
    });

    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
  });
});
