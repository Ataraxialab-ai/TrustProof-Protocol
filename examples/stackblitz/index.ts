import { readFileSync } from "node:fs";

import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";

import { append, generate, verify, verifyChain } from "../../packages/js/src/index.ts";

type Claims = Record<string, unknown>;

function loadBaseClaims(): Claims {
  const fileUrl = new URL("../../spec/examples/allow.json", import.meta.url);
  return JSON.parse(readFileSync(fileUrl, "utf8")) as Claims;
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function shortToken(value: string): string {
  return `${value.slice(0, 60)}...`;
}

function tamperOneChar(token: string): string {
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

function summary(claims: unknown): string {
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) {
    return "unknown";
  }

  const record = claims as Record<string, unknown>;
  const subject =
    record.subject && typeof record.subject === "object" && !Array.isArray(record.subject)
      ? (record.subject as Record<string, unknown>)
      : {};
  const result =
    record.result && typeof record.result === "object" && !Array.isArray(record.result)
      ? (record.result as Record<string, unknown>)
      : {};

  return [
    `subject=${String(subject.id ?? "unknown")}`,
    `action=${String(record.action ?? "unknown")}`,
    `decision=${String(result.decision ?? "unknown")}`
  ].join(" ");
}

async function main(): Promise<void> {
  // 1) Ed25519 keypair in-memory (no external API keys/services)
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const privateKeyPem = await exportPKCS8(privateKey);
  const publicKeyPem = await exportSPKI(publicKey);

  // 2) Base claims from spec example
  const claims1 = loadBaseClaims();

  // 3) generate + 4) verify
  const jwt1 = await generate(claims1, privateKeyPem);
  const verify1 = await verify(jwt1, publicKeyPem);

  console.log("TrustProof StackBlitz Playground");
  console.log("--------------------------------");
  console.log(`JWT1: ${shortToken(jwt1)}`);
  console.log(`verify(jwt1): ok=${verify1.ok}`);
  console.log(`summary(jwt1): ${summary(verify1.claims)}`);

  // 5) append second proof with distinct jti + resource.id
  const claims2 = deepClone(claims1);
  claims2.jti = "jti_stackblitz_002";
  claims2.timestamp = "2026-02-25T17:00:05Z";

  const resource =
    claims2.resource && typeof claims2.resource === "object" && !Array.isArray(claims2.resource)
      ? (claims2.resource as Record<string, unknown>)
      : {};
  claims2.resource = {
    ...resource,
    id: "po_stackblitz_002"
  };

  const jwt2 = await append(jwt1, claims2, privateKeyPem);
  const verify2 = await verify(jwt2, publicKeyPem);
  const chainResult = await verifyChain([jwt1, jwt2], publicKeyPem);

  console.log(`JWT2: ${shortToken(jwt2)}`);
  console.log(`verify(jwt2): ok=${verify2.ok}`);
  console.log(`summary(jwt2): ${summary(verify2.claims)}`);
  console.log(`verifyChain([jwt1,jwt2]): ok=${chainResult.ok}`);

  // 7) Tamper failure demonstration
  const tamperedJwt2 = tamperOneChar(jwt2);
  const tamperedResult = await verifyChain([jwt1, tamperedJwt2], publicKeyPem);
  if (!tamperedResult.ok) {
    console.log("Tamper => OK (failed as expected)");
    console.log(
      `tamper_error=${tamperedResult.errors[0]?.code ?? "UNKNOWN"} index=${String(
        tamperedResult.errors[0]?.index ?? "n/a"
      )}`
    );
  } else {
    console.log("Tamper => FAIL (unexpectedly verified)");
    process.exitCode = 1;
  }
}

await main();
