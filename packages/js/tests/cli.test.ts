import { readFileSync } from "node:fs";

import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";

import { generate } from "../src";
import { runCli } from "../src/cli";

describe("cli", () => {
  it("verify returns exit code 0 for a valid JWT", async () => {
    const claims = JSON.parse(
      readFileSync(new URL("../../../spec/examples/allow.json", import.meta.url), "utf8")
    ) as Record<string, unknown>;

    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const privateKeyPem = await exportPKCS8(privateKey);
    const publicKeyPem = await exportSPKI(publicKey);

    const token = await generate(claims, privateKeyPem);

    const stdout: string[] = [];
    const stderr: string[] = [];

    const exitCode = await runCli(["verify", token, "--pubkey", publicKeyPem], {
      out: (message) => {
        stdout.push(message);
      },
      err: (message) => {
        stderr.push(message);
      }
    });

    expect(exitCode).toBe(0);
    expect(stderr).toEqual([]);
    expect(stdout.some((line) => line.includes("✅ Verified"))).toBe(true);
  });
});
