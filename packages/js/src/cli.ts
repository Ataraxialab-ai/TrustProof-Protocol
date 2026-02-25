#!/usr/bin/env node

import { basename } from "node:path";
import { existsSync, readFileSync } from "node:fs";

import { verify } from "./verify";

type CliIO = {
  out: (message: string) => void;
  err: (message: string) => void;
};

function defaultIO(): CliIO {
  return {
    out: (message: string) => {
      // eslint-disable-next-line no-console
      console.log(message);
    },
    err: (message: string) => {
      // eslint-disable-next-line no-console
      console.error(message);
    }
  };
}

function helpText(): string {
  return [
    "TrustProof CLI v0",
    "",
    "Usage:",
    "  trustproof verify <jwt> --pubkey <pem|b64|path> [--json]",
    "  trustproof inspect <jwt> [--json]"
  ].join("\n");
}

function decodeBase64UrlToUtf8(value: string): string {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  return Buffer.from(padded, "base64").toString("utf8");
}

function decodeJwtPayloadUntrusted(token: string): unknown {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Token must be compact JWS (three dot-separated segments).");
  }

  const payloadJson = decodeBase64UrlToUtf8(parts[1]);
  return JSON.parse(payloadJson) as unknown;
}

function loadPublicKeyPem(pubkeyArg: string): string {
  if (pubkeyArg.includes("BEGIN PUBLIC KEY")) {
    return pubkeyArg;
  }

  if (existsSync(pubkeyArg)) {
    return readFileSync(pubkeyArg, "utf8");
  }

  return decodeBase64UrlToUtf8(pubkeyArg);
}

function findOptionValue(args: string[], option: string): string | null {
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === option) {
      return args[i + 1] ?? null;
    }
    if (arg.startsWith(`${option}=`)) {
      return arg.slice(option.length + 1);
    }
  }
  return null;
}

function formatSummary(payload: unknown): string {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return "OK";
  }

  const claims = payload as Record<string, unknown>;
  const subject =
    claims.subject && typeof claims.subject === "object" && !Array.isArray(claims.subject)
      ? ((claims.subject as Record<string, unknown>).id ?? "unknown")
      : "unknown";
  const action = claims.action ?? "unknown";
  const decision =
    claims.result && typeof claims.result === "object" && !Array.isArray(claims.result)
      ? ((claims.result as Record<string, unknown>).decision ?? "unknown")
      : "unknown";

  return `OK\nsubject.id=${String(subject)}\naction=${String(action)}\ndecision=${String(decision)}`;
}

async function runVerify(args: string[], jsonMode: boolean, io: CliIO): Promise<number> {
  const token = args[1];
  if (!token) {
    io.err("FAIL\nmissing <jwt> argument");
    return 1;
  }

  const pubkeyArg = findOptionValue(args.slice(2), "--pubkey");
  if (!pubkeyArg) {
    io.err("FAIL\nmissing --pubkey <pem|b64|path>");
    return 1;
  }

  let publicKeyPem: string;
  try {
    publicKeyPem = loadPublicKeyPem(pubkeyArg);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (jsonMode) {
      io.out(JSON.stringify({ ok: false, errors: [{ code: "PUBKEY_LOAD_ERROR", message }] }, null, 2));
    } else {
      io.err(`FAIL\nPUBKEY_LOAD_ERROR: ${message}`);
    }
    return 1;
  }

  const result = await verify(token, publicKeyPem);

  if (jsonMode) {
    io.out(JSON.stringify(result, null, 2));
  } else if (result.ok) {
    io.out(formatSummary(result.claims));
  } else {
    const lines = ["FAIL", ...result.errors.map((error) => `${error.code}: ${error.message}`)];
    io.err(lines.join("\n"));
  }

  return result.ok ? 0 : 1;
}

function runInspect(args: string[], jsonMode: boolean, io: CliIO): number {
  const token = args[1];
  if (!token) {
    io.err("FAIL\nmissing <jwt> argument");
    return 1;
  }

  try {
    const payload = decodeJwtPayloadUntrusted(token);
    if (jsonMode) {
      io.out(JSON.stringify({ ok: true, payload }, null, 2));
    } else {
      io.out(JSON.stringify(payload, null, 2));
    }
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (jsonMode) {
      io.out(JSON.stringify({ ok: false, error: message }, null, 2));
    } else {
      io.err(`FAIL\n${message}`);
    }
    return 1;
  }
}

export async function runCli(args: string[] = process.argv.slice(2), io: CliIO = defaultIO()): Promise<number> {
  const jsonMode = args.includes("--json");
  const filteredArgs = args.filter((arg) => arg !== "--json");

  if (
    filteredArgs.length === 0 ||
    filteredArgs[0] === "--help" ||
    filteredArgs[0] === "-h" ||
    filteredArgs[0] === "help"
  ) {
    io.out(helpText());
    return 0;
  }

  const command = filteredArgs[0];

  if (command === "verify") {
    return runVerify(filteredArgs, jsonMode, io);
  }

  if (command === "inspect") {
    return runInspect(filteredArgs, jsonMode, io);
  }

  io.err(`Unknown command: ${command}`);
  io.out(helpText());
  return 1;
}

function isDirectExecution(): boolean {
  const invoked = basename(process.argv[1] ?? "");
  return invoked === "cli.js" || invoked === "cli.cjs" || invoked === "trustproof";
}

if (isDirectExecution()) {
  runCli()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      const message = error instanceof Error ? error.message : String(error);
      // eslint-disable-next-line no-console
      console.error(`FAIL\n${message}`);
      process.exitCode = 1;
    });
}
