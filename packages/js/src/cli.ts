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

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }

  return value as Record<string, unknown>;
}

function shortHash(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    return "unknown";
  }

  return `${value.slice(0, 6)}…`;
}

function formatVerifiedSummary(payload: unknown): string {
  const claims = asRecord(payload);
  if (!claims) {
    return "✅ Verified";
  }

  const subject = asRecord(claims.subject);
  const resource = asRecord(claims.resource);
  const result = asRecord(claims.result);
  const hashes = asRecord(claims.hashes);
  const chain = asRecord(claims.chain);

  const subjectType = typeof subject?.type === "string" ? subject.type : "unknown";
  const subjectId = typeof subject?.id === "string" ? subject.id : "unknown";
  const action = typeof claims.action === "string" ? claims.action : "unknown";
  const decision = typeof result?.decision === "string" ? result.decision : "unknown";
  const resourceType = typeof resource?.type === "string" ? resource.type : "unknown";
  const resourceId = typeof resource?.id === "string" ? resource.id : "unknown";
  const timestamp = typeof claims.timestamp === "string" ? claims.timestamp : "unknown";
  const jti = typeof claims.jti === "string" ? claims.jti : "unknown";

  return [
    "✅ Verified",
    `Subject: ${subjectType}:${subjectId}`,
    `Action: ${action}`,
    `Decision: ${decision}`,
    `Resource: ${resourceType}:${resourceId}`,
    `Timestamp: ${timestamp}`,
    `JTI: ${jti}`,
    `Hashes: input=${shortHash(hashes?.input_hash)} output=${shortHash(hashes?.output_hash)}`,
    `Chain: prev=${shortHash(chain?.prev_hash)} entry=${shortHash(chain?.entry_hash)}`
  ].join("\n");
}

function formatNotVerified(errors: Array<{ code?: string; message?: string }>): string {
  const lines = ["❌ Not Verified"];
  for (const error of errors) {
    const code = error.code ?? "UNKNOWN_ERROR";
    const message = error.message ?? "Unknown verification error.";
    lines.push(`${code}: ${message}`);
  }
  return lines.join("\n");
}

async function runVerify(args: string[], jsonMode: boolean, io: CliIO): Promise<number> {
  const token = args[1];
  if (!token) {
    const result = {
      ok: false,
      errors: [{ code: "MISSING_ARGUMENT", message: "missing <jwt> argument" }]
    };
    if (jsonMode) {
      io.out(JSON.stringify(result));
    } else {
      io.err(formatNotVerified(result.errors));
    }
    return 1;
  }

  const pubkeyArg = findOptionValue(args.slice(2), "--pubkey");
  if (!pubkeyArg) {
    const result = {
      ok: false,
      errors: [{ code: "MISSING_ARGUMENT", message: "missing --pubkey <pem|b64|path>" }]
    };
    if (jsonMode) {
      io.out(JSON.stringify(result));
    } else {
      io.err(formatNotVerified(result.errors));
    }
    return 1;
  }

  let publicKeyPem: string;
  try {
    publicKeyPem = loadPublicKeyPem(pubkeyArg);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const result = {
      ok: false,
      errors: [{ code: "PUBKEY_LOAD_ERROR", message }]
    };
    if (jsonMode) {
      io.out(JSON.stringify(result));
    } else {
      io.err(formatNotVerified(result.errors));
    }
    return 1;
  }

  const result = await verify(token, publicKeyPem);

  if (jsonMode) {
    io.out(JSON.stringify(result));
  } else if (result.ok) {
    io.out(formatVerifiedSummary(result.claims));
  } else {
    io.err(formatNotVerified(result.errors));
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
      io.out(JSON.stringify(payload));
    } else {
      io.out(JSON.stringify(payload, null, 2));
    }
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (jsonMode) {
      io.out(JSON.stringify({ error: message }));
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
