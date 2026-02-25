#!/usr/bin/env node

import { fileURLToPath } from "node:url";

function helpText(): string {
  return [
    "TrustProof CLI (placeholder)",
    "",
    "Usage:",
    "  trustproof --help",
    "",
    "Commands such as verify/inspect will be added in later PRs."
  ].join("\n");
}

export function runCliPlaceholder(args: string[] = process.argv.slice(2)): number {
  if (args.includes("--help") || args.includes("-h") || args.length === 0) {
    // eslint-disable-next-line no-console
    console.log(helpText());
    return 0;
  }

  // eslint-disable-next-line no-console
  console.log(helpText());
  return 0;
}

function isDirectExecution(): boolean {
  if (!Array.isArray(process.argv) || typeof process.argv[1] !== "string") {
    return false;
  }

  if (typeof import.meta === "undefined" || typeof import.meta.url !== "string") {
    return false;
  }

  try {
    return fileURLToPath(import.meta.url) === process.argv[1];
  } catch {
    return false;
  }
}

if (isDirectExecution()) {
  process.exitCode = runCliPlaceholder();
}
