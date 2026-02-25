import { randomBytes, randomUUID } from "node:crypto";

import type { ToolInterface } from "@langchain/core/tools";

import { computeCanonicalEventMaterial, computeEntryHash, normalizeHex } from "../chain";
import { canonicalJson } from "../canonical";
import { sha256Hex } from "../crypto";
import { generate } from "../generate";

const GENESIS_PREV_HASH = "0".repeat(64);

type TrustProofClaims = {
  subject: { type: "human" | "agent"; id: string };
  action: string;
  resource: { type: string; id: string };
  policy: {
    policy_v: "v0";
    scopes: string[];
    constraints: Record<string, unknown>;
  };
  result: {
    decision: "allow" | "deny" | "step_up";
    reason_codes: string[];
  };
  hashes: {
    input_hash: string;
    output_hash: string;
  };
  timestamp: string;
  jti: string;
  chain: {
    prev_hash: string;
    entry_hash: string;
  };
};

type ToolLike = ToolInterface | { invoke: (input: unknown, ...rest: unknown[]) => Promise<unknown> };

export type TrustProofToolWrapOptions = {
  privateKeyPem: string;
  subject: { type: "human" | "agent"; id: string };
  policy?: { policy_v: "v0"; scopes: string[]; constraints?: Record<string, unknown> };
  resource?: { type: string; id: string };
  action?: string;
  decision?: "allow" | "deny" | "step_up";
  reasonCodes?: string[];
  kid?: string;
  chain?: { enabled?: boolean };
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function assertNonEmptyString(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${label} must be a non-empty string.`);
  }
}

function normalizeSubject(subject: TrustProofToolWrapOptions["subject"]): TrustProofClaims["subject"] {
  assertNonEmptyString(subject.id, "opts.subject.id");
  if (subject.type !== "human" && subject.type !== "agent") {
    throw new Error('opts.subject.type must be "human" or "agent".');
  }
  return {
    type: subject.type,
    id: subject.id
  };
}

function normalizePolicy(policy: TrustProofToolWrapOptions["policy"]): TrustProofClaims["policy"] {
  if (!policy) {
    return {
      policy_v: "v0",
      scopes: [],
      constraints: {}
    };
  }

  if (policy.policy_v !== "v0") {
    throw new Error('opts.policy.policy_v must be "v0".');
  }

  if (!Array.isArray(policy.scopes) || policy.scopes.some((scope) => typeof scope !== "string")) {
    throw new Error("opts.policy.scopes must be an array of strings.");
  }

  const constraints = policy.constraints ?? {};
  if (!isRecord(constraints)) {
    throw new Error("opts.policy.constraints must be an object when provided.");
  }

  return {
    policy_v: "v0",
    scopes: [...policy.scopes],
    constraints: { ...constraints }
  };
}

function resolveResource(
  tool: Record<string, unknown>,
  resource: TrustProofToolWrapOptions["resource"]
): TrustProofClaims["resource"] {
  if (resource) {
    assertNonEmptyString(resource.type, "opts.resource.type");
    assertNonEmptyString(resource.id, "opts.resource.id");
    return { type: resource.type, id: resource.id };
  }

  const toolName = typeof tool.name === "string" && tool.name.trim().length > 0 ? tool.name : "unknown_tool";
  return {
    type: "tool",
    id: toolName
  };
}

function normalizeReasonCodes(reasonCodes: string[] | undefined): string[] {
  if (!reasonCodes) {
    return [];
  }

  if (!Array.isArray(reasonCodes) || reasonCodes.some((reasonCode) => typeof reasonCode !== "string")) {
    throw new Error("opts.reasonCodes must be an array of strings.");
  }

  return [...reasonCodes];
}

function nextJti(): string {
  if (typeof randomUUID === "function") {
    return randomUUID();
  }

  return randomBytes(16).toString("hex");
}

function assertToolLike(tool: unknown): asserts tool is ToolLike & Record<string, unknown> {
  if (!isRecord(tool) || typeof tool.invoke !== "function") {
    throw new Error("tool must expose invoke(input, ...args).");
  }
}

export function wrapToolWithTrustProof<T>(
  tool: T,
  opts: TrustProofToolWrapOptions
): T & {
  getLastProofJwt: () => string | null;
  getLastClaims: () => Record<string, unknown> | null;
} {
  assertToolLike(tool);

  assertNonEmptyString(opts.privateKeyPem, "opts.privateKeyPem");

  const subject = normalizeSubject(opts.subject);
  const policy = normalizePolicy(opts.policy);
  const resource = resolveResource(tool, opts.resource);
  const action = opts.action ?? "tool.invoke";
  const decision = opts.decision ?? "allow";
  const reasonCodes = normalizeReasonCodes(opts.reasonCodes);
  const chainEnabled = opts.chain?.enabled ?? true;

  assertNonEmptyString(action, "opts.action");

  let lastProofJwt: string | null = null;
  let lastClaims: TrustProofClaims | null = null;
  let previousEntryHash: string | null = null;

  const originalInvoke = tool.invoke.bind(tool) as (input: unknown, ...rest: unknown[]) => Promise<unknown>;

  const wrappedInvoke = async (input: unknown, ...rest: unknown[]) => {
    const output = await originalInvoke(input, ...rest);

    const inputHash = sha256Hex(canonicalJson(input));
    const outputHash = sha256Hex(canonicalJson(output));

    const prevHash = chainEnabled && previousEntryHash ? previousEntryHash : GENESIS_PREV_HASH;

    const claims: TrustProofClaims = {
      subject,
      action,
      resource,
      policy,
      result: {
        decision,
        reason_codes: reasonCodes
      },
      hashes: {
        input_hash: inputHash,
        output_hash: outputHash
      },
      timestamp: new Date().toISOString(),
      jti: nextJti(),
      chain: {
        prev_hash: normalizeHex(prevHash),
        entry_hash: GENESIS_PREV_HASH
      }
    };

    const canonicalEventMaterial = computeCanonicalEventMaterial(claims);
    claims.chain.entry_hash = computeEntryHash(claims.chain.prev_hash, canonicalEventMaterial);

    const proofJwt = await generate(claims, opts.privateKeyPem, {
      kid: opts.kid
    });

    if (chainEnabled) {
      previousEntryHash = claims.chain.entry_hash;
    }

    lastProofJwt = proofJwt;
    lastClaims = claims;

    return {
      output,
      proof_jwt: proofJwt,
      claims
    };
  };

  const proxied = new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === "invoke") {
        return wrappedInvoke;
      }

      if (prop === "getLastProofJwt") {
        return () => lastProofJwt;
      }

      if (prop === "getLastClaims") {
        return () => lastClaims;
      }

      return Reflect.get(target, prop, receiver);
    }
  });

  return proxied as unknown as T & {
    getLastProofJwt: () => string | null;
    getLastClaims: () => Record<string, unknown> | null;
  };
}
