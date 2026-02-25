import { randomBytes, randomUUID } from "node:crypto";

import { append } from "../chain";
import { canonicalJson } from "../canonical";
import { sha256Hex } from "../crypto";

const GENESIS_PREV_HASH = "0".repeat(64);
const ALLOWED_DECISIONS = new Set(["allow", "deny", "step_up"] as const);
const ALLOWED_CONSTRAINT_KEYS = new Set([
  "max_amount_cents",
  "currency_allowlist",
  "merchant_allowlist"
] as const);

type ClaimsRecord = Record<string, unknown>;

export type AgentHookOpts = {
  privateKeyPem: string;
  subject: { type: "agent"; id: string; parent?: { humanId?: string } };
  policy?: {
    policy_v: "v0";
    scopes: string[];
    constraints?: {
      max_amount_cents?: number;
      currency_allowlist?: string[];
      merchant_allowlist?: string[];
      [key: string]: unknown;
    };
  };
  kid?: string;
  chain?: { enabled?: boolean };
};

export type AgentLifecycleEvent = {
  action_name?: string;
  tool_name?: string;
  input?: unknown;
  output?: unknown;
  resource?: { type?: string; id?: string };
  timestamp?: string;
  decision?: "allow" | "deny" | "step_up";
  reason_codes?: string[];
  jti?: string;
  [key: string]: unknown;
};

export type AgentProofResult = {
  proof_jwt: string;
  claims: ClaimsRecord;
};

function isRecord(value: unknown): value is ClaimsRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function asNonEmptyString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeName(value: unknown, fallback: string): string {
  const raw = asNonEmptyString(value) ?? fallback;
  return raw.replace(/\s+/g, ".").replace(/[^A-Za-z0-9._-]/g, "_");
}

function normalizeIsoTimestamp(value: unknown): string {
  const raw = asNonEmptyString(value);
  if (!raw) {
    return new Date().toISOString();
  }

  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed)) {
    return new Date().toISOString();
  }

  return new Date(parsed).toISOString();
}

function normalizeDecision(value: unknown): "allow" | "deny" | "step_up" {
  if (typeof value === "string" && ALLOWED_DECISIONS.has(value as "allow" | "deny" | "step_up")) {
    return value as "allow" | "deny" | "step_up";
  }

  return "allow";
}

function normalizeReasonCodes(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

function nextJti(): string {
  if (typeof randomUUID === "function") {
    return randomUUID();
  }

  return randomBytes(16).toString("hex");
}

function normalizePolicy(policy: AgentHookOpts["policy"]): {
  policy_v: "v0";
  scopes: string[];
  constraints: ClaimsRecord;
} {
  if (!policy) {
    return {
      policy_v: "v0",
      scopes: [],
      constraints: {}
    };
  }

  const scopes = Array.isArray(policy.scopes)
    ? policy.scopes.filter((scope): scope is string => typeof scope === "string" && scope.length > 0)
    : [];

  const constraints: ClaimsRecord = {};
  if (isRecord(policy.constraints)) {
    for (const [key, value] of Object.entries(policy.constraints)) {
      if (!ALLOWED_CONSTRAINT_KEYS.has(key as "max_amount_cents" | "currency_allowlist" | "merchant_allowlist")) {
        continue;
      }

      if (key === "max_amount_cents" && Number.isInteger(value)) {
        constraints.max_amount_cents = value;
      }

      if (
        (key === "currency_allowlist" || key === "merchant_allowlist") &&
        Array.isArray(value) &&
        value.every((item) => typeof item === "string")
      ) {
        constraints[key] = [...value];
      }
    }
  }

  return {
    policy_v: "v0",
    scopes,
    constraints
  };
}

function resolveAction(kind: "action" | "tool", event: AgentLifecycleEvent): string {
  const explicitAction = asNonEmptyString(event.action_name);
  if (explicitAction) {
    return explicitAction;
  }

  const suffix = normalizeName(event.tool_name ?? event.action_name, "unknown");
  return kind === "tool" ? `agent.tool.${suffix}` : `agent.action.${suffix}`;
}

function resolveResource(
  kind: "action" | "tool",
  event: AgentLifecycleEvent,
  resolvedAction: string
): { type: string; id: string } {
  if (isRecord(event.resource)) {
    const type = asNonEmptyString(event.resource.type);
    const id = asNonEmptyString(event.resource.id);
    if (type && id) {
      return { type, id };
    }
  }

  if (kind === "tool") {
    return {
      type: "tool",
      id: normalizeName(event.tool_name ?? resolvedAction, "unknown")
    };
  }

  return {
    type: "action",
    id: normalizeName(event.action_name ?? resolvedAction, "unknown")
  };
}

function normalizeHashInput(value: unknown): unknown {
  return value === undefined ? null : value;
}

function decodeJwtPayloadUntrusted(token: string): ClaimsRecord {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Expected compact JWT format.");
  }

  const payloadSegment = parts[1];
  const base64 = payloadSegment.replace(/-/g, "+").replace(/_/g, "/");
  const paddedBase64 = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");

  const payloadJson = Buffer.from(paddedBase64, "base64").toString("utf8");
  const payload = JSON.parse(payloadJson) as unknown;

  if (!isRecord(payload)) {
    throw new Error("JWT payload must decode to a JSON object.");
  }

  return payload;
}

function buildClaims(
  kind: "action" | "tool",
  event: AgentLifecycleEvent,
  opts: AgentHookOpts
): ClaimsRecord {
  const action = resolveAction(kind, event);
  const resource = resolveResource(kind, event, action);
  const normalizedInput = normalizeHashInput(event.input);
  const normalizedOutput = normalizeHashInput(event.output);

  const inputHash = sha256Hex(canonicalJson(normalizedInput));
  const outputHash = sha256Hex(canonicalJson(normalizedOutput));

  return {
    subject: {
      type: "agent",
      id: opts.subject.id
    },
    action,
    resource,
    policy: normalizePolicy(opts.policy),
    result: {
      decision: normalizeDecision(event.decision),
      reason_codes: normalizeReasonCodes(event.reason_codes)
    },
    hashes: {
      input_hash: inputHash,
      output_hash: outputHash
    },
    timestamp: normalizeIsoTimestamp(event.timestamp),
    jti: asNonEmptyString(event.jti) ?? nextJti(),
    chain: {
      prev_hash: GENESIS_PREV_HASH,
      entry_hash: GENESIS_PREV_HASH
    }
  };
}

export function createTrustProofAgentHook(opts: AgentHookOpts): {
  onActionStart: (event: AgentLifecycleEvent) => void;
  onActionEnd: (event: AgentLifecycleEvent) => Promise<AgentProofResult>;
  onToolStart: (event: AgentLifecycleEvent) => void;
  onToolEnd: (event: AgentLifecycleEvent) => Promise<AgentProofResult>;
  getChain: () => { proofs: string[] };
} {
  if (opts.subject.type !== "agent") {
    throw new Error('opts.subject.type must be "agent".');
  }

  if (!asNonEmptyString(opts.subject.id)) {
    throw new Error("opts.subject.id must be a non-empty string.");
  }

  if (!asNonEmptyString(opts.privateKeyPem)) {
    throw new Error("opts.privateKeyPem must be a non-empty string.");
  }

  const chainEnabled = opts.chain?.enabled ?? true;
  const proofs: string[] = [];
  let previousProofJwt: string | null = null;

  const emitProof = async (
    kind: "action" | "tool",
    event: AgentLifecycleEvent
  ): Promise<AgentProofResult> => {
    const claims = buildClaims(kind, event, opts);
    const prev = chainEnabled ? previousProofJwt : null;
    const proofJwt = await append(prev, claims, opts.privateKeyPem, { kid: opts.kid });
    const signedClaims = decodeJwtPayloadUntrusted(proofJwt);

    proofs.push(proofJwt);
    if (chainEnabled) {
      previousProofJwt = proofJwt;
    }

    return {
      proof_jwt: proofJwt,
      claims: signedClaims
    };
  };

  return {
    onActionStart: () => {},
    onActionEnd: (event) => emitProof("action", event),
    onToolStart: () => {},
    onToolEnd: (event) => emitProof("tool", event),
    getChain: () => ({ proofs: [...proofs] })
  };
}
