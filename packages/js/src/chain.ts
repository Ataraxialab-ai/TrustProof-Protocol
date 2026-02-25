import { canonicalJson } from "./canonical";
import { sha256Hex } from "./crypto";
import { generate } from "./generate";
import { verify } from "./verify";

const GENESIS_PREV_HASH = "0".repeat(64);
const HEX_64_RE = /^[a-fA-F0-9]{64}$/;

type ClaimsRecord = Record<string, unknown>;

function isRecord(value: unknown): value is ClaimsRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isHex64(value: string): boolean {
  return HEX_64_RE.test(value);
}

function hexEquals(left: string, right: string): boolean {
  return normalizeHex(left) === normalizeHex(right);
}

function decodeJwtPayloadUntrusted(token: string): ClaimsRecord {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Previous JWT must be in compact JWS format.");
  }

  const payloadSegment = parts[1];
  const base64 = payloadSegment.replace(/-/g, "+").replace(/_/g, "/");
  const paddedBase64 = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");

  const bufferApi = globalThis as unknown as {
    Buffer?: {
      from: (input: string, encoding: "base64") => {
        toString: (encoding: "utf8") => string;
      };
    };
  };

  if (!bufferApi.Buffer || typeof bufferApi.Buffer.from !== "function") {
    throw new Error("Buffer API is unavailable for JWT decoding.");
  }

  let payloadJson: string;
  try {
    payloadJson = bufferApi.Buffer.from(paddedBase64, "base64").toString("utf8");
  } catch {
    throw new Error("Previous JWT payload is not valid base64url data.");
  }

  let payload: unknown;
  try {
    payload = JSON.parse(payloadJson);
  } catch {
    throw new Error("Previous JWT payload is not valid JSON.");
  }

  if (!isRecord(payload)) {
    throw new Error("Previous JWT payload must be a JSON object.");
  }

  return payload;
}

function getEntryHashFromClaims(claims: ClaimsRecord, label: string): string {
  if (!isRecord(claims.chain)) {
    throw new Error(`${label} is missing chain data.`);
  }

  const entryHash = claims.chain.entry_hash;
  if (typeof entryHash !== "string" || !isHex64(entryHash)) {
    throw new Error(`${label} has invalid chain.entry_hash (expected 64-char hex).`);
  }

  return normalizeHex(entryHash);
}

export function normalizeHex(s: string): string {
  return s.toLowerCase();
}

export function computeCanonicalEventMaterial(claims: unknown): string {
  if (!isRecord(claims)) {
    throw new Error("Claims must be a JSON object.");
  }

  return canonicalJson({
    subject: claims.subject,
    action: claims.action,
    resource: claims.resource,
    policy: claims.policy,
    result: claims.result,
    hashes: claims.hashes,
    timestamp: claims.timestamp,
    jti: claims.jti
  });
}

export function computeEntryHash(prevHashHex: string, canonicalEventMaterial: string): string {
  if (!isHex64(prevHashHex)) {
    throw new Error("prevHashHex must be a 64-char hex string.");
  }

  return sha256Hex(`${normalizeHex(prevHashHex)}${canonicalEventMaterial}`);
}

export async function append(
  prev: string | ClaimsRecord | null,
  nextClaims: ClaimsRecord,
  privateKeyPem: string,
  opts?: { kid?: string }
): Promise<string> {
  let prevHash = GENESIS_PREV_HASH;

  if (typeof prev === "string") {
    prevHash = getEntryHashFromClaims(decodeJwtPayloadUntrusted(prev), "Previous JWT payload");
  } else if (prev !== null) {
    if (!isRecord(prev)) {
      throw new Error("prev must be null, a JWT string, or a claims object.");
    }

    prevHash = getEntryHashFromClaims(prev, "Previous claims");
  }

  if (!isRecord(nextClaims)) {
    throw new Error("nextClaims must be a JSON object.");
  }

  const nextClaimsWithChain: ClaimsRecord = {
    ...nextClaims,
    chain: {
      ...(isRecord(nextClaims.chain) ? nextClaims.chain : {}),
      prev_hash: normalizeHex(prevHash)
    }
  };

  const canonicalEventMaterial = computeCanonicalEventMaterial(nextClaimsWithChain);
  const entryHash = computeEntryHash(prevHash, canonicalEventMaterial);

  nextClaimsWithChain.chain = {
    ...(isRecord(nextClaimsWithChain.chain) ? nextClaimsWithChain.chain : {}),
    prev_hash: normalizeHex(prevHash),
    entry_hash: normalizeHex(entryHash)
  };

  return generate(nextClaimsWithChain, privateKeyPem, opts);
}

export async function verifyChain(
  tokens: string[],
  publicKeyPem: string,
  opts?: { expectedGenesisPrevHash?: string }
): Promise<{ ok: boolean; errors: Array<{ index?: number; code: string; message: string }> }> {
  const expectedGenesisPrevHash = normalizeHex(opts?.expectedGenesisPrevHash ?? GENESIS_PREV_HASH);
  if (!isHex64(expectedGenesisPrevHash)) {
    return {
      ok: false,
      errors: [
        {
          code: "CHAIN_GENESIS_PREV_HASH_INVALID",
          message: "expectedGenesisPrevHash must be a 64-char hex string."
        }
      ]
    };
  }

  let previousEntryHash: string | null = null;

  for (const [index, token] of tokens.entries()) {
    const verification = await verify(token, publicKeyPem);
    if (!verification.ok || !isRecord(verification.claims)) {
      const details = verification.errors.map((error) => `${error.code}: ${error.message}`).join("; ");
      return {
        ok: false,
        errors: [
          {
            index,
            code: "INVALID_PROOF",
            message: details || "Proof failed signature or schema validation."
          }
        ]
      };
    }

    const claims = verification.claims;
    if (!isRecord(claims.chain)) {
      return {
        ok: false,
        errors: [
          {
            index,
            code: "INVALID_PROOF",
            message: "Claims are missing chain object."
          }
        ]
      };
    }

    const prevHashValue = claims.chain.prev_hash;
    const entryHashValue = claims.chain.entry_hash;

    if (
      typeof prevHashValue !== "string" ||
      typeof entryHashValue !== "string" ||
      !isHex64(prevHashValue) ||
      !isHex64(entryHashValue)
    ) {
      return {
        ok: false,
        errors: [
          {
            index,
            code: "INVALID_PROOF",
            message: "Claims chain hashes must be 64-char hex strings."
          }
        ]
      };
    }

    const prevHash = normalizeHex(prevHashValue);
    const entryHash = normalizeHex(entryHashValue);

    const canonicalEventMaterial = computeCanonicalEventMaterial(claims);
    const recomputedEntryHash = computeEntryHash(prevHash, canonicalEventMaterial);

    if (!hexEquals(recomputedEntryHash, entryHash)) {
      return {
        ok: false,
        errors: [
          {
            index,
            code: "CHAIN_ENTRY_HASH_MISMATCH",
            message: "chain.entry_hash does not match recomputed hash."
          }
        ]
      };
    }

    if (index === 0) {
      if (!hexEquals(prevHash, expectedGenesisPrevHash)) {
        return {
          ok: false,
          errors: [
            {
              index,
              code: "CHAIN_GENESIS_PREV_HASH_INVALID",
              message: "First proof chain.prev_hash does not match expected genesis prev hash."
            }
          ]
        };
      }
    } else if (!previousEntryHash || !hexEquals(prevHash, previousEntryHash)) {
      return {
        ok: false,
        errors: [
          {
            index,
            code: "CHAIN_LINK_MISMATCH",
            message: "chain.prev_hash does not match the previous proof chain.entry_hash."
          }
        ]
      };
    }

    previousEntryHash = entryHash;
  }

  return {
    ok: true,
    errors: []
  };
}
