import { canonicalJson } from "./canonical";
import { sha256Hex } from "./crypto";
import { getJoseModule } from "./jose-runtime";
import { validateEnvelopeSchema } from "./schema";

type TrustProofError = {
  code: string;
  message: string;
  details?: unknown;
};

type VerifyResult = {
  ok: boolean;
  claims?: unknown;
  errors: TrustProofError[];
};

const JWT_METADATA_KEYS_TO_STRIP = ["iat", "exp", "nbf", "iss", "aud", "sub"] as const;

function sanitizeClaimsPayload(payload: Record<string, unknown>): Record<string, unknown> {
  const claims = { ...payload };

  for (const key of JWT_METADATA_KEYS_TO_STRIP) {
    delete claims[key];
  }

  return claims;
}

function getHashField(
  claims: Record<string, unknown>,
  key: "input_hash" | "output_hash"
): string | undefined {
  const hashes = claims.hashes;
  if (!hashes || typeof hashes !== "object" || Array.isArray(hashes)) {
    return undefined;
  }

  const value = (hashes as Record<string, unknown>)[key];
  return typeof value === "string" ? value : undefined;
}

function hexEquals(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

export async function verify(
  token: string,
  publicKeyPem: string,
  opts?: { expectedInput?: unknown; expectedOutput?: unknown }
): Promise<VerifyResult> {
  let payload: Record<string, unknown>;

  try {
    const jose = await getJoseModule();
    const publicKey = await jose.importSPKI(publicKeyPem, "EdDSA");
    const result = await jose.jwtVerify(token, publicKey, {
      algorithms: ["EdDSA"]
    });
    payload = result.payload;
  } catch (error) {
    return {
      ok: false,
      errors: [
        {
          code: "INVALID_SIGNATURE",
          message: "JWT signature verification failed.",
          details: error instanceof Error ? error.message : String(error)
        }
      ]
    };
  }

  const claims = sanitizeClaimsPayload(payload);
  const errors: TrustProofError[] = [];

  const schemaValidation = validateEnvelopeSchema(claims);
  if (!schemaValidation.valid) {
    errors.push({
      code: "INVALID_SCHEMA",
      message: "Claims payload does not conform to TrustProof schema.",
      details: schemaValidation.errors
    });
  }

  if (typeof claims.jti !== "string" || claims.jti.trim().length === 0) {
    errors.push({
      code: "MISSING_JTI",
      message: "Claims payload must include a non-empty jti."
    });
  }

  if (opts?.expectedInput !== undefined) {
    const expectedHash = sha256Hex(canonicalJson(opts.expectedInput));
    const actualHash = getHashField(claims, "input_hash");

    if (!actualHash || !hexEquals(expectedHash, actualHash)) {
      errors.push({
        code: "INPUT_HASH_MISMATCH",
        message: "Computed input hash does not match claims.hashes.input_hash.",
        details: {
          expectedHash,
          actualHash
        }
      });
    }
  }

  if (opts?.expectedOutput !== undefined) {
    const expectedHash = sha256Hex(canonicalJson(opts.expectedOutput));
    const actualHash = getHashField(claims, "output_hash");

    if (!actualHash || !hexEquals(expectedHash, actualHash)) {
      errors.push({
        code: "OUTPUT_HASH_MISMATCH",
        message: "Computed output hash does not match claims.hashes.output_hash.",
        details: {
          expectedHash,
          actualHash
        }
      });
    }
  }

  if (errors.length > 0) {
    return {
      ok: false,
      claims,
      errors
    };
  }

  return {
    ok: true,
    claims,
    errors: []
  };
}
