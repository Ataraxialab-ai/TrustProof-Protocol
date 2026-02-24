import { getJoseModule } from "./jose-runtime";
import { formatAjvErrors, validateEnvelopeSchema } from "./schema";

export async function generate(
  envelope: unknown,
  privateKeyPem: string,
  opts?: { kid?: string }
): Promise<string> {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("Envelope must be a JSON object.");
  }

  const validation = validateEnvelopeSchema(envelope);
  if (!validation.valid) {
    throw new Error(`Invalid TrustProof envelope: ${formatAjvErrors(validation.errors)}`);
  }

  const jose = await getJoseModule();
  const privateKey = await jose.importPKCS8(privateKeyPem, "EdDSA");
  const protectedHeader: { alg: "EdDSA"; typ: "JWT"; kid?: string } = {
    alg: "EdDSA",
    typ: "JWT"
  };

  if (opts?.kid) {
    protectedHeader.kid = opts.kid;
  }

  return new jose.SignJWT(envelope as Record<string, unknown>)
    .setProtectedHeader(protectedHeader)
    .setIssuedAt()
    .sign(privateKey);
}
