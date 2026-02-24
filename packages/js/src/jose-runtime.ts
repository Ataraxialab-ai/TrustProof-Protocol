type JoseSignJwt = {
  setProtectedHeader(header: { alg: string; typ?: string; kid?: string }): JoseSignJwt;
  setIssuedAt(input?: number | string | Date): JoseSignJwt;
  sign(key: unknown): Promise<string>;
};

type JoseModule = {
  SignJWT: new (payload?: Record<string, unknown>) => JoseSignJwt;
  importPKCS8: (pem: string, alg: string) => Promise<unknown>;
  importSPKI: (pem: string, alg: string) => Promise<unknown>;
  jwtVerify: (
    token: string,
    key: unknown,
    options?: { algorithms?: string[] }
  ) => Promise<{ payload: Record<string, unknown> }>;
};

let joseModulePromise: Promise<JoseModule> | null = null;

export async function getJoseModule(): Promise<JoseModule> {
  if (!joseModulePromise) {
    joseModulePromise = (
      new Function('return import("jose")')() as Promise<JoseModule>
    ).catch((error: unknown) => {
      joseModulePromise = null;
      throw error;
    });
  }

  return joseModulePromise;
}
