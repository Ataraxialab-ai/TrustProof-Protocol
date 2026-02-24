# TrustProof Spec (Outline)

## Envelope v1 Fields
- `subject`
- `action`
- `resource`
- `policy`
- `result`
- `hashes`
- `chain`
- `jti`
- `timestamp`

## SDK Function Signatures
```txt
generate(envelope, privateKey, opts) -> jwt
verify(jwt, publicKey, opts) -> { ok, claims, errors[], replay_risk? }
chain.append(prevClaimsOrJwt, nextEnvelope, privateKey) -> jwt
chain.verify(jwts[], publicKey) -> { ok, indexOfFailure?, errors[] }
```

## CLI Commands
```bash
trustproof verify <jwt> --pubkey <pem|b64>
trustproof inspect <jwt>
```

## Schema and Vectors
- Envelope/schema definitions for v1 will live in `spec/schema/v1`.
- Golden vectors will live in `spec/vectors`.
