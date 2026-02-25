# Security Notes

## Replay Protection

- `jti` is required in every claims envelope.
- Verification can use a server-side replay store, but store integration is deployment-specific.
- Use idempotency keys alongside `jti` for externally triggered operations (for example payout requests).

Recommended storage pattern:

- Key: `issuer_or_kid + jti`
- Value: first-seen timestamp, status, optional metadata
- TTL: align with your operation replay window (for example 24h/7d depending on risk)

## Chain Integrity

What chain provides:

- tamper-evidence between linked proofs
- local integrity checks for `prev_hash` and `entry_hash`

What chain does not provide by itself:

- global ordering across distributed systems
- wall-clock ordering guarantees
- uniqueness without replay-store enforcement

If strict ordering is required, enforce write ordering in your own persistence layer.

## Key Management

- Use Ed25519 key pairs and rotate keys regularly.
- Set `kid` during signing when multiple active keys may exist.
- Never log private keys or commit them to source control.
- Keep private keys in secure storage (KMS/HSM or equivalent secret manager).

## Data Minimization

- Default to hashing input/output payloads in proofs.
- Avoid embedding raw PII unless required for your use case.
- Store raw payloads separately with stricter retention and access controls.

## Threat Model (Quick)

Defends against:

- payload tampering after signing
- chain-link tampering in linked proofs
- unverifiable action claims from unknown keys

Does not fully defend against:

- signer key compromise
- malicious signer generating valid but harmful actions
- replay attacks without a replay-store/idempotency strategy
