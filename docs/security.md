# Security Notes

## Key Management & Rotation

- Use Ed25519 key pairs and store private keys in secure systems (KMS/HSM for enterprise deployments).
- Rotate keys regularly and include `kid` in JWT headers when multiple active keys exist.
- Verifiers should be able to select public keys by `kid` (recommended roadmap behavior).
- Keep prior public keys available for verification until the associated proofs expire.
- Never log private keys.
- Treat proofs as potentially sensitive records (they may contain operational metadata).
- For production flows, prefer short-lived proofs (`exp`) where replay window and audit requirements permit.

## Replay & Idempotency

- `jti` is required in every claims envelope.
- Store seen `jti` values per tenant and action scope with TTL.
- Recommended key shape: `tenant_id + action + kid + jti`.
- Store first-seen timestamp and result status for replay decisions.
- Use idempotency keys on action endpoints (for example payout initiation APIs) in addition to `jti`.
- TTL should match operational replay risk windows (for example 24h or 7d based on risk profile).

## Chain Integrity

What chain provides:

- tamper-evidence between linked proofs
- local integrity checks for `prev_hash` and `entry_hash`

What chain does not provide by itself:

- global ordering across distributed systems
- wall-clock ordering guarantees
- uniqueness without replay-store enforcement

If strict ordering is required, enforce write ordering in your own persistence layer.

## Data Minimization

- Default to hashing input/output payloads in proofs.
- Avoid embedding raw PII unless required for your use case.
- Store raw payloads separately with stricter retention and access controls.

## Operational Notes

- Set maximum accepted claim/payload sizes and reject oversized proofs early.
- Recommended starting point:
  - max JWT size: 64 KB
  - max `subject.id`/`resource.id`: application-defined hard caps
  - max array lengths (for example `scopes`, `reason_codes`): enforce server limits
- Fail closed on oversized input with explicit errors; do not attempt partial verification.

## Threat Model (Quick)

Defends against:

- payload tampering after signing
- chain-link tampering in linked proofs
- unverifiable action claims from unknown keys

Does not fully defend against:

- signer key compromise
- malicious signer generating valid but harmful actions
- replay attacks without a replay-store/idempotency strategy
