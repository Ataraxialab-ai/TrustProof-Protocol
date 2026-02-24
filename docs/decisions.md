# TrustProof Protocol Decisions (PR2)
Date: 2026-02-24

## Context / Goal
- Lock cryptographic and canonicalization behavior so JS/Python outputs are deterministic.
- Define envelope, replay, and chain semantics early so SDK/CLI and vectors can converge.
- Keep scope narrow for protocol hardening without introducing external infrastructure dependencies.

## Decisions
- Decision: Algorithm is Ed25519 with JWT header `alg=EdDSA`, `typ=JWT`, `kid` optional. Why: Ed25519 is widely supported, fast, compact, and stable for cross-language verification. Reversal plan: Introduce algorithm negotiation via explicit `alg` policy/versioning and dual-sign support during migration.
- Decision: Canonicalization for hashing is `json.dumps(sort_keys=True, separators=(",", ":"))` (cross-language deterministic canonical JSON). Why: Stable key ordering and compact separators remove whitespace/key-order drift across implementations. Reversal plan: Version canonicalization as a new profile, keep old profile verifier-compatible, and regenerate vectors before default switch.
- Decision: Hashes are `sha256(canonical_json(input))` and `sha256(canonical_json(output))`. Why: Separating input and output digests makes tampering boundaries explicit and implementation-simple. Reversal plan: Add hash-alg/version metadata, back-verify legacy hashes, and run parallel vectors until cutover.
- Decision: Chain rule is `entry_hash = sha256(prev_hash + canonical_event_material)`. Why: Linear linkage provides tamper-evidence with minimal state and straightforward verification order. Reversal plan: Introduce chain versioning for new composition rules while preserving legacy verification path.
- Decision: Replay model requires `jti`; `verify()` exposes `replay_risk` and accepts optional `ReplayStore`. Why: `jti` gives portable nonce identity while allowing deployments to choose strict or advisory replay enforcement. Reversal plan: Promote `ReplayStore` from optional to required in a future major version with transition warnings.
- Decision: Envelope shape is CloudEvents-ish with `subject`, `action`, `resource`, `policy`, `result`, `hashes`, `timestamp`, `jti`, `chain`. Why: These fields cover actor, intent, outcome, integrity, and ordering without overfitting provider-specific semantics. Reversal plan: Add fields only via versioned schema evolution with compatibility gates and vectors.
- Decision: Policy stub v0 is:
  - `policy_v: "v0"`
  - `scopes: string[]`
  - `constraints: { max_amount_cents?, currency_allowlist?, merchant_allowlist? }`
  Why: Smallest useful authorization surface for early demos and deterministic tests. Reversal plan: Extend constraints behind new policy versions and keep v0 parse/verify support.

## Out of Scope
- DID/VCs
- On-chain anchoring
- Global transparency log

## Open Questions
- Should `timestamp` accept only UTC RFC3339 with second precision, or allow sub-second precision?
- Should `kid` be recommended when key rotation is enabled, or always emitted?
- Should `ReplayStore` define a minimum TTL contract for `jti` records?
- Should chain verification support partial windows, or require full history by default?
- Should policy constraints include locale/regional dimensions in v1, or remain external?

## Change Control
Any change to canonicalization/hash/chain requires updating golden vectors and cross-lang tests.
