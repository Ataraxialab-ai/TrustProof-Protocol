# TrustProof Protocol Roadmap

## Principles

- Stability first: protocol behavior is defined by schema + canonicalization/hash/chain rules, not implementation details.
- Vectors are the contract: changes that affect canonicalization, hashing, or chain behavior require vector updates.
- Cross-language parity: JS and Python verification paths should agree on expected outcomes.
- Incremental evolution: prefer additive changes with explicit versioning and migration notes.

## Now (0.1.x)

Focus: hardening current protocol surface and improving developer reliability.

- Harden existing schema/examples/vectors workflow (`pnpm spec:validate`) and CI checks.
- Improve packaging polish for JS/Python SDK usage and CLI ergonomics.
- Expand integration adapters already present in repo (LangChain + OpenAI Agents) with practical examples.
- Strengthen docs for spec, security, demo runbook, and launch artifacts.
- Keep examples reproducible offline and generate deterministic outputs where possible.

## Next (0.2.x)

Focus: operational interfaces around verification and chaining.

- Define a replay-store interface contract (SDK-level) for `jti` handling.
- Add chain-oriented CLI subcommands for chain inspection/verification workflows.
- Define webhook event shapes for proof emission/verification events.
- Expand integrations:
  - LangChain callback-level hooks
  - OpenTelemetry-oriented receipt export patterns

## Later (0.3+)

Focus: richer policy and step-up artifacts with neutral enterprise mapping surfaces.

- Policy profiles with explicit versioned constraints beyond `policy_v: "v0"`.
- Step-up session artifacts that link approval state to action receipts.
- Enterprise mapping surfaces (neutral protocol extensions) for:
  - key lifecycle metadata
  - tenancy boundaries
  - compliance export interfaces

## Non-goals

- DID/VC frameworks as a protocol dependency
- On-chain anchoring requirements
- KYC/identity verification orchestration
- Platform-specific control planes in the core protocol spec

## How We Decide Changes

- Any change to canonicalization/hash/chain rules must:
  - update golden vectors
  - preserve or explicitly version backward compatibility
  - pass cross-language tests (JS/Python)
- Breaking behavioral changes require:
  - migration plan
  - explicit version boundary
  - release-note callout in changelog/docs
