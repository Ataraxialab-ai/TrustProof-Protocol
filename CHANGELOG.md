# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-25
### Added
- Spec v1 claims envelope schema at `spec/trustproof.schema.json`.
- Spec examples (`allow`, `deny`, `step_up`) and golden vectors in `spec/vectors/`.
- Spec validator workflow via `pnpm spec:validate`.
- JS SDK core for `generate`, `verify`, `append`, and `verifyChain`.
- Python SDK parity for `generate`, `verify`, `append`, and `verify_chain`.
- Node and Python CLI v0 commands for `verify` and `inspect`.
- Reproducible example suites:
  - `pnpm --filter @trustproof/sdk example:payout-stepup`
  - `pnpm --filter @trustproof/sdk example:agent-actions`

### Security
- Tamper-evident chain verification in JS and Python workflows.
- Deterministic canonicalization + hashing rules backed by cross-language vectors.
