# Badge Guide

## What "Verified" means

In this repo, "Verified" means a proof passes cryptographic signature validation and claims validation checks for the command you run:

- `verify` checks JWT signature and claims shape/required fields.
- `verifyChain` additionally checks chain linkage and recomputed chain entry hashes.
- Hash checks (`input_hash`, `output_hash`) depend on whether expected input/output values are provided to the verifier.

## Badge snippets

- Verified placeholder badge (not CI-linked):
  - `https://img.shields.io/badge/verified-trustproof-lightgrey`
- Spec validated badge (`pnpm spec:validate`):
  - `https://img.shields.io/badge/spec-validated-blue`

Copy/paste Markdown:

```md
[![Verified](https://img.shields.io/badge/verified-trustproof-lightgrey)](docs/badge.md)
[![Spec Validated](https://img.shields.io/badge/spec-validated-blue)](README.md#quickstart)
```

## Disclaimer

Badges do not imply endorsement or legal assurance. Verification results depend on the keys, token contents, and provided expected inputs/outputs.
