# TrustProof Protocol
[![Spec Validated](https://img.shields.io/badge/spec-validated-blue)](#quickstart)
[![TypeScript](https://img.shields.io/badge/language-TypeScript-3178c6)](#)
[![Python](https://img.shields.io/badge/language-Python-3776ab)](#)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-black)](https://ataraxialab-ai.github.io/TrustProof-Protocol/)
[![Verified](https://img.shields.io/badge/verified-trustproof-lightgrey)](docs/badge.md)

TrustProof Protocol defines signed action receipts — compact JWT artifacts (Ed25519 / EdDSA) that bind a subject, a policy snapshot, an action, hashed inputs/outputs, a timestamp + jti, and a tamper-evident chain.

- Protocol (OSS): schema + canonicalization + hashing + chain rules + vectors + SDKs + CLI
- Enterprise mapping (Verdicto): KYH/KYA, policy engine, hosted verification, dashboards/log export, webhooks, step-up UX, multi-tenant keys, SLAs

## Quickstart

```bash
pnpm install
pnpm spec:validate
pnpm --filter @trustproof/sdk build
pnpm --filter @trustproof/sdk test
cd packages/py && python -m pytest -q && cd -
node --input-type=module -e "import {generateKeyPairSync} from 'node:crypto'; import fs from 'node:fs'; import {generate} from './packages/js/dist/index.js'; const c=JSON.parse(fs.readFileSync('./spec/examples/allow.json','utf8')); const {privateKey,publicKey}=generateKeyPairSync('ed25519'); const priv=privateKey.export({format:'pem',type:'pkcs8'}).toString(); const pub=publicKey.export({format:'pem',type:'spki'}).toString(); const jwt=await generate(c,priv); fs.writeFileSync('/tmp/tp.jwt',jwt); fs.writeFileSync('/tmp/tp.pub.pem',pub);"
node packages/js/dist/cli.js inspect "$(cat /tmp/tp.jwt)"
node packages/js/dist/cli.js verify "$(cat /tmp/tp.jwt)" --pubkey /tmp/tp.pub.pem
```

## Playground (StackBlitz)

Run generate/verify/chain in the browser:

https://stackblitz.com/github/Ataraxialab-ai/TrustProof-Protocol/tree/main/examples/stackblitz

## What it is / What it isn't

What it is:

- stable claims envelope (JSON Schema)
- deterministic canonicalization + hashing
- chain rule for tamper evidence
- golden vectors to prevent drift
- SDKs + CLI to generate/verify

What it isn't:

- Not KYC/KYB
- Not an IdP / auth provider
- Not hosted verification (enterprise implementation layer)

## Docs

- [Spec](docs/spec.md)
- [Security notes](docs/security.md)
- [Demo runbook](docs/demo_runbook.md)
- [Docs site](https://ataraxialab-ai.github.io/TrustProof-Protocol/)
- [Why now](docs/why-now.md)
- [LangChain integration](docs/integrations/langchain.md)
- [OpenAI Agents integration](docs/integrations/openai_agents.md)

## Adoption

- [Adoption guide](docs/adoption.md)

## Protocol Artifacts

- Schema: [`spec/trustproof.schema.json`](spec/trustproof.schema.json)
- Examples: [`spec/examples/`](spec/examples/)
- Vectors: [`spec/vectors/`](spec/vectors/)

## Verifier CLI

```bash
node packages/js/dist/cli.js inspect "<jwt>"
node packages/js/dist/cli.js verify "<jwt>" --pubkey "<pem|b64|path>"
cd packages/py && python -m trustproof inspect "<jwt>"
cd packages/py && python -m trustproof verify "<jwt>" --pubkey "<pem|b64|path>"
```

## Repo Layout

- `packages/js`: `@trustproof/sdk` (generate/verify/chain + CLI)
- `packages/py`: `trustproof` Python package (generate/verify/chain + CLI)
- `spec`: schema, examples, and golden vectors
- `examples`: integration and workflow demos
- `docs`: protocol decisions, spec notes, security, runbooks
- `.github/workflows`: CI for JS, Python, and vectors

## Protocol vs Verdicto Enterprise

| Scope | Includes |
| --- | --- |
| Protocol (OSS) | Schema, canonicalization rules, hash rules, chain rules, golden vectors, JS/Python SDKs, CLI verify/inspect |
| Enterprise mapping (Verdicto) | Key management at scale, hosted verification, dashboards/logs, policy engine, webhooks, step-up UX, multi-tenant operations, SLA/compliance workflows |

Enterprise capabilities map to protocol primitives and are out of scope for the protocol definition itself.

## Security & Correctness

- `pnpm spec:validate` enforces schema and golden vector consistency.
- Mutate one byte in a signed JWT and verification fails (`INVALID_SIGNATURE` / `INVALID_PROOF` paths).
- Golden vectors lock canonicalization/hashing/chain behavior across languages.
- Tampering (payload, hashes, or chain links) breaks verification deterministically.
- Protocol proofs can use hashes/digests; raw PII payload storage is not required.

## License

Apache-2.0. See `LICENSE`.
