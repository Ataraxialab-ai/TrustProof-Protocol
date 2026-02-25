# TrustProof Protocol
https://ataraxialab-ai.github.io/TrustProof-Protocol/

Signed, verifiable action receipts for humans + agents.

[![Spec Validated](https://img.shields.io/badge/spec-validated-blue)](#quickstart)
[![TypeScript](https://img.shields.io/badge/language-TypeScript-3178c6)](#)
[![Python](https://img.shields.io/badge/language-Python-3776ab)](#)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-black)](https://ataraxialab-ai.github.io/TrustProof-Protocol/)
[![Verified](https://img.shields.io/badge/verified-trustproof-lightgrey)](docs/badge.md)

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

**Protocol (OSS):** schema, canonicalization, hashing, chain rules, golden vectors, JS/Python SDKs. **Verdicto Enterprise:** hosted verification APIs, dashboards, webhooks, policy engine, step-up UX, compliance/audit workflows, multi-tenant key management, SLA-backed operations.

## Security & Correctness

- Golden vectors lock canonicalization/hashing/chain behavior across languages.
- Tampering (payload, hashes, or chain links) breaks verification deterministically.
- Protocol proofs can use hashes/digests; raw PII payload storage is not required.

## License

Apache-2.0. See `LICENSE`.
