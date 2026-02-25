# TrustProof StackBlitz Playground

This playground runs TrustProof end-to-end in one file:

- generate a JWT proof (`generate`)
- verify signature + schema (`verify`)
- append a chained proof (`append`)
- verify chain integrity (`verifyChain`)
- show tamper failure by mutating one JWT character

It imports SDK functions directly from repo source (`../../packages/js/src/index.ts`), so no npm publish is required.

## Run

```bash
npm install
npm start
```

## Expected output (example)

- `verify(jwt1): ok=true`
- `verify(jwt2): ok=true`
- `verifyChain([jwt1,jwt2]): ok=true`
- `Tamper => OK (failed as expected)`
