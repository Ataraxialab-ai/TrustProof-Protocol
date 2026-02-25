# LangChain Tool Proof Example

Run from repo root:

```bash
pnpm --filter @trustproof/sdk build
pnpm --filter @trustproof/sdk example:langchain
```

This demo executes a local `DynamicTool` twice, emits a TrustProof JWT per call, verifies both proofs, and verifies chain linkage between them.
