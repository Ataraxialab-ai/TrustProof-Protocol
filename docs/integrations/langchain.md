# LangChain Integration

## What It Does

`wrapToolWithTrustProof(...)` wraps a LangChain tool call and emits a TrustProof JWT per invocation.

For each call, it:

- executes the original tool
- hashes canonicalized `input` and `output`
- builds claims envelope fields
- signs with `generate(...)`
- optionally chains with prior proof in memory

Implementation:

- [`../../packages/js/src/integrations/langchain.ts`](../../packages/js/src/integrations/langchain.ts)

## Run the Example

```bash
pnpm --filter @trustproof/sdk example:langchain
```

Example script:

- [`../../examples/integrations/langchain/tool_call_proof.mjs`](../../examples/integrations/langchain/tool_call_proof.mjs)

## Minimal Usage

```ts
import { wrapToolWithTrustProof } from "@trustproof/sdk";

const wrapped = wrapToolWithTrustProof(tool, {
  privateKeyPem,
  subject: { type: "agent", id: "agent_demo_1" },
  action: "agent.tool.payout.quote",
  resource: { type: "tool", id: "payout.quote" },
  policy: { policy_v: "v0", scopes: ["tools:invoke"], constraints: {} }
});

const { output, proof_jwt } = await wrapped.invoke(input);
```

## Naming Convention

Use stable, parseable action names:

- `agent.tool.<domain>.<operation>`
- examples: `agent.tool.payout.quote`, `agent.tool.payout.initiate`
