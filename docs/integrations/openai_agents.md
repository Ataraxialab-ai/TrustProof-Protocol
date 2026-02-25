# OpenAI Agents Integration

## What It Does

`createTrustProofAgentHook(...)` provides SDK-agnostic hook handlers for agent lifecycle events.

For each completed action/tool event, it:

- computes canonical input/output hashes
- creates a claims envelope
- signs a JWT proof
- chains proofs in memory when enabled

Implementation:

- [`../../packages/js/src/integrations/openai_agents.ts`](../../packages/js/src/integrations/openai_agents.ts)

## Run the Example

```bash
pnpm --filter @trustproof/sdk example:openai-agents
```

Example script:

- [`../../examples/integrations/openai_agents/on_action_proof_chain.mjs`](../../examples/integrations/openai_agents/on_action_proof_chain.mjs)

## Minimal Usage

```ts
import { createTrustProofAgentHook } from "@trustproof/sdk";

const hook = createTrustProofAgentHook({
  privateKeyPem,
  subject: { type: "agent", id: "agent_demo_1" },
  policy: { policy_v: "v0", scopes: ["tools:invoke"], constraints: {} },
  chain: { enabled: true }
});

const { proof_jwt } = await hook.onToolEnd({
  tool_name: "payout.initiate",
  input,
  output,
  action_name: "agent.tool.payout.initiate"
});
```

## Connecting to Real Agents SDK Callbacks

Keep the adapter thin:

- map SDK callback payloads into the internal event shape (`action_name`, `tool_name`, `input`, `output`, `resource`, `timestamp`, `jti`)
- call `onToolEnd(...)` / `onActionEnd(...)` at completion points
- persist `getChain().proofs` externally if you need cross-process continuity

Avoid deep coupling to transient SDK types; keep mapping logic isolated.
