# agent_actions example

Simulates two agent tool actions, produces chained TrustProof JWTs, and demonstrates tamper detection.

## Actions

- `agent.tool.payout.quote`
- `agent.tool.payout.initiate`

## Run

From repo root:

```bash
pnpm --filter @trustproof/sdk build
pnpm --filter @trustproof/sdk example:agent-actions
```

## Output

- `examples/output/agent_actions/proofs.json`
- `examples/output/agent_actions/summary.txt`
