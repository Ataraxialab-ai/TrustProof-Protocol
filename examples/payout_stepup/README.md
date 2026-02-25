# payout_stepup example

Demonstrates policy outcomes for payouts and chained step-up approval proofs.

## Scenario

- Case A: payout `25.00 USD` to `m_alpha` => `allow`
- Case B: payout `7500.00 USD` to `m_alpha` => `step_up`
- Optional follow-up: `payout.step_up.approve` => `allow` chained from the step-up proof

## Run

From repo root:

```bash
pnpm --filter @trustproof/sdk build
pnpm --filter @trustproof/sdk example:payout-stepup
```

## Output

- `examples/output/payout_stepup/proofs.json`
- `examples/output/payout_stepup/summary.txt`
