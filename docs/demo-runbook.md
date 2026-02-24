# TrustProof Demo Runbook

## Goal
Prove protocol + repo health in under 5 minutes.

## Steps
From repo root:

```bash
pnpm install
pnpm -r test
pnpm -r build
pnpm -r lint
python -m pip install -e "packages/py[dev]"
python -m pytest -q
```

## CLI Placeholder
If the Python package is installed in the current environment:

```bash
trustproof --help
```

Current CLI behavior is placeholder-only. Future proof inspection flow (placeholder):

```bash
trustproof inspect <jwt>
```

## Next Milestone
Next demo milestone: tamper-evidence + golden vectors.
