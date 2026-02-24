# Contributing

## Pull Request Rules

- Target 1-3 PRs/day.
- Keep PRs focused and small.
- Every PR must include a **How to test** section.

## Local Verification

```bash
pnpm install
pnpm -r lint
pnpm -r test
pnpm -r build
```

```bash
cd packages/py
python -m pytest -q
```
