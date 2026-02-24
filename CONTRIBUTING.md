# Contributing

## Pull Request Rules

- PR titles should use one of: `chore:`, `docs:`, `feat:`, `fix:`.
- Target 1-3 PRs/day.
- Keep PRs focused and small.
- Every PR must include a **How to test** section with exact commands.
- Each PR must be mergeable and scope-closed.
- Golden vectors discipline: changes to canonicalization/hashing must update vectors and preserve JS/Py parity.

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
