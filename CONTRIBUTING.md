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

## Add an Integration (Recipe)

### Integration Contract

- Implement integration code in `packages/js/src/integrations/<name>.ts` (or add docs if code is out of scope).
- Add a runnable example in `examples/integrations/<name>/`.
- Add an SDK script in `packages/js/package.json`:
  - `example:<name>`
- Integration example must emit at least one proof and show `verify(...)` succeeds.

### Testing Checklist

Run from repo root unless noted:

```bash
pnpm spec:validate
pnpm --filter @trustproof/sdk test
pnpm --filter @trustproof/sdk example:<name>
```

If parity-related files are touched:

```bash
cd packages/py
python -m pytest -q
```

### PR Requirements

- Include a **How to test** section with exact commands.
- Link to generated example output artifacts (or output paths), when applicable.
- For protocol-impacting changes (canonicalization/hash/chain), update vectors and document compatibility implications.
