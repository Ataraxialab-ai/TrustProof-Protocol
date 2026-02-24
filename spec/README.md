# TrustProof Spec

## What is a TrustProof claim object
A TrustProof claim object is a signed-claims/envelope payload (JSON) that captures who acted (`subject`), what action occurred (`action` + `resource`), policy context (`policy`), decision outcome (`result`), integrity digests (`hashes`), replay identity (`jti`), event time (`timestamp`), and chain linkage (`chain`).

## Normative Definitions
- `canonical_json`: recursively sort object keys (UTF-8), arrays preserve order, no whitespace, separators `","` and `":"` only.
- `input_hash = sha256(canonical_json(input))` encoded as hexadecimal, lower-case.
- `output_hash = sha256(canonical_json(output))` encoded as hexadecimal, lower-case.
- `canonical_event_material = canonical_json({ subject, action, resource, policy, result, hashes, timestamp, jti })`.
- `entry_hash = sha256(prev_hash_hex_string + canonical_event_material_utf8_bytes)`.
  - Operationally: concatenate `prev_hash` as a 64-char hex string with the `canonical_event_material` string, then SHA-256 over the resulting UTF-8 bytes.
- Genesis `prev_hash` MUST be `0000000000000000000000000000000000000000000000000000000000000000` (64 zeros).

## Validator Pseudocode
```txt
function canonical_json(v):
  return JSON.stringify(sort_recursively(v))

function sha256_hex(s_utf8):
  return SHA256(s_utf8).hex_lower()

canonical_input  = canonical_json(input)
canonical_output = canonical_json(output)
input_hash  = sha256_hex(canonical_input)
output_hash = sha256_hex(canonical_output)

canonical_event_material = canonical_json({
  subject, action, resource, policy, result,
  hashes: { input_hash, output_hash }, timestamp, jti
})
entry_hash = sha256_hex(prev_hash_hex_string + canonical_event_material)
assert(canonical_input  == vector.canonical_input)
assert(canonical_output == vector.canonical_output)
assert(entry_hash       == vector.expected.entry_hash_hex)
```

## Replay rule
`jti` is required. Verifiers should expose `replay_risk`; `ReplayStore` support is optional in verifier integrations.

## Change Control
Any changes to canonicalization/hashing/chain require updating golden vectors and passing `pnpm spec:validate`.

## Validate locally
From repo root:

```bash
pnpm install
pnpm spec:validate
```
