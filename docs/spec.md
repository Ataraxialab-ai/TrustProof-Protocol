# TrustProof Spec

## What is a TrustProof

A TrustProof is a claims envelope (JSON) signed as a JWT.  
The signed payload captures actor, action, policy context, result, integrity hashes, and chain linkage.

Primary functions:

```txt
generate(claims, privateKeyPem, opts?) -> jwt
verify(jwt, publicKeyPem, opts?) -> { ok, claims, errors[] }
append(prevJwtOrClaimsOrNull, nextClaims, privateKeyPem, opts?) -> jwt
verifyChain(jwts[], publicKeyPem, opts?) -> { ok, errors[] }
```

## Envelope Fields (v1)

- `subject`: actor identity (`type`, `id`)
- `action`: operation name (for example `payout.initiate`)
- `resource`: target (`type`, `id`)
- `policy`: policy version/scopes/constraints
- `result`: decision + reason codes
- `hashes`: `input_hash`, `output_hash`
- `timestamp`: event timestamp (ISO UTC)
- `jti`: replay identifier (required)
- `chain`: `prev_hash`, `entry_hash`

Schema:

- [`../spec/trustproof.schema.json`](../spec/trustproof.schema.json)

Examples:

- [`../spec/examples/allow.json`](../spec/examples/allow.json)
- [`../spec/examples/deny.json`](../spec/examples/deny.json)
- [`../spec/examples/step_up.json`](../spec/examples/step_up.json)

Vectors:

- [`../spec/vectors/`](../spec/vectors/)

## Canonicalization and Hash Rules

Normative definitions are in:

- [`../spec/README.md`](../spec/README.md)

In brief:

- Canonical JSON is deterministic (sorted object keys, compact separators).
- `input_hash = sha256(canonical_json(input))`
- `output_hash = sha256(canonical_json(output))`

## Chain Rules (Summary)

- `canonical_event_material = canonical_json({ subject, action, resource, policy, result, hashes, timestamp, jti })`
- `entry_hash = sha256(prev_hash_hex_string + canonical_event_material_utf8_string)`
- Genesis `prev_hash` is 64 zeros.

Reference vectors:

- [`../spec/vectors/v001_allow_basic.json`](../spec/vectors/v001_allow_basic.json)
- [`../spec/vectors/v004_chain_linking.json`](../spec/vectors/v004_chain_linking.json)
- [`../spec/vectors/v005_canonicalization_edge.json`](../spec/vectors/v005_canonicalization_edge.json)

## Validate the Spec

From repo root:

```bash
pnpm spec:validate
```

CLI verification commands:

```bash
trustproof inspect "<jwt>"
trustproof verify "<jwt>" --pubkey "<pem|b64|path>"
```
