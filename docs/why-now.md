# Why Now

## Shift: Chat to Actions

Agents are moving from answering questions to executing real operations:

- initiate payouts
- approve internal workflows
- trigger infrastructure changes
- execute tool chains autonomously

Action systems need verifiable receipts, not only conversational transcripts.

## Logs Are Not Enough

Traditional logs are useful for debugging, but weak for portable trust:

- format varies by platform
- tamper detection is inconsistent
- replay and chain context are usually external
- third parties cannot reliably verify without full platform access

For high-risk operations, logs alone are insufficient for independent verification.

## Protocol Approach

TrustProof uses signed action receipts with deterministic verification:

- deterministic envelope schema
- canonicalization + hashing rules
- replay identifier (`jti`)
- tamper-evident chain (`prev_hash` / `entry_hash`)
- language parity via golden vectors

Any verifier with the public key can independently check signature and integrity.

## What This Enables

- Fintech payouts:
  prove how `allow` vs `step_up` decisions were produced.
- Enterprise approvals:
  carry signed evidence across systems, teams, and auditors.
- Agentic operations:
  chain tool actions with tamper-evident linkage for incident review.

## Practical Outcome

TrustProof keeps verification portable across execution platforms and organizations.
