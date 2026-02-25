# Why Now

## Shift: Chat to Actions

Agents are moving from answering questions to executing real operations:

- initiate payouts
- approve internal workflows
- trigger infrastructure changes
- execute tool chains autonomously

Action systems need verifiable evidence, not just conversational transcripts.

## Logs Are Not Enough

Traditional logs are useful for debugging, but weak for portable trust:

- format varies by platform
- tamper detection is inconsistent
- replay and chain context are usually external
- third parties cannot reliably verify without full platform access

For high-risk operations, "trust us, check our logs" does not scale.

## Protocol Approach

TrustProof uses signed, portable action receipts:

- deterministic envelope schema
- canonicalization + hashing rules
- replay identifier (`jti`)
- optional tamper-evident chain (`prev_hash` / `entry_hash`)
- language parity via golden vectors

Any verifier with the public key can independently check integrity.

## What This Enables

- Fintech payouts:
  prove how `allow` vs `step_up` decisions were produced.
- Enterprise approvals:
  carry signed evidence across systems, teams, and auditors.
- Agentic operations:
  chain tool actions with tamper-evident linkage for incident review.

## Practical Outcome

TrustProof separates evidence from execution platforms.  
That makes verification portable, testable, and automatable across organizations.
