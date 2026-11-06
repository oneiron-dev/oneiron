# Claim descriptor validation

Claim-class descriptors are synchronized maintenance entities. A readable stored
row supplies the class's current validation semantics. If that row is absent,
unreadable, or names another predicate, the existing compiled descriptor remains
the fallback.

## Transactional validation

Local writes and sync replay use the descriptor visible in their transaction.
The common claim validator still checks the claim envelope, source lineage,
carry-forward, e-sign events, supersession provenance, and the existing builtin
family validators. A class compiled as generic uses the resolved generic
descriptor instead of first requiring its value to satisfy the compiled seed as
well. If its current descriptor is builtin, the native family validator runs.

The raw-put builder preflight and base-write taint scanner decode only the
envelope fields they need for source rules and reference checks. Full class
validation remains at the actual write admission before mutation. Demotion,
lifecycle-close, and the updated verified-transition next bodies use their
existing transaction; their predecessor reads and proof conditions are unchanged.

This matters when the stored generic schema differs from the seed. A value
allowed by the stored schema must not be rejected by a narrower seed before the
stored descriptor is checked. The stored schema still rejects values it does
not admit. The descriptor's subject-kind checks also remain in force.

## Federation

Guest routing, claim-blob admission, and confirmation of already-admitted bytes
use the receiving vault's readable descriptor in their read transaction. They
do not use an uncommitted descriptor supplied by the peer as authority. Existing
guest-world rewriting, source grading, policy checks, quarantine handling, and
confirmation digest bindings are unchanged. The write/replay door validates
again in its own transaction before applying the claim.

## Unchanged boundaries

Stateless validation without a vault transaction still uses the compiled seed.
This change does not retire the remaining builtin family validators or turn
other families into generic classes. It does not change descriptor governance,
enforcement stamps, local policy, the compiled vocabulary, storage formats, or
any provider behavior.
