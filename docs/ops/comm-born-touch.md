# Explicitly born communication touches

A reader-bound or actor-bound batch can project a canonical `comm.last_touch`
Put with an explicit `RowBirth` without replacing its original claim id. It can
also project one whose only noncanonical context is a non-base world, using
the scoped source described in `comm-scoped-touch-source.md`.

The batch keeps that Put, its `ClaimOf` edges, and its birth in the ordinary
native write. Its existing input, caller-envelope, source, policy, actor or
reader checks still run. Only after the original row and immutable birth are
staged does the same writer record a `TouchAsserted` source and reconcile the
original claim as the actual communication head. There is no second derived
claim and no copied birth. The original body and header stay the native
writer's; normal supersession can close the losing head.

The source's `original_head` is bookkeeping, not write authority. Projection
requires that actual original CLAIM, its native birth, its matching touch value,
and its live `ClaimOf` edge. Missing rows or births leave the source pending;
a closed or retracted original is not revived. The ordinary slot winner and
supersession rules still apply, including caller checks on other heads.
Provider aliases share their normal normalized slot without rewriting the
original touch's body.

The source id derives from the original id, full actual stored row, and actual
base birth. Adoption rechecks that binding, so a pending source cannot use a
later scope, envelope, header, or birth revision that happens to state the
same touch value. Closed historical heads still stay closed. Exact retries
keep that source record. Retrying an original Put
still reconciles its current live head even if the source already projected;
`minted = false` is not used to skip this reconciliation.

This applies only to the canonical and world-only explicit-born touches
admitted through these bound batch paths. Other explicit births, STOPs,
thread events, other noncanonical scope/context, and unsupported cases retain
the fully gated raw path. Ordinary no-birth source creation is unchanged.
LastTouch slot selection compares the full context for every source, so a
base event and a world-bearing head cannot supersede each other.

`COMM_RECORD` has the required `original_head` key: an entity id for this
TouchAsserted case, `nil` otherwise. Every original-head source also requires
its typed `source_position`, including canonical base-world sources. They
retain the original CLAIM disclosure band and audience requirements; they are
not readable through a COMM_RECORD-only selector. The strict format and
unified born-source id binding are described in `comm-scoped-touch-source.md`.
When a batch has an eligible born touch, its ordinary routed touches join the
same post-native assertion schedule in original Put order. Later unprocessed
born Puts are excluded from each earlier assertion's projection, so the later
assertion wins a time tie even when only one Put has an explicit birth. STOP
and thread events keep their original pre-apply phase. Batches without born
touches keep their original event phase and order. Original routed inputs
still pass their policy and caller preflight before native apply.
Deploy matching engine/server binaries
at the normal authorized release. There is no migration, old-format reader,
new configuration, policy cap, or numeric default.
