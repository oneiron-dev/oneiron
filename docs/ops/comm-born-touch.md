# Explicitly born communication touches

A reader-bound or actor-bound batch can project a canonical `comm.last_touch`
Put with an explicit `RowBirth` without replacing its original claim id.

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
base birth. Exact retries keep that source record. Retrying an original Put
still reconciles its current live head even if the source already projected;
`minted = false` is not used to skip this reconciliation.

This applies only to canonical, explicit-born touches admitted through these
bound batch paths. Other explicit births, STOPs, thread events, noncanonical
scope/context, and other unsupported cases retain the fully gated raw path.
Ordinary no-birth source projection is unchanged.

`COMM_RECORD` now has the required `original_head` key: an entity id for this
TouchAsserted case, `nil` otherwise. Deploy matching engine/server binaries
at the normal authorized release. There is no migration, old-format reader,
new configuration, policy cap, or numeric default.
