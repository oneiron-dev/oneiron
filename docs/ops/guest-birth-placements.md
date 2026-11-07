# Guest TASK and SUMMARY birth placements

FIX 3656, Engine ruling A (19:03).

A TASK and a SUMMARY read their world and facet only from their birth stamp.
`stamp_put` never mints a stamp for a replicated non-CLAIM row, so a guest's
TASK or SUMMARY used to land unstamped. A read narrowed on worlds or facets
then kept it out.

## Export

A copy to another vault carries the sender's stamp beside each TASK and
SUMMARY row, in the window map `row_birth_placements`. The key is the row's
canonical hex id. The value is a `BirthPlacement`: the row's kind, its one
world and its one facet, in canonical named MessagePack.

Only a stamp of the shape a local birth door writes travels: a default birth,
`stamp_task_birth` or `settle_epoch_birth`. A row with another stamp, or with
none, carries no placement.

The entry rides in the same update bytes as its row. The federation session
that serves the update, or the guest-share envelope's signature, covers both.
Copies among the owner's own machines carry no placement.

## Admission

`Routes::plan` reads the map of a guest's update before it copies a row.

- An entry that does not decode, or names no row the update carries as that
  kind, refuses the update.
- The sender's base reality maps to the guest's base copy, as a guest CLAIM's
  world does.
- Any other world maps through the `Routes::worlds` map that InWorld and
  SetIn edges use. The update must carry that WORLD row, or this vault must
  already store its foreign copy as a WORLD.
- A world the map does not hold keeps its sender id (#5009). A guest's row is
  never placed at a sender id, so admission refuses the placement and the
  update.

The map never enters the admitted bytes. A member's update, first-party here,
reads no placement, and its rows land as before.

## Landing

Each admitted part holds its rows' validated placements, each bound to the
digest of the bytes admission admitted. The part's import runs inside
`with_placements`. The entity door lands a placement with
`stamp_carried_placement` in the savepoint whose put lands that row here
first. A row already stored here, a row already stamped, or other bytes take
no placement.

## Residuals

- A forward pass, a window open and a staged confirmation replay persisted
  bytes with no placement. Those rows stay unstamped, as a row from an older
  sender does.
- A row that landed unstamped before this change stays unstamped. There is no
  backfill.
