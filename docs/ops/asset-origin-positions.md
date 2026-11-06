# Same-vault asset origin-position facts

`federation::record_scope::origin_positions` captures canonical source data
for a same-vault ASSET/ASSET_TEXT position importer. The real window's reverse
pass publishes it beside the exact carrier and native file reference in the
same bridge commit. Own-machine projections copy it; foreign projections do
not. There is no new asset-ingest setting, grant, or nonbase birth path.

## Canonical source capture

The source pins result bodies before opening one read transaction. It compares
the actual window carrier with the canonical stored row in that transaction.
It then reads the actual immutable stored position, not the position that
`scope_for_blob` can derive from a replicated `FacetOf` edge. Only an existing
BASE position of the same kind and birth facet is captured.

The facts bind the entity id, actual kind, birth facet, and BLAKE3 of the whole
logical row, metadata header included. An ASSET on the file plane also binds
the native descriptor-backed `AssetBodyRef`. Its complete logical body is
streamed through the native checked body reader under the snapshot's body
pin. A manifest or digest string alone is not the body proof. Each row also
records the digest of its actual stored native birth when one exists. An
absent birth stays unknown; the header alone is not a universal incarnation
proof.

An ASSET_TEXT captures its complete sorted, distinct native `DerivedFrom`
source set. Every source must be a live ASSET under the same birth facet,
with its own logical digest and native file facts. A source-bound text that
lost its final source does not become an unbound caption. Deleted, stale,
withdrawn, missing, or unplaced rows do not produce new facts.

`OriginPosition::decode` accepts only the canonical encoding. This is data
parsing, not authentication. `matches_in_txn` compares the current canonical
row, full source set, facets, and checked file facts in the caller's
transaction. It does not install or replace a scope stamp.

## Live own-device updates

The optional `origin_positions` lifecycle helpers copy values only beside
identical owner bytes and native file references in the existing own-machine
projection. Foreign copies do not call them. Native owner-removal and egress
scrub paths remove unbound values within their existing pin and bridge commit.
The publisher pins history before replacing or removing older facts. Export
and persistence scrub values whose canonical stamp, full source set, facets,
birth, or checked body no longer matches.

An actor-birth erase also compares each carried owner and source birth digest
with the current canonical birth in the erase's own transaction, after its
birth removals. This covers a caption whose source lives in another window.
Only stale optional position keys leave; a source's removed birth does not
delete the caption's unrelated birth. The existing stored-window bridge,
pending update, history pin, queue scrub, full resync and compaction debt stay
in their original order.

Checkpoint capture files each entire value as row-owned encrypted payload,
with its actual source rows as dependencies. Hashes and scope fields are not
plaintext skeleton structure. A facet id is a position, not necessarily a
stored row, so it is not an invented restore dependency.

For a live own-device UPDATE, preparation reads only optional root values
that the exact admitted payload supplies: snapshot values, or binary map
insert operations inside its native version-vector range. It never treats
the fork's entire earlier state as new evidence. The current owner carrier
and native file reference must bind those exact bytes before preparation and
after the successful observed import. The old generic MESSAGE import wrappers
still return their caller's result unchanged.

The private proof retains the ORIGINAL connection key. The dedicated writer
pins result bodies before its transaction, rechecks that original key against
the current authority fold, and compares the current complete canonical row,
source set, facets, checked files and actual birth digests in that SAME writer.
Every owner and source must have a known native birth. Unknown remains data,
not an incarnation certificate. Native peer-origin tracking includes ASSET
and ASSET_TEXT; the writer excludes a peer-origin owner or source in that
row's actual residence window, not just the caption's window.

Only the existing native BASE/default scope shape can be installed. An
existing immutable stamp always wins, including one current edges do not
validate. This is a dedicated own-device source-position import, not
`RowPut::Birth`, replay authority, restored `FacetOf`, or a new read grant.
Optional metadata errors do not fail an otherwise working raw update.

## Remaining cases

The live client UPDATE and server push success boundaries are wired. Bounded
replacement, deferred/body-later arrival, recovery and later replay do not
mint an import proof. Raw, held, staged, missing or unknown evidence keeps its
existing behavior. Those cases and a production compile/runtime demonstration
remain separate work; this does not close all of FIX40. The older
foreign-Connect proposal is not enabled by this path.
