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

An ASSET peer-origin record keeps its original 32-byte wire digest for
carrier cleanup and adds a 32-byte logical identity: the exact metadata
header plus the native body's BLAKE3, length and `xxh32`. Admission and
staged confirmation compute that identity before import. A bound body
reference supplies the carried facts; a native descriptor selects stored
file facts. Manifest-looking inline bytes never select the file path.
Checks therefore keep the origin across inline/file/reference echoes,
including before the echo lands. A new pending carrier does not replace the
origin of the ASSET still stored locally. Before recording that carrier, the
writer retains only an existing peer entry matching the current canonical
ASSET's native logical identity. The latest carrier's entry follows it;
when no distinct canonical entry is needed, the record holds just the latest
entry. Repeated pending replacements therefore preserve the stored row's
origin without accumulating earlier pending entries. This also applies when
the latest carrier is a different kind and has not replaced the stored ASSET.

A canonical comparison checks both entries and never deletes a different
pending carrier's origin. Exact carrier removal drops only entries with that
wire digest. Actual local re-authoring still clears every origin for that
id. The next carrier writer rechecks which recorded ASSET, if any, is still
canonical. Wire-map digests and copy/stale checks remain unchanged. Other
kinds retain their 32-byte exact-byte entries; a distinct retained canonical
ASSET entry is 64 bytes and precedes the latest entry in the same local
record. There is no old ASSET-record reader or migration.

Only the existing native BASE/default scope shape can be installed. An
existing immutable stamp always wins, including one current edges do not
validate. This is a dedicated own-device source-position import, not
`RowPut::Birth`, replay authority, restored `FacetOf`, or a new read grant.
Optional metadata errors do not fail an otherwise working raw update.

## Own-device bounded replacement

The native replacement manager prepares the exact incoming snapshot's
positions under the original live proof. After the existing concurrent-key,
queued-write and tombstone decisions, it selects only those incoming values
still bound to the chosen candidate, before reverse rematerialization can
remove uninstalled position data. Reverse, forward and canonical export
scrubs keep their original behavior; unsupported root values are not retained
or later published as source truth.

Before the final persistence writer, the caller pins result bodies. An
optional nested savepoint then checks the final candidate's owner carrier
and file reference, original current connection key, complete canonical
facts, known births and every row's peer origin. It installs only the native
BASE/default position with no immutable prior. The savepoint joins the SAME
snapshot/queue/mirror persistence transaction before its existing freshness
write. Any optional failure discards all staged position/revision writes
and leaves ordinary replacement intact. A precommit transaction failure
rolls the metadata back with the snapshot; an after-commit error does not
imply rollback. Observers and registry publication remain last.

Raw/public replacement, sealed relay and kit restore supply no live proof
and do not enter this optional path. Its persistence-bound holder is not a
deferred socket proof.

## Client body-later arrival

Only a complete successful live own-device client UPDATE may retain selected
incoming values in that connection's existing body session. Registration
follows all native no-op, healing and persistence success returns. The
selected owner carrier and file reference must still match; missing root
values deliberately removed by strong scrubs are not restored or exported.
Known births and at least one native file reference are required for this
optional deferred slice.

A weak handle binds each selected witness to the SAME registered window
object, without keeping a window open or delaying replacement. Registration
checks the already-held import window under the registry mutex without
waiting for a transition that may be waiting for that import handle. Retry
resolves the settled registry before taking any window handle. Eviction or
replacement invalidates the weak identity. Reconnecting resets the body session, including
all selected values and local-land effects. New selected values supersede
older values only for the same owner keys; an obsolete window's values leave.

Only the native local close path, after a complete spool really lands, emits
an own-device local-body-land effect. A remote Receipt cannot emit one. A
selected owner or source reference must equal that effect's entire native
encoded reference before the value becomes ready. Earlier local landings in
the same connection also wake matching later selected values. This routing
works across source residence windows; it is not just an owed-window match.

The existing frame/poll housekeeping retries ready values, including after a
caption materializes later than its body. Each retry still requires the live
original window/carrier, ORIGINAL key, complete current canonical facts,
known births, each row's own residence and peer exclusion, and immutable
prior semantics in the dedicated writer, with bodies pinned before it opens.
The local effect schedules a retry; it replaces none of those predicates.
Optional metadata errors leave the working body and raw import paths intact.
No new timer, operating cap, wire tag, retry authority or body plane is added.

## Server-push body-later arrival

A live server push retains its selected witness only after the actual native
observed import has no pending operations, fan-out encoding succeeds, and
any required residence/sidecar acknowledgment has been queued. The original
persist-before-import, import-error eviction, broadcast and receipt ordering
is unchanged. A pending import, held or translated refusal, failed import,
failed fan-out encoding or failed acknowledgment creates no deferred holder.

The socket's existing `ConnState.asset_bodies` owns the witness and local-land
effects. That state is taken only through the connection loop's mutable
borrow, including its existing blocking body handler; it is not a concurrent
shared queue. A minimal opaque core adapter captures the native manager
window's weak identity, without transition waits. The existing live-window
body frame and housekeeping paths retry it. Selector/admitted-copy polling
does not borrow this live-window proof. Socket teardown drops all witnesses.
The same exact local-reference scheduling and current writer predicates as
the client apply; remote receipts still prove no local landing.

## Remaining cases

The live client UPDATE, server push and live own-device bounded-replacement
boundaries are wired. Client and server-push body-later completion stay
within their original live connections. Recovery and later replay do not
mint a deferred import proof. Raw, held, staged, missing or unknown
evidence keeps its existing behavior. Broader modes and a runtime
demonstration remain separate work; this does not close all of FIX40. The
older foreign-Connect proposal is not enabled by this path.
