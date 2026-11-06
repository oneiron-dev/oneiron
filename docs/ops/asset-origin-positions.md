# Same-vault asset origin-position facts

`federation::record_scope::origin_positions` captures data for a future
same-vault ASSET/ASSET_TEXT position importer. It does not publish a window
root, import a position, or change any reader's scope. There is no new public
asset-ingest setting, grant, or nonbase birth path.

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
pin. A manifest or digest string alone is not the body proof.

An ASSET_TEXT captures its complete sorted, distinct native `DerivedFrom`
source set. Every source must be a live ASSET under the same birth facet,
with its own logical digest and native file facts. A source-bound text that
lost its final source does not become an unbound caption. Deleted, stale,
withdrawn, missing, or unplaced rows do not produce new facts.

`OriginPosition::decode` accepts only the canonical encoding. This is data
parsing, not authentication. `matches_in_txn` compares the current canonical
row, full source set, facets, and checked file facts in the caller's
transaction. It does not install or replace a scope stamp.

## Not activated

The same-vault carrier still needs source publication into the real window,
paired-row selection and erasure, checkpoint ownership, and an authenticated
success hook. Its dedicated importer must bind the exact admitted update,
exclude native peer-origin rows, recheck the original proven machine key in
its writer, and keep conflicting prior positions unchanged. A connection's
own-device proof is not an origin writer or a read grant.

Missing evidence, raw replay, recovery, held rows, and staged rows keep their
existing behavior. No local `RowPut::Birth` or restored `FacetOf` may stand in
for an authenticated source position. The older foreign-Connect proposal is
not enabled by this source module.
