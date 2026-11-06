# Record/document transport source metadata

An authenticated own-device import can capture the exact SKILL record/document pair it carried. This records transport facts, not authorship, a grant, native admission, or a completed write.

## Capture and persistence

The private import span captures the vault, window, sending MACHINE and pair digests. A materializer error returns the original error. A successful outer import returns its original value with an optional, uncommitted capture. The client checks its original inner transport result before using that capture. An error does not imply that earlier canonical entity writes rolled back.

The original update writer persists the accepted `u:w:` update, then reconstructs `d:w:` plus every surviving `u:w:` row in that same transaction. A successful no-op import also runs this source persistence step. Only an originally captured pair that matches this actual durable carrier can produce a source row. Missing pairs produce no source fact and do not reject the canonical import.

The capture checks carried peer origin before the peer-origin exclusion and excludes erased entities or senders. Its private writer product holds the original mutable transaction. The Store sink consumes that product; it does not accept an arbitrary decoded row or caller-supplied Loro document as proof.

## Stored format

`SYNC_RECORD_DOCUMENT_SOURCE` uses the `sync_state` prefix `record:source:`. Its key is:

```text
record:source:<window>:<entity hex32>:<pair identity hex64>
```

Its named MessagePack value contains the sending MACHINE id, exact pair digests, and the canonical `CarriedRecordDocument` head bytes. It stores no record body, document snapshot, or duplicate history. The head remains the existing native metadata codec, not a parallel descriptor schema.

The key includes the whole pair identity, so another pair does not overwrite an earlier transport fact. Folding pending updates does not delete these rows.

## Checkpoints and erasure

The restore class is historical CONTENT. Payload classification starts as Unclassified. A row becomes Structure only after the actual canonical head, entity, row digest, head hash, key tuple, MACHINE id and named encoding validate. Invalid or mismatched rows stay Unclassified under the image's seal. A decoded row is not authentication.

A valid structural row depends on its entity and sending MACHINE. The existing authenticated checkpoint landing and opened-owner/erasure filtering remain required. `CanonicalSnapshot` remains the closed window manifest; it gains no arbitrary database-row vocabulary.

Generic entity/MACHINE erasure removes source rows naming that entity or sender in the same writer. Exact window removal deletes only that window's transport metadata, not its members' documents, history, sequence rows or provenance.

The owner's constrained entity-document history purge also removes affected transport facts in its original writer. Its private cut product holds the actual entity, incarnation, old shallow floor, new shallow floor and mutable transaction. A source is affected only when its retained per-peer operation interval intersects the operations that cut removed. This includes another logical-document alias of the same incarnation when it retains those operations. An already-shallow source that excludes them stays. A version that covers the new floor can still retain erased older operations; version coverage alone does not keep its source fact.

## Retained transport selection

A replay without a matching live import can select the exact persisted transport fact through the Store's private reader. The reader checks the canonical metadata, its exact key, entity and sender erasures, and retained stored bytes. The sync owner then reconstructs the actual durable `d:w:` snapshot plus every surviving `u:w:` update in that same transaction. Its row, document head, snapshot and FIRST must match the selected pair. A decoded row, a caller's Loro document, or a negative peer-origin marker alone supplies no transport proof.

Every batch-consumption recheck repeats the metadata and durable-carrier comparison and the original live-carrier, carried-origin and peer-origin checks. Live import selections still require their original current weak scope. Retained selections do not require a new live `OwnDeviceImport` or new historical MACHINE standing.

## Admission boundary

Retained transport selection supplies transport facts to the existing record/document candidate. It is not retained native-operation admission. The candidate and every original record phase still judge the current local document, exact source records and native continuations. A persisted source row is not `SkillStateWrite`, a native final input, or a commit receipt. The full retained native source/admission producers, mirror and native root-list activation remain separate work; capture, persistence and transport readmission alone do not supply them.

## Native materializer failure

A native put's real `AppliedRecordDocument` now stays owned through the entity savepoint and the observer's outer materializer. It is produced only after the original batch checks; a selected pair or lower installer cannot fabricate it. The original row's final caller checks still run before it is returned.

If the outer grouped writer reports an error, the observer compares each real native result with one committed read view: the physical row, head, all document rows and ordered updates, FIRST origins, and refinement control. The read view closes before the existing retry-marker writes. A mismatch or read error leaves that entity for replay. A later error can occur after commit, so an error alone is not proof that the native write was lost.

Only the exact native `(entity, raw row)` uses this complete-output comparison. Other operations keep the original physical parity and echo handling, with comparison before de-duplication. A match is retry bookkeeping, not native admission or an outer commit receipt. Successful materializer outputs and watch/revision handling stay unchanged.

## SKILL checkpoint content codec

`sync::skill_docs::checkpoint` can split one exact historical carried head with its captured row and parts. The snapshot uses the existing whole-history entity-document actor codec. FIRST stays the exact immutable Candidate row under the SKILL owner, following the generic entity-row getter. Its revision and permanent body hash still validate.

The content keeps neither leg's original part manifest. Joining fills only the snapshot actors that opened, validates the rebuilt native document against the same row, and re-parts snapshot and FIRST independently. Shared digests and repeated parts keep their per-leg positions. A short final snapshot piece is not concatenated with FIRST. The restored head names the actual rebuilt bytes and their new digests. A history-equivalent Loro encoding can change those digests even when every actor opened.

The window integration below now consumes this codec through its native source owner. The codec alone is not native-operation admission and does not activate mirror publication or canonical native producers.

## Historical SKILL checkpoint capture

`sync::skill_docs::checkpoint::capture` now reads a closed Loro document through the vendored root-map capture. It returns sources only after the whole export succeeds. The caller must pass the document already opened over the window snapshot and its pending/queued updates. This is a read-only intermediate, not the window's emitted carrier. Its temporary plain-key skeleton is discarded; its digest keys must never become checkpoint Structure.

Each carried head keeps its real shallow-root or retained-operation site. The native record's `row_digest` selects the exact historical entities-map bytes, rather than the current winner or callback order. The normal paired codec then validates that row, the document history and immutable FIRST. Each snapshot/FIRST descriptor position keeps every observed write of its part. Repeated positions, shared parts and multiple historical heads are not collapsed into one source or one digest-to-position map. Callback atom ids are checked against the completed temporary capture and are not final projected slot ids.

The production window preparation below consumes this historical catalog in its final source-aware classification. The temporary catalog remains private and is never emitted. Native permission, authenticated native source-metadata rebinding and the other outstanding producers are unchanged.


## Independent native window source copies

The window source owner in `sync/checkpoint_payload/record_documents.rs` prepares
all historical SKILL pairs from the same opened document. It uses each exact
historical entities row's existing placement, not a root-wide holder. Binding
uses native `Site::Op`/shallow-root identity against the final capture, so added
withheld-key slots do not turn temporary callback ordinals into final slot ids.
Each original descriptor position retains all of its writes, including shared
writes in other heads or the other leg. Only final slot references, opaque entity
keys, copy locators and actor field names leave that ephemeral preparation;
original heads and actor-bearing part digests do not become outer structure.

The owner emits one actor-free native content copy per rightful holder and seals
its native history actors beside that exact copy. Opening checks the copy's
actual authenticated home, actor-part locator, field and id bytes, then uses the
paired native codec independently for each source. A missing source remains
absent at its own position; it is not replaced by another source sharing a write.
The paired codec also returns the exact entities row. Its rebuilt snapshot and
FIRST retain all new pieces without a bound from the old descriptor count.

Window preparation and FRAME4 now carry this source-copy module through the
reconstruction below. One fixed native map operation still cannot silently stand
for extra operations, and divergent shared uses cannot be erased or first-selected
to make a join pass. No source data here grants native permission; canonical native
producer and mirror activation remain separate.


### Native window source-bank framing (source only)

The independent SKILL source bank now has a canonical binary spelling in
`sync/checkpoint_payload/frame/record_documents.rs`. It reuses the outer
carrier's copy-locator, home and dependency encoding. Each source keeps its own
copies, actor holes and final head/row/part slot uses. Repeated descriptor
positions and writes shared by different sources are not deduplicated. The bank
contains no original head bytes, part digests or actor payloads.

Both encoding and decoding validate against the actual final outer skeleton.
Every value reference must be a retained native write or a shallow winner, with
any retained/shallow alias agreeing on root, key, peer and Lamport timestamp.
Latest-state entries alone do not establish a source. Head and row references
keep the exact entity key; each native part reference must name its actual
withheld key slot. The source owner's opening function takes that same skeleton
and validates these references before reading authenticated holder copies.

This remains the source bank's first format, with no old-format reader. FRAME4
now embeds that exact bank against its outer skeleton. Opened history and newly
derived digests remain data, not native operation authority.


## Final native window classification

`PreparedRecordDocuments::classify` now drives the real root-map capture with
native SKILL head, entities-row and snapshot/FIRST part ownership. It matches
values by their actual `Site::Op` or shallow `Site::Root`, key and native bytes.
Every source sharing a write contributes its rightful holders. Digest keys are
withheld under the union of their source holders. Ordinary window families
still use their existing classifier, including the manifest-noting pass.

The returned `ClassifiedRecordDocuments` owns the final `Parts`, ordinary
plans/homes and all native source bindings together. Native plans do not hold
original head, row, part or digest-key bytes for scalar emission. Its native
slot set must exactly equal all value/key uses in the bound source bank,
including repeated descriptor positions and aliases. This private, non-wire
product cannot be passed to the ordinary scalar-slot emitter.

Production `operations::prepare` now consumes this complete classification.
Its native-aware root-map capture includes SKILL without changing ordinary family
placement. Opening a holder compartment is custody/data authentication, not native
operation authority. No source is selected in place of another, no extra part is
discarded and no old part count becomes a bound.

## Authenticated window restore source and writer

The real checkpoint payload open now constructs a private window restore
source only after the artifact's custody plan has opened its original
bundles. It binds the same image carrier records, authenticated window
compartments and unopened-owner set. The sync restore port consumes this
source instead of accepting those three independently supplied arguments.
Holder metadata and an opened-home answer remain data checks, not a way to
construct the source or admit a native operation.

The joined rows remain in a private prepared product through the original
write-budget calculation. The original restore writer consumes that product
after the content/carrier bundles and before call rows. Row order, errors,
markers, erasure filtering and snapshot/pending/queue slicing are unchanged.
This connects the authenticated source to the actual applying writer. The native
source-aware restore below now feeds its real reconstructed rows into that same
prepared product and writer. It does not supply native-operation admission or
activate canonical native producers.

## Native operation reconstruction (source only)

The classified source owner now has a concrete per-window reconstruction entry.
It rejoins each original native source once across the snapshot and combined
pending/queued groups. Identity is the original head operation, or its actual
nonretained shallow winner, plus the entity key; never a digest or temporary atom
ordinal. Both groups use that same native transport and one shared fresh-peer
allocator over all original peers.

Reconstruction replaces each head at its original operation id. Every original
head/row operation retains its id, dependency, Lamport time and timestamp. Old
native part values and withheld keys become deletes at their original ids, so no
actor-bearing old part bytes remain in an allegedly immutable base. Each rebuilt
snapshot and FIRST descriptor gets a real additional map operation on its source's
fresh peer, including repeated positions and shared pieces. Same-key pieces must
be byte-equal. Native heads still use opaque entity keys; piece keys use `part/`.

Added operations depend on the original head, or the actual retained shallow
frontier for a nonretained head. The original operations do not gain invented
dependencies. Each update retains its exact original operation spans and adds only
the extension of heads actually in those spans. A snapshot includes its own
extensions; they are not copied wholesale into every pending or queued row. The
per-window coordinator replays the actual output snapshot and update slices and
compares the full retained history, versions, frontiers, shallow boundary and
latest values against the complete reconstructed document before returning rows.

This proof is against an explicitly extended scratch skeleton, not the original
version vector. Added source spans and native source/actor availability are
reported separately. The ordinary `WINDOW_ROUND_TRIP` remains unchanged. The
opened-source entry first uses the original authenticated home and actor-part
checks; a decoded source or generated piece is not native operation permission.
Its per-window cache shares a native rejoin only after each source's own copy
opened with equal content and actor fields at the same original head. An absent
copy is never filled from the cache. The cache and its shared transports end with
the reconstruction call. Original native opening checks are unchanged.

Even when all native content opened, old part operations were rewritten.
`native_lossless` reports content/actor availability; `rewritten_native_history`
reports that separate history change. Source-aware restore must not use the first
as an unchanged-original-history verdict or skip the existing altered-history
marker rule. An ordinary snapshot with no SKILL source remains a valid base for
the first native head in a pending update.

Production preparation, FRAME4, copy enumeration and authenticated restore now
consume this kernel as described below. Canonical native admission, source-metadata
rebinding, mirror and native producers remain separate. This source implementation
is not a compiler result or runtime proof.


## Native sources in the actual checkpoint carrier

`operations::project` prepares both a window's original snapshot and combined
pending/queued groups before emitting any native source. Ordinary values still
prove their family codec, repository-manifest bindings and joined-turn erasure
forms. A native window then runs the shared all-open reconstruction across both
actual classified groups and exact original slices. Failure keeps its rows whole
and emits no native source; source-free groups keep their ordinary history proof.

`LoroCarrier` owns every independent native source bank beside its ordinary slots
and joined turns. Native value and withheld-key slots are empty shells, never raw
scalar copies. `copies()` includes every native source copy, so the original seal
and authenticated-open path handles its actual holder, dependencies and actor
parts. FRAME4 embeds the canonical source bank against the same final skeleton.
There is no FRAME3 reader, migration or ignored native field.

Restore first opens ordinary keys and values with their original home and family
checks, skipping only validated empty native slots. It groups the actual carriers
by window, opens each source's own authenticated copy and runs one shared native
reconstruction for snapshot and pending/queued groups. Returned rows use their
actual extended slices, not an export with the old spans. Queue wrapping, row
locators and final carrier/row order stay unchanged. Missing native copies enter
the existing dropped-copy list.

The real artifact-opened source supplies these rows to the existing prepared
window restore, write-budget calculation and same transaction writer. Every
restored window still gets the full-resync marker. A native rewrite also uses the
existing altered-history history-free rule even when all source content opened.
Its verdict reports native content availability separately from rewritten history
and does not claim original `WINDOW_ROUND_TRIP` equivalence. No new refusal policy,
operating cap, default, grant or authority witness is introduced.
