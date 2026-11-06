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

This codec is not wired into window capture/restore or the root registry yet. Historical head/row association, shared-part slot ownership and changed-content window reconstruction still belong to that integration. The codec alone does not make SKILL roots classified or activate native operations, mirror publication, or checkpoint restore.

## Historical SKILL checkpoint capture

`sync::skill_docs::checkpoint::capture` now reads a closed Loro document through the vendored root-map capture. It returns sources only after the whole export succeeds. The caller must pass the document already opened over the window snapshot and its pending/queued updates. This is a read-only intermediate, not the window's emitted carrier. Its temporary plain-key skeleton is discarded; its digest keys must never become checkpoint Structure.

Each carried head keeps its real shallow-root or retained-operation site. The native record's `row_digest` selects the exact historical entities-map bytes, rather than the current winner or callback order. The normal paired codec then validates that row, the document history and immutable FIRST. Each snapshot/FIRST descriptor position keeps every observed write of its part. Repeated positions, shared parts and multiple historical heads are not collapsed into one source or one digest-to-position map. Callback atom ids are checked against the completed temporary capture and are not final projected slot ids.

This implements historical pair capture, not its window projection. The source catalog is not connected to `operations::prepare`, emitted frames, seal/open/restore, changed piece-count reconstruction, or authenticated source-metadata rebinding yet. The emitted root registry is unchanged, so SKILL windows still use their existing unclassified route. Native permission and the other outstanding producers are unchanged.


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

This source-copy module is not yet connected to window prepare, the carrier's
wire frame or outer reconstruction. A variable number of rebuilt part writes
still needs a real expansion/placement representation and the authenticated
opened-checkpoint source writer. One fixed native map operation cannot silently
stand for extra operations, and divergent shared uses cannot be erased or
first-selected to make a join pass. SKILL remains absent from the emitted window
root registry. No source data here grants native permission, and no complete
window round-trip or root activation is claimed.


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

This is the source bank's first format, not a new spelling of `LoroCarrier` and
not an old-format reader. It does not connect the real operations classifier,
outer carrier field, variable piece-count reconstruction, row-slice export or
authenticated native source writer. SKILL root activation remains off. Opened
history and newly derived digests remain data, not native operation authority.


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

This is source classification, not activation. The production window root
registry and `operations::prepare` remain unchanged. The actual outer carrier,
variable native write expansion, source-aware restore and authenticated applying
writer still need integration. Opening a holder compartment is custody/data
authentication, not native operation authority. No source is selected in place
of another, no extra part is discarded and no old part count becomes a bound.

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
This connects the authenticated source to the actual applying writer; it does
not yet connect the native source bank or implement variable piece-count
reconstruction. Native root and producer activation remain off.
