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
