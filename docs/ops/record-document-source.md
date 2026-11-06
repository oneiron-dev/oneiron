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

Generic entity/MACHINE erasure removes source rows naming that entity or sender in the same writer. Exact window removal deletes only that window's transport metadata, not its members' documents, history, sequence rows or provenance. These hooks do not establish selective partial-history invalidation.

## Admission boundary

The metadata is not currently a source for retained-record admission. Replay still requires the live import's selected source and all original native checks. A persisted source row is not `SkillStateWrite`, a native final input, or a commit receipt. Retained-source readmission and precise history-cut invalidation require their actual source-owner continuations; capture and persistence alone do not supply them.
