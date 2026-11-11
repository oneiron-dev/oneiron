# Code snapshot capture receipts

`vault.code.snapshots.ingest` imports the selected committed Git tree through
its existing custody-filtered writer. The authenticated owner's proof is
checked again in that writer, before any derived row is written. The snapshot,
blobs, symbols and one capture receipt commit together. A failed or rolled-back
import returns no capture receipt.

The ingest response's `capture_receipt` is the committed `gate:<hex>` reference.
Manifest get and projected-get responses omit that optional field. Retained
capture history is available through the existing `vault.receipts` gate family,
both with omitted `kinds` and with explicit `kinds=["gate"]`, including pages:

- `content_kind` is `code_snapshot_capture` and `outcome` is `imported`.
- `reason_codes` contains `gate.code.capture.imported`.
- `claim_ref` names the actual snapshot CODE_ARTIFACT. Despite that shared field's
  name, its typed `claim` reference is CODE_ARTIFACT, not CLAIM. The unified
  family's trigger is the generic `entity:<artifact-hex>` binding.
- `fields.repo` is that artifact's hex id. `fields.snapshot` is the filtered
  snapshot's fork hash, not the Git commit or an unfiltered input-tree hash.

Each successful owner capture keeps its own receipt, including repeated
captures of the same snapshot. The ledger's existing entity-bound read,
device-local, custody and erasure rules apply to the actual artifact. When
native erasure reduces a receipt to its retention skeleton, the new `repo` and
`snapshot` fields are omitted. A historical receipt is not proof that
the artifact is live, readable now or admitted for another act.

The native owner entry is `Vault::ingest_local_repo_at_commit_as`. Existing
trusted, run-granted and served-repository import paths retain their behavior
and return no receipt from this new local-owner capture path.

This does not register a repository, mint a stable repository id, retain an
editable whitelist or grant membership. Registration receipts remain separate
work (FIX 4299 / the registration half of FIX 4301). No new setting, default,
limit, wire verb, protocol, table, migration or artifact rebuild is needed.
Deploy only the normal matching engine/server when authorized.
