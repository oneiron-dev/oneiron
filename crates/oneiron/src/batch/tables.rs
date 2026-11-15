//! The side tables `batch` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// An entity document's snapshot (document family). Key: hex32.
    DOCUMENT_SNAPSHOT: SyncState b"d:e:" Raw
        [restore: content] [family: owner EntityDoc] [tier: canonical];
    /// Body hash (blake3, 32 bytes) of an engine-seeded default policy manifest; an owner write
    /// clears it. Key: hex32.
    GATE_MANIFEST_SEEDED_CONFIDENCE: SyncState b"manifest:seeded_confidence:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Authenticity hash stamped when a policy manifest is contributed directly (non-replicated).
    /// Key: hex32.
    GATE_MANIFEST_TRUSTED_ORIGIN: SyncState b"manifest:trusted:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Loro snapshot bytes of a proposal (non-live) NOTE document head. Key: hex32(note) ":"
    /// hex32(head).
    NOTE_PROPOSAL_DOC: SyncState b"note_proposal_doc:v1:" Raw
        [restore: content] [family: owner Note] [tier: canonical];
    /// One pending update of an entity document (document family). Key: hex32 (entity id) ":" hex8
    /// (sequence).
    DOCUMENT_UPDATE: SyncState b"u:e:" Raw
        [restore: content] [family: owner EntityDoc] [tier: canonical];
    /// The by-reference ASSET bodies a confirmed staged import still owes (FIX 12408): each owed
    /// body's admitted window and row, and every row its kept content carries. No body bytes.
    /// Key: hex64 (receipt).
    VAULT_IMPORT_BODY_WORK: SyncState b"vault_import_body_work:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Admitted foreign-import payload retained while its receipt is Pending, so recovery
    /// survives losing the in-memory stage, and after its confirmation while it owes bodies.
    /// Key: hex64.
    VAULT_IMPORT_CONTENT: SyncState b"vault_import_content:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Terminal/pending status receipt (hand-rolled MessagePack map) for one foreign vault-import
    /// artifact, keyed by its content-derived receipt id. Key: hex64.
    VAULT_IMPORT_RECEIPT: SyncState b"vault_import_receipt:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The facet stamps a foreign artifact staged ahead of their rows, kept with its receipt while
    /// it is Pending, and after its confirmation while it owes bodies, bound to it by the
    /// receipt's digest, so its confirmation holds every one of them again. Key: hex64.
    VAULT_IMPORT_STAMPS: SyncState b"vault_import_stamps:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Born-from projection: one row per version whose made_by names a trigger (task or ask) or
    /// whose provenance names an agent run, read backwards from the source. Key: bytes17 (source
    /// kind byte + id16 or the run ref's blake3 prefix) + id16 (artifact) + u64be (version).
    BLOB_ARTIFACT_BORN_FROM: VaultMeta b"blob_artifact:born_from:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// `BLOB_ARTIFACT_VERSION_CLAIM` keyed by artifact, so an artifact's delete reads its own
    /// bytes without a scan. Key: id16 (artifact) + bytes32.
    BLOB_ARTIFACT_CLAIMED_HASH: VaultMeta b"blob_artifact:claimed_hash:v1:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Native slide and shape id high-water marks of one deck artifact, raised at each settled
    /// deck transaction (ARCH-0077 managed id history). Key: id16.
    BLOB_ARTIFACT_DECK_ID_MARKS: VaultMeta b"blob_artifact:deck_id_marks:v1:" Named
        [restore: content] [family: structure] [tier: canonical];
    /// Blob artifact head version. Key: id16.
    BLOB_ARTIFACT_HEAD: VaultMeta b"blob_artifact:head:v1:" Raw
        [restore: content] [family: owner BlobArtifact] [tier: canonical]
        => crate::blob_artifact::erase::erase_blob_artifact_version_actor_in_txn;
    /// Monotonic last version, retained after deletion. Key: id16; value: u64be.
    BLOB_ARTIFACT_HIGHWATER: VaultMeta b"blob_artifact:highwater:v1:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Edit proposal settlement ledger row. Key: id16 + hash32.
    EDIT_SETTLE_RECORD: VaultMeta b"blob_artifact:settlement:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Blob artifact version record. Key: id16 + u64be.
    BLOB_ARTIFACT_VERSION: VaultMeta b"blob_artifact:version:v1:" Raw
        [restore: content] [family: owner BlobArtifact] [tier: canonical]
        => crate::blob_artifact::erase::erase_blob_artifact_version_actor_in_txn;
    /// Which artifacts hold which bytes: one row per artifact and content hash a `blob.version`
    /// claim named here, replicated claims included, kept until the artifact's delete. Key:
    /// bytes32 + id16 (artifact).
    BLOB_ARTIFACT_VERSION_CLAIM: VaultMeta b"blob_artifact:version_claim:v1:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Private local binding digest (row_digest, 32 bytes) proving which writer authored/finalized a
    /// CLAIM row. Key: id16.
    CLAIM_MATERIALIZATION_AUTHORED: VaultMeta b"claim:materialization:authored:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Immutable tested snapshot of a code document at one exact operation frontier (document id + op
    /// fold hash). Key: hash32 + hash32.
    CODE_DOCUMENT_FRONTIER: VaultMeta b"code_document:frontier:v1:" Named
        [restore: content] [family: owner CodeDocument] [tier: canonical];
    /// Monotonic rename-generation counter (u64be) for a (repo, path) pair, advanced on rename. Key:
    /// hash32.
    CODE_DOCUMENT_GENERATION: VaultMeta b"code_document:generation:v1:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Current durable head snapshot plus full receipt history for one code document. Key: hash32.
    CODE_DOCUMENT_HEAD: VaultMeta b"code_document:head:v1:" Named
        [restore: content] [family: owner CodeDocument] [tier: canonical]
        => crate::code_document::erase_head_actor_in_txn;
    /// Durable replay-guard receipt for one applied code-file-edit ingress operation. Key: id16.
    CODE_DOCUMENT_INGRESS: VaultMeta b"code_document:ingress:v1:" Named
        [restore: content] [family: owner CodeDocument] [tier: canonical]
        => crate::code_document::erase_ingress_actor_in_txn;
    /// Maps a (repo, path) pair (sha256-hashed) to the code-document id currently living at that
    /// path. Key: hash32.
    CODE_DOCUMENT_PATH: VaultMeta b"code_document:path:v1:" Raw
        [restore: content] [family: owner CodeDocument] [tier: canonical];
    /// Registered always-on code-memory contract (interface/policy) for a symbol slot payload. Key:
    /// id16 "\x00" string "\x00" u8 id16.
    CODE_MEMORY_ALWAYS_ON: VaultMeta b"code_memory:always_on:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable L2 attachment row binding a code-symbol slot value to a note/claim payload (symbol,
    /// slot name, payload tag+id). Key: id16 "\x00" string "\x00" u8 id16.
    CODE_MEMORY_ATTACHMENT: VaultMeta b"code_memory:attachment:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Named code-memory slot holding the live (possibly conflicting) values recorded against one
    /// code symbol. Key: id16 "\x00" string.
    CODE_MEMORY_SLOT: VaultMeta b"code_memory:slot:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Idempotent receipt of a code-symbol anchor rename/copy transfer (from, to, observed_at, digest
    /// of the transfer identity). Key: id16 + id16 + u64be + hash32.
    CODE_MEMORY_TRANSFER: VaultMeta b"code_memory:transfer:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Recorded code-revision fork/branch row. Key: id16.
    CODE_REVISION_FORK: VaultMeta b"code_revision:fork:v1:" Raw
        [restore: content] [family: owner CodeRevision] [tier: canonical];
    /// Index of forks by parent session, empty marker value. Key: id16 + id16.
    CODE_REVISION_FORK_PARENT_INDEX: VaultMeta b"code_revision:fork_parent:v1:" Raw
        [restore: content] [family: owner CodeRevision] [tier: canonical];
    /// A session's current revision-frontier record. Key: id16.
    CODE_REVISION_FRONTIER: VaultMeta b"code_revision:frontier:v1:" Raw
        [restore: content] [family: owner CodeRevision] [tier: canonical];
    /// Cached integrity/hash-fold record for one revision. Key: id16.
    CODE_REVISION_INTEGRITY: VaultMeta b"code_revision:integrity:v1:" Raw
        [restore: content] [family: owner CodeRevision] [tier: canonical];
    /// Index of child revisions by parent revision, empty marker value. Key: id16 + id16.
    CODE_REVISION_PARENT_INDEX: VaultMeta b"code_revision:parent:v1:" Raw
        [restore: content] [family: owner CodeRevision] [tier: canonical];
    /// Immutable receipt of the file-mode-review proposal ids that promoted a revision. Key: id16.
    CODE_REVISION_PROMOTION: VaultMeta b"code_revision:promotion:v1:" LegacyCompact
        [restore: content] [family: owner CodeRevision] [tier: canonical];
    /// Stranded/diverged revision proposal awaiting reconciliation with the head. Key: id16.
    CODE_REVISION_PROPOSAL: VaultMeta b"code_revision:proposal:v1:" Raw
        [restore: content] [family: owner CodeRevision] [tier: canonical]
        => crate::code_revision::erase_proposal_author_in_txn;
    /// Finalized code-revision row (hand-rolled MessagePack map). Key: id16.
    CODE_REVISION_RECORD: VaultMeta b"code_revision:record:v1:" Raw
        [restore: content] [family: owner CodeRevision] [tier: canonical]
        => crate::code_revision::erase_revision_author_in_txn;
    /// Index of revisions belonging to a session, empty marker value. Key: id16 + id16.
    CODE_REVISION_SESSION_INDEX: VaultMeta b"code_revision:session:v1:" Raw
        [restore: content] [family: owner CodeRevision] [tier: canonical];
    /// A code run's raw output bytes, keyed by their deterministic content handle. Key: string.
    CODE_RUN_RAW_OUTPUT: VaultMeta b"code_run:raw_output:v1:" Raw
        [restore: content] [family: dispatch Body] [tier: canonical];
    /// Per-codebase-snapshot custody report (encoded via rmp_serde::to_vec_named), keyed by the fork
    /// hash; the const and key builder live in secret_snapshot.rs but the actual put/get/delete call
    /// sites are in codebase/store.rs — flagged as a borderline cross-module row, report per "if
    /// unsure, report it". Key: hex64.
    SECRET_SNAPSHOT_CODEBASE_CUSTODY: VaultMeta b"codebase:custody:v1:" Raw
        [restore: content] [family: owner Codebase] [tier: canonical];
    /// Index from a fork hash to the codebase snapshots sharing it. Key: bytes32(fork_hash) + "\x00"
    /// + id16.
    CODEBASE_FORK_INDEX: VaultMeta b"codebase:fork:v1:" Raw
        [restore: content] [family: owner Codebase] [tier: canonical];
    /// Index from a project id to the codebase snapshots recorded against it. Key: string(project_id)
    /// + "\x00" + id16.
    CODEBASE_PROJECT_INDEX: VaultMeta b"codebase:project:v1:" Raw
        [restore: content] [family: owner Codebase] [tier: canonical];
    /// Index from a repo reference to the codebase snapshots recorded against it. Key: bytes(repo_ref
    /// canonical text) + "\x00" + id16.
    CODEBASE_REPO_INDEX: VaultMeta b"codebase:repo:v1:" Raw
        [restore: content] [family: owner Codebase] [tier: canonical];
    /// Index from a codebase scope key to the snapshot and asset entities visible under it. Key:
    /// bytes(scope_key) + "\x00" + id16.
    CODEBASE_SCOPE_INDEX: VaultMeta b"codebase:scope:v1:" Raw
        [restore: content] [family: owner Codebase] [tier: canonical];
    /// A codebase snapshot's file manifest, keyed by the CODE_ARTIFACT entity id it snapshots. Key:
    /// id16.
    CODEBASE_SNAPSHOT: VaultMeta b"codebase:snapshot:v1:" Raw
        [restore: content] [family: owner Codebase] [tier: canonical];
    /// Caller-supplied phonetic codes retained to recompute an entity's phonetic postings on
    /// reindex/delete. Key: id16.
    BATCH_PHONETIC_INDEX_SOURCE: VaultMeta b"index_source:phonetic:v1:" Named
        [restore: content] [family: owner PhoneticSource] [tier: canonical];
    /// In-flight streamed message recovery seed. Key: id16. FIX 10668: this entry's scrub takes
    /// the signed slip out of a Retry seed's action its erased requester asked.
    MESSAGE_STREAM_ACTIVE: VaultMeta b"message_stream:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::memory::scrub_stream_seed_actor_in_txn;
    /// Machine work on a live office body: opener, base frontier and state. Key: id16 (artifact) +
    /// id16 (fork).
    OFFICE_BODY_FORK: VaultMeta b"office_body:fork:v1:" Named
        [restore: content] [family: owner OfficeBody] [tier: canonical]
        => crate::office_body::erase_fork_actor_in_txn;
    /// Forward index (empty marker): which owners still reference one chunk hash. Key: hash32 + id16.
    ORIGIN_LFS_CHUNK_REF: VaultMeta b"origin:lfs:chunk-ref:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Permanent tombstone (empty marker) for one deleted LFS object id, blocking resurrection. Key:
    /// hash32.
    ORIGIN_LFS_DELETED: VaultMeta b"origin:lfs:deleted:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Reverse pointer (32-byte oid) from an LFS manifest ASSET back to its object id. Key: id16.
    ORIGIN_LFS_MANIFEST_REVERSE: VaultMeta b"origin:lfs:manifest:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable LFS object record: asset id, size, created time, ref owner (48 raw bytes). Key:
    /// hash32.
    ORIGIN_LFS_OBJECT: VaultMeta b"origin:lfs:object:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Reverse index (empty marker): which chunk hashes one upload-journal owner references, for
    /// garbage collection. Key: id16 + hash32.
    ORIGIN_LFS_OWNER_REF: VaultMeta b"origin:lfs:owner-ref:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Attaches one LFS object id to one git ref in one repository (value = learned_at u64 LE). Key:
    /// id16 "\x00" string "\x00" hash32.
    ORIGIN_LFS_REF: VaultMeta b"origin:lfs:ref:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Pending owner policy-row change proposal. Key: proposal id.
    OWNER_POLICY_CHANGE_PROPOSAL: VaultMeta b"owner_policy:change:proposal:v1:" Raw Admitted
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner policy-row change receipt, in sequence order. Key: u64be sequence.
    OWNER_POLICY_CHANGE_RECEIPT: VaultMeta b"owner_policy:change:receipt:v1:" Raw Admitted
        [restore: live] [family: unclassified] [tier: canonical];
    /// The owner's `secrets: on | off` switch for the write-door secret scan. Key: ().
    OWNER_POLICY_SECRET_SCAN_MODE: VaultMeta b"owner_policy:secret_scan:mode:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// One claim the owner's whole-vault restore inserted as Proposed: a member of that
    /// restore's inbox group. Only the owner restore door writes it. Key: hex32 (restore
    /// receipt) ":" hex32 (claim).
    OWNER_RESTORE_CLAIM: VaultMeta b"owner_restore:claim:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The source vault id an owner whole-vault restore's archive names, for that restore's
    /// inbox group card. Only the owner restore door writes it. Key: hex32 (restore receipt).
    OWNER_RESTORE_GROUP: VaultMeta b"owner_restore:group:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Durable per-operation oplog entry (prepared/committed/failed mutation record), keyed by (repo
    /// key hash, seq as 16 lowercase hex chars). Key: hex64 ":" hex16.
    REPO_MUTATION_OPLOG: VaultMeta b"repo_mutation:oplog:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::repo_mutation::erase_oplog_actor_in_txn;
    /// Durable per-operation code proposal (file change plus critic evidence), keyed by proposal
    /// claim id. Key: id16.
    REPO_MUTATION_PROPOSAL: VaultMeta b"repo_mutation:proposal:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::repo_mutation::erase_proposal_actor_in_txn;
    /// The scope-stamp sweep over stored claims has run. Key: ().
    SCOPE_STAMP_SWEEP_DONE: VaultMeta b"scope:claim-codec:v2" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The scope-stamp sweep over policy manifests has run. Key: ().
    SCOPE_POLICY_SWEEP_DONE: VaultMeta b"scope:policy-manifest:v1.2" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Canonical lift counts by run, family and actual source entity or explicitly unmapped
    /// source (FIX 10493). No values. Key: run id16, family byte, source tag, source id16 if known.
    SECRET_LIFT_CONTRIBUTION: VaultMeta b"secret_lift:contribution:v1:" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// The needs-you notice the lift sweep raised last for its open proposals: the run that raised
    /// it and each owner's inbox row, acknowledged once none is open (OF-067). Key: ().
    SECRET_LIFT_NOTICE: VaultMeta b"secret_lift:notice:v1" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// A hit the historical lift sweep could not place, filed for the owner: the record or row
    /// that holds it, the detector's reason and why the sweep left it, and once closed, when, by
    /// whom and why (OF-067). Holds no value. Key: the family's code, a zero byte, `h` for a
    /// retained-history proposal or `r` for the row's own, then the row's key.
    SECRET_LIFT_PROPOSAL: VaultMeta b"secret_lift:proposal:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Completion metadata for one lift run (OF-067); its canonical contribution rows supply
    /// the served receipt's counts. Never a value or a digest. Key: id16 (run id).
    SECRET_LIFT_RECEIPT: VaultMeta b"secret_lift:receipt:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The lift sweep run in progress: its trigger and its `(family, last key)` cursor (OF-067).
    /// Key: ().
    SECRET_LIFT_RUN: VaultMeta b"secret_lift:run:v1" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Where a mask on write found the secret one custody record holds: the record, the field and
    /// the key's kind (OF-560). Key: id16 (custody record id).
    SECRET_MASK_ORIGIN: VaultMeta b"secret_mask:origin:v1:" Named Custody
        [restore: content] [family: unclassified] [tier: canonical];
    /// Last short-id counter per entity type. Key: u8.
    SHORT_ID_COUNTER: VaultMeta b"sid_counter:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Last short-id counter per runtime (pack) kind, by its stable short-id prefix, kept across
    /// uninstall, slot collection and reinstall (FIX 7741). Key: string.
    SHORT_ID_KIND_COUNTER: VaultMeta b"sid_kind_counter:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// One eval case in a seat's derivation ledger (MessagePack named map). Key: id16 (case).
    SKILL_OPTIMIZE_EVAL_CASE: VaultMeta b"skill_optimize:eval_case:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::skill_optimize::erase_eval_source_in_txn;
    /// A typed body's Loro snapshot at its head. Key: id16 (entity).
    TYPED_BODY_DOC: VaultMeta b"typed_body:doc:v1:" Raw
        [restore: content] [family: owner TypedBody] [tier: canonical];
    /// An open typed-body fork's Loro snapshot. Key: id16 (entity) + id16 (fork).
    TYPED_BODY_FORK_DOC: VaultMeta b"typed_body:fork_doc:v1:" Raw
        [restore: content] [family: owner TypedBody] [tier: canonical];
}
