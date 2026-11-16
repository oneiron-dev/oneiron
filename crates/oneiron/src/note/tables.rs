//! The side tables `note` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Per-admission disclosure floor: the VV as of the last full-state text-document export to one
    /// selector/peer. Key: hex32 (entity id) [":" hex32 (NOTE head)] ":" hex64 (blake3 of admission
    /// key).
    SYNC_AD_E: SyncState b"ad:e:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-entity text-document subscription row replayed as a REQUEST frame on every reconnect. Key:
    /// hex32 (entity id).
    SYNC_DS_E: SyncState b"ds:e:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable receipt for one applied/rejected NOTE-operation request, kept for reconnect/reopen.
    /// Key: hex32 (entity id) ":" hex32 (request id).
    SYNC_NC_E: SyncState b"nc:e:" LegacyJson
        [restore: content] [family: owner Note] [tier: canonical];
    /// Marks a replica's NOTE fork its authority sent (FIX 12789): the
    /// authority's fork set settles it, and a fork made here carries no mark.
    /// Key: hex32(note) ":" hex32(fork); value: BLAKE3 of the fork document
    /// as sent.
    NOTE_FORK_AUTHORITY: SyncState b"note_fork_authority:v1:" Raw
        [restore: content] [family: owner Note] [tier: canonical];
    /// Marks a window whose peer-authored NOTE inbox residue was staged, consulted by the note
    /// module's erasure sweep. Key: yyyy-mm (window key).
    SYNC_NOTE_INBOX: SyncState b"note_inbox:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Idempotent operation receipt for one authenticated NOTE command. Key: hex32(note) ":"
    /// hex32(request id).
    NOTE_RECEIPT_BY_REQUEST: SyncState b"nr:e:" LegacyJson
        [restore: content] [family: owner Note] [tier: canonical]
        => crate::Vault::erase_note_request_receipt_actor_in_txn;
    /// A folder the owner attached as a standing source of notes (OF-554): the folder, its
    /// include patterns, default kind, source and trust tier, and its last rescan. Key: hex16
    /// (hash of the folder).
    FOLDER_SOURCE: VaultMeta b"folder-source:attached:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::note::erase_folder_source_actor_in_txn;
    /// What an attached folder's rescans know of one file: its note, the hash of its text and of
    /// what the vault took from it, and whether it landed, waits as a fork or was retracted.
    /// Key: string (`folder hash:path`, a long path by its hash).
    FOLDER_SOURCE_FILE: VaultMeta b"folder-source:file:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Saved oplog version-vector floor an authority rebase cannot cross past a scrub. Key:
    /// hex32(id).
    NOTE_ERASE_AUTHORITY_FLOOR: VaultMeta b"note.erase/authority-floor/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Fence marking a citing document's dependency on an erased source until scrubbed. Key:
    /// hex32(citing) ":" hex32(erased source).
    NOTE_ERASE_PENDING: VaultMeta b"note.erase/pending/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Marker that a NOTE/CLAIM source has been citation-erased. Key: hex32(id).
    NOTE_ERASE_SOURCE: VaultMeta b"note.erase/source/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The one blessed, person-stamped brief-kind policy contract. Key: ().
    NOTE_BRIEF_KIND_CONTRACT: VaultMeta b"note.kind/brief/v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Reverse citation-pin index keyed by the citing document; value points at NOTE_PIN_SOURCE's
    /// key. Key: hex32(citing) ":" hex32(document) ":" hex64(hash).
    NOTE_PIN_CITING: VaultMeta b"note.pin/citing/" Raw
        [restore: content] [family: owner Note] [tier: canonical];
    /// Reverse citation-pin index keyed by the cited claim; value points at NOTE_PIN_SOURCE's key.
    /// Key: hex32(claim) ":" hex32(citing) ":" hex64(hash).
    NOTE_PIN_CLAIM: VaultMeta b"note.pin/claim/" Raw
        [restore: content] [family: owner Note] [tier: canonical];
    /// Pending (pre-admission) citation-request dependency, keyed by the citing document. Key:
    /// hex32(citing) ":" hex32(request).
    NOTE_PIN_REQUEST_CITING: VaultMeta b"note.pin/request/citing/" LegacyJson
        [restore: content] [family: owner Note] [tier: canonical];
    /// Pending citation-request index keyed by the cited claim. Key: hex32(claim) ":" hex32(citing)
    /// ":" hex32(request).
    NOTE_PIN_REQUEST_CLAIM: VaultMeta b"note.pin/request/claim/" Raw
        [restore: content] [family: owner Note] [tier: canonical];
    /// Pending citation-request index keyed by the cited source document. Key: hex32(document) ":"
    /// hex32(citing) ":" hex32(request).
    NOTE_PIN_REQUEST_SOURCE: VaultMeta b"note.pin/request/source/" Raw
        [restore: content] [family: owner Note] [tier: canonical];
    /// Reverse citation-pin row keyed by the cited source document. Key: hex32(document) ":"
    /// hex32(citing) ":" hex64(hash).
    NOTE_PIN_SOURCE: VaultMeta b"note.pin/source/" LegacyJson
        [restore: content] [family: owner Note] [tier: canonical];
    /// One author's reservation of a normalized NOTE title; value id16(note). Key: hex32(author)
    /// ":" hex64(blake3(normalized title)).
    NOTE_TITLE_RESERVATION: VaultMeta b"note.title/v1/author/" Raw
        [restore: content] [family: owner Note] [tier: canonical];
    /// A NOTE's current title reservation; value is NOTE_TITLE_RESERVATION's full key. Key:
    /// hex32(note).
    NOTE_TITLE_BY_NOTE: VaultMeta b"note.title/v1/id/" Raw
        [restore: content] [family: owner Note] [tier: canonical];
    /// The archive an archived NOTE was read in since it was archived, and when (OF-073,
    /// FIX 2419). Key: id16(note).
    NOTE_ARCHIVE_READ: VaultMeta b"note_archive_read:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Recorded NOTE fork awaiting review/decision. Key: id16(fork head).
    NOTE_FORK: VaultMeta b"note_fork:v1:" Named
        [restore: content] [family: owner Note] [tier: canonical]
        => crate::note::erase_fork_actor_in_txn;
    /// A NOTE's current head document id and head-move sequence number. Key: id16.
    NOTE_HEAD: VaultMeta b"note_head:v1:" Raw
        [restore: content] [family: owner Note] [tier: canonical];
    /// PACK-registered NOTE kind descriptor (extraction/context/retention defaults). Key:
    /// string(kind).
    NOTE_KIND: VaultMeta b"note_kind:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The extraction, context and retention defaults one NOTE overrides over its kind's
    /// (ARCH-0032, FIX 2418). Key: id16(note).
    NOTE_OVERRIDE: VaultMeta b"note_override:v1:" Named
        [restore: content] [family: owner Note] [tier: canonical];
    /// A plan-doc's review (plan mode): when it was proposed, and the owner's last verdict with
    /// the revision hash it was given at. No actor ref; the proposer is the NOTE's author and the
    /// owner is in the verdict's gate decision. Key: id16(note).
    NOTE_PLAN_DOC_REVIEW: VaultMeta b"note_plan_doc_review:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Review bundle grouping several fork proposals under one shared explainer. Key: id16(bundle
    /// id).
    NOTE_PROPOSAL_BUNDLE: VaultMeta b"note_proposal:v1:" Named
        [restore: content] [family: owner Note] [tier: canonical]
        => crate::note::erase_proposal_actor_in_txn;
    /// Durable head-move (merge/switch/reject) receipt. Key: id16(receipt id).
    NOTE_RECEIPT: VaultMeta b"note_receipt:v1:" Named
        [restore: content] [family: owner Note] [tier: canonical]
        => crate::note::erase_receipt_actor_in_txn;
    /// A NOTE's seal: the head document and frontier it froze, its sealer and time (ARCH-0032
    /// lifecycle). Key: id16(note).
    NOTE_SEAL: VaultMeta b"note_seal:v1:" Named
        [restore: content] [family: owner Note] [tier: canonical]
        => crate::note::erase_seal_actor_in_txn;
    /// A NOTE tombstone the monthly review proposed for the owner: the archive it holds for, and
    /// when the owner declined it, if they did (OF-073, FIX 2419). Key: id16(note).
    NOTE_TOMBSTONE_PROPOSAL: VaultMeta b"note_tombstone:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The last UTC calendar month the NOTE tombstone review ran (FIX 2419). Key: ().
    NOTE_TOMBSTONE_REVIEW: VaultMeta b"note_tombstone_review:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
