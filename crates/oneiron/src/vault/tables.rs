//! The side tables `vault` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A BASE window the owner's discard of a world copy took rows from (FIX 14534 part E): a
    /// first byte of 1 while its persisted copy still waits for its projection, 0 once
    /// installed, then the version vector the last projection kept, the floor below which no
    /// send of the window goes to the home. Key: window key.
    SYNC_BASE_WINDOW_DISCARD: SyncState b"bd:w:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// The scope a deleted record held, bound to its delete request, so a narrower grant's export
    /// carries its tombstone only where the grant reads that scope (FIX 10161). Ids and levels
    /// only, never content. Local to this vault: never replicated or exported. Key: hex32 (entity
    /// id).
    FEDERATION_TOMBSTONE_SCOPE: SyncState b"fedtombscope:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Which machine wrote the MESSAGE row this install stores (FIX 12113): the row's BLAKE3
    /// (32 bytes) when this install's local put wrote it, or the writer's whole proof (the row's
    /// BLAKE3, the writer machine and its Ed25519 signature, 112 bytes) when the own-device lane
    /// admitted it. The reverse scan vouches for a row beside it only while its bytes are the
    /// ones named here. Runtime: never imaged, a restore drops it. Key: hex32 (MESSAGE id).
    SYNC_MESSAGE_WRITER: SyncState b"mw:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Latest peer carrier's wire digest (32 bytes), plus an ASSET logical body digest (32).
    /// A distinct still-canonical peer ASSET entry (wire + logical, 64 bytes) precedes it:
    /// pending replacement never erases the stored row's origin. Logical identity survives
    /// native inline/file/reference echoes; each wire digest binds exact carrier cleanup.
    /// Local to this vault, never replicated. Key: hex32 (entity id) ":" window key.
    SYNC_PEER_ORIGIN: SyncState b"po:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Request-bound reservation fencing topology writes on an entity between tombstone
    /// publication and purge (34 bytes: phase, request id, reason, deleted_at LE, window_ts LE).
    /// Key: hex32 (entity id).
    DELETION_TOPOLOGY_DELETE_INTENT: SyncState b"topology-delete-intent:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A BASE row the owner's discard of a world copy took as that world's alone (FIX 14534):
    /// the world's id (16 bytes), the ingest ladder's cue to judge the row's body again before
    /// its window brings it back. Key: hex32 (entity id).
    SYNC_DISCARDED_WORLD_ROW: SyncState b"wd:e:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Pointer from an owner (a stored entity or a proposal artifact) to its document, plus
    /// generation/pending-update counters. Key: hex32.
    ENTITY_DOC_HEAD: VaultMeta b"entity_doc:v1:head:" Named
        [restore: content] [family: owner EntityDoc] [tier: canonical];
    /// Retained revision history document. Key: id16.
    ENTITY_REVISION_DOC: VaultMeta b"entity_revision:doc:" Raw
        [restore: content] [family: owner EntityRevision] [tier: canonical];
    /// Pinned revision frontier. Key: id16 + rev16.
    ENTITY_REVISION_FRONTIER: VaultMeta b"entity_revision:frontier:" Raw
        [restore: content] [family: owner EntityRevision] [tier: canonical];
    /// Revision hash to owning entity. Key: rev16.
    ENTITY_REVISION_IDENTITY: VaultMeta b"entity_revision:identity:" Raw
        [restore: content] [family: owner EntityRevision] [tier: canonical];
    /// Staged text/vector index inputs. Key: id16.
    ENTITY_REVISION_PENDING_INDEX_INPUTS: VaultMeta b"entity_revision:index_inputs:" Named
        [restore: content] [family: owner EntityRevision] [tier: canonical];
    /// Staged phonetic codes. Key: id16.
    ENTITY_REVISION_PENDING_PHONETIC: VaultMeta b"entity_revision:phonetic:" Named
        [restore: content] [family: owner EntityRevision] [tier: canonical];
    /// Live vs indexed revision pointers. Key: id16.
    ENTITY_REVISION_STATE: VaultMeta b"entity_revision:state:" Named
        [restore: content] [family: owner EntityRevision] [tier: canonical];
    /// A published revision whose vector an embedding-space swap dropped, to be embedded again at
    /// idle. Key: id16.
    ENTITY_REVISION_VECTOR_REFILL: VaultMeta b"entity_revision:vector_refill:" Raw
        [restore: content] [family: owner EntityRevision] [tier: canonical];
    /// Idle publication delay. Key: ().
    ENTITY_TEXT_INDEXED_IDLE_DELAY_MS: VaultMeta b"manifest:entity_text:indexed_idle_delay_ms" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The vault's document-mutation head (FIX 2860): 16 bytes of BLAKE3 over the head before it,
    /// the entity and the live revision of the newest committed document edit (for a copy
    /// lineage, its copy id and frontier revision), read beside the change log's head into an
    /// action's inputs. Key: ().
    PORTS_DOCUMENT_MUTATION_HEAD: VaultMeta b"ports:document_mutation_head:v1" Raw
        [restore: content] [family: structure] [tier: canonical];
}
