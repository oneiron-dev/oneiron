//! The side tables `embed` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Lease fencing one pending-embedding job against a route/token pair. Key: hex32.
    PENDING_EMBEDDING_LEASE: SyncState b"pelease:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// An owner-approved retrieval embedder binding staged through a space move, with its move
    /// and state (OF-577, O3b PR B). Key: id16 (the offer, or the training run).
    EMBEDDING_BINDING_MOVE: VaultMeta b"embedding/binding_move/" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::embed::erase_binding_move_actor_in_txn;
    /// Where the current reconciled embedding vector was filled (on-device/owner-server/third-party).
    /// Key: id16.
    EMBEDDING_LOCALITY: VaultMeta b"embedding/locality/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The device family and runtime that computed each media vector in a declared space, outside
    /// the space identity (ARCH-0036; FIX 7796). Key: space key16 + id16.
    EMBEDDING_MEDIA_DEVICE: VaultMeta b"embedding/media_device/" Named
        [restore: content] [family: owner EmbedMedia] [tier: canonical];
    /// A document a declared space's model refused by its content, with the BLAKE3 of the bytes
    /// it refused; the media backfill skips it until they change (OF-370). Key: space key16 +
    /// id16.
    EMBEDDING_MEDIA_REFUSED: VaultMeta b"embedding/media_refused/" Named
        [restore: live] [family: owner EmbedMedia] [tier: canonical];
    /// One media vector per declared space and entity: its input-kind byte, then the v1 vector
    /// row (OF-370). Key: space key16 + id16.
    EMBEDDING_MEDIA_VECTOR: VaultMeta b"embedding/media_vector/" Raw
        [restore: content] [family: owner EmbedMedia] [tier: canonical];
    /// A kind slot version move, open or concluded, with its last paired probe check (OF-370).
    /// Key: candidate space id string.
    EMBEDDING_MOVE: VaultMeta b"embedding/move/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A retrieval probe a space version move runs on both spaces (OF-370). Key: probe id16.
    EMBEDDING_PROBE: VaultMeta b"embedding/probe/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Media kind slot to declared space id (OF-370). Key: one input-kind byte.
    EMBEDDING_SLOT: VaultMeta b"embedding/slot/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Declared embedding space: id, width, accepted inputs, query towers (OF-370). Key: string.
    EMBEDDING_SPACE: VaultMeta b"embedding/space/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Each world's own text space, as the text pass last moved this device's vectors to match
    /// (DEC-0005 #private-world-vectors); a pass that reads another map sweeps. Key: ().
    EMBEDDING_WORLD_TEXT_SPACES_SWEPT: SyncState b"embedding_world_text_spaces_swept:v1" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// The safe index copy of a text a model derived from a marked repo blob, or of a probe query
    /// made from one (FIX 7608 S3F): pending, or ready with its source proof. Node-local cache, no
    /// secret value. Key: u8 (owner kind) + id16.
    REPO_DERIVED_INDEX_COPY: VaultMeta b"repo_index:derived_copy:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
