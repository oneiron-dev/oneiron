//! The side tables `artifact_hosting` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Runtime spool of artifact publication parts, sent (`tx`) and received (`rx`) (FIX 9575).
    /// Key: side ":" hex32 ":" (`m` | `p:` u64hex16 | `s`).
    ARTIFACT_PUBLICATION_PARTS: SyncState b"bulk:artifact:publication:parts:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Channel pointer (published/preview) naming the fork hash a codebase artifact currently serves.
    /// Key: channel byte + u16be length + string (artifact id).
    ARTIFACT_POINTER: VaultMeta b"artifact:pointer:v1:" Raw
        [restore: refuse "published artifacts"] [family: owner BlobArtifact] [tier: canonical];
    /// Immutable publish admission receipt keyed by publish entity id16.
    ARTIFACT_PUBLISH_ADMISSION: VaultMeta b"artifact:publish:admission:v1:" LegacyJson
        [restore: content] [family: owner BlobArtifact] [tier: canonical];
    /// A replica's serving descriptor of one published blob version: content hash, export name
    /// and media type, nothing else (FIX 1195). Key: id16 (artifact) + u64be (version).
    ARTIFACT_SERVING_BLOB: VaultMeta b"artifact:serving:blob:v1:" Named
        [restore: content] [family: owner BlobArtifact] [tier: canonical];
    /// The change id (16 bytes) of this channel pointer's change whose publication has not
    /// reached the sync server yet (FIX 9575). Key: channel byte + u16be length + string
    /// (artifact id).
    ARTIFACT_SYNC_OUTBOX: VaultMeta b"artifact:sync:outbox:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
