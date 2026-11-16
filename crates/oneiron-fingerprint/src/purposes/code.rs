//! Purposes of code snapshots, revisions, imports and received bundles (`oneiron-store`'s
//! `code_snapshot`, `code_revision_identity`, `code_import_manifest` and
//! `repo_proposal_record`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {}

legacy_purposes! {
    /// A snapshot file's ASSET (`code_snapshot::ids::codebase_asset_entity_id`). Parts: the
    /// file's content hash.
    CODEBASE_ASSET = (Blake3, HashedFirst, "oneiron:codebase-asset-entity:v1");

    /// A capture's CODE entity, one per revision (`code_snapshot::ids::codebase_snapshot_entity_id`,
    /// FIX 4299). Parts: the scope key, the fork hash, the canonical repo ref.
    CODEBASE_SNAPSHOT = (Blake3, HashedFirst, "oneiron:codebase-snapshot-entity:v2");

    /// The SESSION one queue's tested chain shares
    /// (`code_revision_identity::queue_aggregation_session`). Parts: store, checked init.
    QUEUE_AGGREGATION_SESSION = (Blake3, HashedFirst, "oneiron:queue-aggregation-session:v1");

    /// One tested revision (`code_revision_identity::queue_revision_id`). Parts: store,
    /// checked init, target, commit, tree, plan digest.
    QUEUE_TESTED_REVISION = (Blake3, HashedFirst, "oneiron:queue-tested-revision:v1");

    /// A tested revision's aggregate provenance claim
    /// (`code_revision_identity::queue_provenance_id`). Parts: the revision.
    QUEUE_REVISION_PROVENANCE = (Blake3, HashedFirst, "oneiron:queue-revision-provenance:v1");

    /// An import manifest's claim (`code_import_manifest::manifest_id`). Parts: the manifest
    /// digest's hex. The manifest digest (`manifest_digest`) starts with the same bytes,
    /// as a raw BLAKE3 start of its own (PLAN-UC-04 stage 7).
    IMPORT_MANIFEST = (Blake3, HashedFirst, "oneiron:code-import-manifest:v1");

    /// A received bundle's proposal (`repo_proposal_record::received_proposal_id`). Parts:
    /// the push candidate.
    PUSH_CANDIDATE_PROPOSAL = (Blake3, HashedFirst, "oneiron:push-candidate-proposal:v1");

    /// The document operation one received bundle file lowers to, apart from the receive
    /// audit's own operation ids (`repo_proposal_record::received_file_operation`). Parts:
    /// the proposal, the source.
    PUSH_CANDIDATE_FILE_OPERATION = (Blake3, HashedFirst, "oneiron:push-candidate-file-op:v1");
}
