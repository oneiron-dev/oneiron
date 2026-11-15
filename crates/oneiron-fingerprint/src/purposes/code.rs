//! Purposes of code snapshots, revisions, imports and received bundles (`oneiron-store`'s
//! `code_snapshot`, `code_revision_identity`, `code_import_manifest` and
//! `repo_proposal_record`; the core's `code_revision`, `merge_queue` and `repo_mutation`).
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

    /// A code import approval's claim (`code_revision::import_types::approval_id`). Parts: the
    /// manifest, the Baseline fold, the selected catalog's digest, the effective review, the
    /// approving owner.
    IMPORT_APPROVAL = (Blake3, HashedFirst, "oneiron:code-import-approval:v1");

    /// A merge queue batch's admission receipt (`merge_queue::receipts::receipt_id`). Parts: the
    /// store, the batch.
    QUEUE_ADMISSION = (Blake3, HashedFirst, "oneiron:repo-queue-admission:v1");

    /// A merge queue batch's terminal completion receipt (`merge_queue::receipts::receipt_id`).
    /// Parts: the store, the batch.
    QUEUE_COMPLETION = (Blake3, HashedFirst, "oneiron:repo-queue-completion:v1");

    /// The document operation a native bundle's file lowers to (CALL BUNDLE-CHILD-OP;
    /// `repo_mutation::bundle`). Parts: the proposal, the file's index (u64 big-endian).
    BUNDLE_FILE_OPERATION = (Blake3, HashedFirst, "oneiron:repo-bundle-file-op:v1");

    /// A queue conflict's resolution
    /// (`repo_mutation::conflict::queue::record_queue_repo_conflict_resolution`). Parts: the open
    /// conflict's claim, the key, the batch.
    QUEUE_CONFLICT_RESOLUTION = (Blake3, HashedFirst, "oneiron:repo-queue-conflict-resolution:v1");

    /// An external import (`repo_mutation::external_import::source::source_id`). Parts: labelled
    /// pairs of the store, the anchor, the whole source tuple, the base, the imported ref and
    /// the authenticated importer.
    EXTERNAL_IMPORT_SOURCE = (Blake3, HashedFirst, "oneiron:external-import:v1");

    /// The one dispatch of a step of an external import
    /// (`repo_mutation::external_import::source::dispatch_id`). Parts: labelled pairs of the
    /// import and the step.
    EXTERNAL_IMPORT_DISPATCH = (Blake3, HashedFirst, "oneiron:external-import-dispatch:v1");

    /// The one binding of an imported ref on its anchor
    /// (`repo_mutation::external_import::source::ref_binding_id`). Parts: labelled pairs of the
    /// anchor and the imported ref.
    EXTERNAL_IMPORT_REF = (Blake3, HashedFirst, "oneiron:external-import-ref:v1");

    /// An observed fact of an external import attempt's step
    /// (`repo_mutation::external_import::source::observation_id`). Parts: labelled pairs of the
    /// attempt, the step and the fact.
    EXTERNAL_IMPORT_OBSERVATION = (Blake3, HashedFirst, "oneiron:external-import-observation:v1");

    /// The session claim a proposal writes beside its proposed diff, one per session and
    /// proposal, with no actor hashed (FIX 4479;
    /// `repo_mutation::proposal::actor_erase::session_claim_id`). Parts: the session, the
    /// proposal.
    REPO_SESSION_CLAIM = (Blake3, HashedFirst, "oneiron:repo-session-claim:v2");

    /// A proposal's submission admission receipt
    /// (`repo_mutation::proposal::receipts::admission_receipt_id`). Parts: the proposal.
    PROPOSAL_ADMISSION = (Blake3, HashedFirst, "oneiron:repo-proposal-admission:v1");

    /// The completion receipt of a proposal's attempt
    /// (`repo_mutation::proposal::receipts::attempt_receipt_id`). Parts: the proposal, the
    /// attempt's sequence number (big-endian).
    PROPOSAL_ATTEMPT_COMPLETION =
        (Blake3, HashedFirst, "oneiron:repo-proposal-attempt-completion:v1");

    /// The one replacement link of a failed proposal
    /// (`repo_mutation::proposal::repair::replacement_receipt_id`). Parts: the failed proposal.
    PROPOSAL_REPLACEMENT = (Blake3, HashedFirst, "oneiron:repo-proposal-replacement:v1");

    /// A resolved successor: one original has at most one, found again by deriving it
    /// (`repo_mutation::proposal::resolve_handles::successor_id`). Parts: the original.
    PROPOSAL_RESOLVED_SUCCESSOR =
        (Blake3, HashedFirst, "oneiron:repo-proposal-resolved-successor:v1");

    /// A secret remediation link (`repo_mutation::secret_remediation::link::put_link_in_txn`).
    /// Parts: the state, the proposal.
    SECRET_REMEDIATION_LINK = (Blake3, HashedFirst, "oneiron:repo-secret-remediation:v1");
}
