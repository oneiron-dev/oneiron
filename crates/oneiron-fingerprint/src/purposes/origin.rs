//! Purposes of the git origin (`crates/oneiron/src/origin` and `oneiron-store`'s
//! `origin`).
//!
//! Each legacy purpose below is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {
    /// A protected ref move's ask (`origin::smart_http::protected_ref_confirm`). Parts: the
    /// move's digest.
    PROTECTED_REF_MOVE_ASK = "oneiron:origin-protected-ref-move-ask:v1";
}

legacy_purposes! {
    /// An LFS chunk's ASSET (`oneiron-store`'s `origin::lfs::chunks::chunk_id`). Parts: the
    /// chunk's BLAKE3.
    LFS_CHUNK = (Blake3, HashedFirst, "oneiron:origin-lfs-chunk:v1");

    /// One publication's record, from everything that makes an advance the same advance,
    /// so a replay addresses the same row (`oneiron-store`'s
    /// `origin::publication::publication_codec::origin_publication_id`). Parts: repo, ref
    /// name, the expected old oid (empty for none), the new oid, the provenance claim.
    PUBLICATION = (Blake3, HashedFirst, "oneiron:origin-publication:v1");

    /// The `repo.publication` claim one record asserts (`origin_publication_claim_id`).
    /// Parts: the publication.
    PUBLICATION_CLAIM = (Blake3, HashedFirst, "oneiron:origin-publication-claim:v1");

    /// The commit-keyed entity one publication's claim is anchored on (RA5;
    /// `origin_published_commit_id`). Parts: the commit oid.
    PUBLICATION_COMMIT = (Blake3, HashedFirst, "oneiron:origin-publication-commit:v1");

    /// A commit's origin change (`origin::change_index::origin_change_id`). Parts: the repo, the
    /// commit.
    CHANGE = (Blake3, HashedFirst, "oneiron:origin-change:v1");

    /// The claim of a commit's origin change (`origin::change_index`). Parts: the repo, the
    /// commit.
    CHANGE_CLAIM = (Blake3, HashedFirst, "oneiron:origin-change-claim:v1");

    /// The intent of publishing one open conflict (`origin::conflict_tree::export_repo_conflict`).
    /// Parts: the repo, the conflict's claim, the ref name, the expected old oid (empty for
    /// none), the commit.
    CONFLICT_EXPORT_INTENT = (Blake3, HashedFirst, "oneiron:conflict-export-intent:v1");

    /// The intent of exporting an engine commit (`origin::export`). Parts: the repo, the
    /// revision, the ref name, the expected old oid (empty for none), the new oid.
    ENGINE_EXPORT_INTENT = (Blake3, HashedFirst, "oneiron:engine-export-intent:v1");

    /// A per-vault, per-actor opaque Git author pseudonym (FIX 5020;
    /// `origin::export::opaque_git_author`). Parts: `authority`, the authority and the actor; or
    /// `store`, the vault and the actor.
    OPAQUE_GIT_AUTHOR = (Blake3, HashedFirst, "oneiron:origin-git-author:v1");

    /// The ASSET that stores an LFS manifest (`origin::lfs::chunks`). Parts: the manifest's
    /// hash.
    LFS_ASSET = (Blake3, HashedFirst, "oneiron:origin-lfs-asset:v1");

    /// The repository key LFS attachment rows are scoped to (`origin::lfs::store::lfs_repo_id`).
    /// Parts: the repo identity.
    LFS_REPO = (Blake3, HashedFirst, "oneiron:origin-lfs-repo:v1");

    /// The request id an idempotency key fixes for one repository
    /// (`origin::publish::store::keyed_request_id`). Parts: the repo, the key.
    PUBLISH_REQUEST = (Blake3, HashedFirst, "oneiron:origin-publish-request:v1");

    /// The intent of the ExactForward arm for one projected update
    /// (`origin::smart_http::push_projection::forward`). Parts: the canonical store, the
    /// operation, the ref name, the old oid (empty for none), the new oid.
    PROJECTION_FORWARD_INTENT = (Blake3, HashedFirst, "oneiron:projection-forward-intent:v1");

    /// One pushed ref's candidate (`origin::document_candidates::push_candidate_id`). Parts: the
    /// store, the provenance, the ref name.
    PUSH_CANDIDATE = (Blake3, HashedFirst, "oneiron:push-candidate:v1");

    /// The session one candidate is decided in (`origin::document_candidates` and its
    /// `projected_decide`). Parts: the candidate, its base revision.
    PUSH_CANDIDATE_SESSION = (Blake3, HashedFirst, "oneiron:push-candidate-session:v1");

    /// The session one push's received code operations land in
    /// (`origin::document_ingress::land_received_code_operations`). Parts: the repo identity's
    /// hex, the provenance claim.
    PUSH_SESSION = (Blake3, HashedFirst, "oneiron:push-session:v1");

    /// A path's operation in one ref of a push, the same for a replay
    /// (`origin::document_ingress::file_operation_id`). Parts: the provenance, the ref name, the
    /// path, the hashes before and after, the old and new modes (0 for none, big-endian).
    PUSH_FILE_OPERATION = (Blake3, HashedFirst, "oneiron:push-file-operation:v1");

    /// A repo secret projection record (`origin::secret_projection::claims`). Parts: the schema,
    /// the graph, the packed identity.
    SECRET_PROJECTION = (Blake3, HashedFirst, "oneiron:repo-secret-projection:v1");

    /// A secret purge plan: the same purge of the same refs by the same owner plans once
    /// (`origin::secret_purge::plan_id`). Parts: the owner, the store, the mark count
    /// (big-endian), each mark, then each moved ref's name and old object.
    SECRET_PURGE_PLAN = (Blake3, HashedFirst, "oneiron:repo-secret-purge-plan:v1");

    /// A secret purge plan's one receipt (`origin::secret_purge::receipt_id`). Parts: the plan.
    SECRET_PURGE_RECEIPT = (Blake3, HashedFirst, "oneiron:repo-secret-purge-receipt:v1");

    /// The intent of one ref move of a secret purge
    /// (`origin::secret_purge::execute::move_purged_ref`). Parts: the plan, the ref name.
    SECRET_PURGE_INTENT = (Blake3, HashedFirst, "oneiron:repo-secret-purge-intent:v1");
}
