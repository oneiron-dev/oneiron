//! Purposes of the git origin (`crates/oneiron/src/origin` and `oneiron-store`'s
//! `origin`).
//!
//! Purposes of the git origin (`crates/oneiron/src/origin`).
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

    /// An exact publish's review digest (`origin::publish::review`). BLAKE3 derive-key: the
    /// commit, the subtracted tip (empty when none) and each commit an earlier mirror
    /// section walked; then each item in walk order: `c`, the commit, the parent count and
    /// each parent; or `p`, the status, the mode, the object (empty for a deletion) and the
    /// path. Every field is framed by its length and every count is written, each as a u64
    /// little-endian; `c` and `p` are not framed. Its hex is the request's `review.digest`:
    /// stored with the request, returned to the caller, and compared with the digest an
    /// approval names (`origin::publish::lifecycle`).
    PUBLISH_REVIEW = (Blake3, DeriveKeyContext, "oneiron:origin-publish-review:v1");

    /// A mirror plan's section digest, one per ref (`origin::publish::mirror_review`).
    /// BLAKE3 derive-key: the ref name, the new object and the observed tip (empty when
    /// none); then in walk order each tag (`t` and the tag oid, then its raw bytes; or `T`
    /// and the tag oid, then its size as 8 bytes, u64 little-endian), each object (`o`, the
    /// kind, the oid), each tree path (as in `PUBLISH_REVIEW`) and each walked commit's
    /// review digest hex. Framed as `PUBLISH_REVIEW`. Stored as the plan ref's review digest
    /// and bound into `MIRROR_PLAN`.
    MIRROR_REVIEW = (Blake3, DeriveKeyContext, "oneiron:origin-mirror-review:v1");

    /// A frozen mirror plan's digest (`origin::publish::mirror_plan::plan_digest`). BLAKE3
    /// derive-key: the repository id (16 bytes, not framed); the URL, user, custody record,
    /// target generation hex (empty when none), audience visibility and role, and strategy;
    /// the strategy revision (8 bytes, u64 little-endian, not framed); per ref the name, the
    /// new object (empty for a deletion), the observed state (`absent`, `at`, `unknown`) and
    /// its value (empty, the oid or the cause), the batch (4 bytes, u32 little-endian,
    /// `u32::MAX` for none, not framed) and the section digest (empty when none); per held
    /// head the ref name, the head and the ancestor sent (empty when none); then the vector
    /// digest. Framed as `PUBLISH_REVIEW`. Stored as `MirrorPushPlan.digest` and returned in
    /// the plan view and the mirror status.
    MIRROR_PLAN = (Blake3, DeriveKeyContext, "oneiron:origin-mirror-plan:v1");

    /// What a mirror selection sends (`origin::publish::mirror_plan`,
    /// `MirrorSelection::vector_digest`). BLAKE3 derive-key: each pushed ref name and its
    /// object, then `d` (not framed), then each deleted ref name. Framed as
    /// `PUBLISH_REVIEW`. Stored as the plan's vector, which a full-auto mirror compares with
    /// its next selection.
    MIRROR_VECTOR = (Blake3, DeriveKeyContext, "oneiron:origin-mirror-vector:v1");
}
