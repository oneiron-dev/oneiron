//! Purposes of the git origin (`crates/oneiron/src/origin`).

purposes! {}

legacy_purposes! {
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
