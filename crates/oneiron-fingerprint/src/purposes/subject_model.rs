//! Purposes of the subject model (`crates/oneiron/src/subject_model`).

purposes! {}

legacy_purposes! {
    /// The digest of an entity's stored raw row in a subject restore review
    /// (`subject_model::archive`): plain SHA-256 of the row, no tag. The review carries the
    /// pending claim's digest and its prior heads' digests; the restore refuses a review
    /// whose digests differ from the rows' now, and the restored claim keeps the hex as
    /// its `archived_proposal_sha256` evidence.
    ARCHIVE_REVIEW = (Sha256, NotHashed, "oneiron.subject_model.archive_review.v1");
}
