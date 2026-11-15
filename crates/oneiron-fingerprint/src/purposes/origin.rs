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
}
