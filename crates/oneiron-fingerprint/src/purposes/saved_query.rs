//! Purposes of saved queries (`crates/oneiron/src/saved_query` and `oneiron-store`'s
//! `query_memo_codec`).

purposes! {}

legacy_purposes! {
    /// The evidence hash (`compute_evidence_hash`). SHA-256: the tag first; the
    /// definition's schema and definition versions (big-endian) and its owner; the scope;
    /// the entity; then the claim values, the value fingerprints, the edge targets, the
    /// semantic inputs and the scope membership. Each list writes its count and each
    /// variable field its length first, as a u64 big-endian. Stored as
    /// `VerdictMemoKey.evidence_hash` (the memo key) and in membership event rows. Version 2
    /// also covers each claim value's lossless canonical bytes (FIX 10090); a v1 memo is
    /// never read again, and no legacy reader exists.
    EVIDENCE = (Sha256, HashedFirst, "oneiron.saved_query.evidence.v2");

    /// A membership plan's content digest (`plan_content_digest`). SHA-256: the tag first,
    /// then the encoded event and the encoded member value, each framed by a u64
    /// big-endian length. Stored in the membership watermark row (`epoch || content
    /// digest`), where a replay of the same plan reads as already applied.
    PLAN_CONTENT = (Sha256, HashedFirst, "oneiron.saved_query.plan.v1");

    /// The vector pair fingerprint (`vector_pair_fingerprint`). SHA-256 with no tag: per
    /// vector a presence byte, then its count as a u64 big-endian and each value's
    /// big-endian bits. Its hex is evidence, hashed into the stored evidence hash.
    VECTOR_PAIR = (Sha256, NotHashed, "oneiron.saved_query.vector_pair.v1");
}
