//! Purposes of saved queries (`crates/oneiron/src/saved_query` and `oneiron-store`'s
//! `query_memo_codec`).

purposes! {}

legacy_purposes! {
    /// A verdict memo's params hash (`evaluator::derivation_envelope`,
    /// `SavedQueryDerivationEnvelope::params_hash`). SHA-256 with no tag: the matcher's
    /// sorted JSON (`matcher_to_json`, then `canonical_json_bytes`); lowercase hex. Every
    /// verdict memo row stores it.
    DERIVATION_PARAMS = (Sha256, NotHashed, "oneiron.saved_query.derivation_params.v1");

    /// The evidence hash (`compute_evidence_hash`). SHA-256: the tag first; the
    /// definition's schema and definition versions (big-endian) and its owner; the scope;
    /// the entity; then the claim values, the value fingerprints, the edge targets, the
    /// semantic inputs and the scope membership. Each list writes its count and each
    /// variable field its length first, as a u64 big-endian. Stored as
    /// `VerdictMemoKey.evidence_hash` (the memo key) and in membership event rows. Version 2
    /// also covers each claim value's lossless canonical bytes (FIX 10090); a v1 memo is
    /// never read again, and no legacy reader exists.
    EVIDENCE = (Sha256, HashedFirst, "oneiron.saved_query.evidence.v2");

    /// The judge's rubric hash (`decisions::judge`). Plain BLAKE3 with no tag: the rubric's
    /// sorted JSON. Its 32 bytes, then the rubric's version, seed the membership question
    /// (`SAVED_QUERY_MATCH`) and so its id.
    JUDGE_RUBRIC = (Blake3, NotHashed, "oneiron.saved_query.judge_rubric.v1");

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
