//! Purposes of saved queries (`crates/oneiron/src/saved_query` and `oneiron-store`'s
//! `query_memo_codec`).

purposes! {}

legacy_purposes! {
    /// A verdict memo's params hash (`evaluator::derivation_envelope`,
    /// `SavedQueryDerivationEnvelope::params_hash`). SHA-256 with no tag: the matcher's
    /// sorted JSON (`matcher_to_json`, then `canonical_json_bytes`); lowercase hex. Every
    /// verdict memo row stores it.
    DERIVATION_PARAMS = (Sha256, NotHashed, "oneiron.saved_query.derivation_params.v1");

    /// The judge's rubric hash (`decisions::judge`). Plain BLAKE3 with no tag: the rubric's
    /// sorted JSON. Its 32 bytes, then the rubric's version, seed the membership question
    /// (`SAVED_QUERY_MATCH`) and so its id.
    JUDGE_RUBRIC = (Blake3, NotHashed, "oneiron.saved_query.judge_rubric.v1");
}
