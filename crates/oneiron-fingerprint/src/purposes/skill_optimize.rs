//! Purposes of skill optimization (`crates/oneiron/src/skill_optimize`).

purposes! {}

legacy_purposes! {
    /// An eval measurement request (`skill_optimize::eval_set::measurement`): plain BLAKE3,
    /// the tag's bytes (with its final NUL), then the named MessagePack of the
    /// `EvalMeasurementRequest`, unframed. The measurement row's key; its hex names the
    /// Coach job and its dedupe key, and a redelivered request finds its row by it.
    EVAL_MEASUREMENT_REQUEST = (Blake3, HashedFirst, "skill_optimize:eval_measurement:v1\0");

    /// Where a Partial measurement is measured again: plain BLAKE3, the tag's bytes (with
    /// its final NUL), the request digest, the row's request time and its settle time (0 for
    /// none; each u64 big-endian), all unframed. The re-measure row's key (FIX 12175).
    EVAL_MEASUREMENT_REMEASURE =
        (Blake3, HashedFirst, "skill_optimize:eval_measurement:remeasure:v1\0");
}
