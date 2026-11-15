//! Purposes of the Dreamer (`crates/oneiron/src/dreamer_consolidation`, `dreamer_runner`).

purposes! {}

legacy_purposes! {
    /// An agent-health trend DIAGNOSTIC's replay hash
    /// (`dreamer_runner::maintenance::agent_health::trend_output`). BLAKE3: the tag first;
    /// the margin (`actor` and the actor id, or `project` and the project id, 16 zero bytes
    /// when none; the words and ids not framed); the task-type node; the model, or one
    /// `0xff` byte when none; the metric token; then per side, prior then latest, its first
    /// and last day, numerator, denominator, known and eligible counts (each 8 bytes, u64
    /// little-endian), the attempt count and each attempt id, the ref count and each ref id,
    /// and the scope count and each scope. Every string is framed by its length and every
    /// count is written, each as a u64 little-endian. Stored as the DIAGNOSTIC body's
    /// `replay.content_hash`, which the row id binds, and returned in diagnostic reads.
    AGENT_HEALTH_TREND = (Blake3, HashedFirst, "oneiron.coach.agent_health.trend.v1");
}
