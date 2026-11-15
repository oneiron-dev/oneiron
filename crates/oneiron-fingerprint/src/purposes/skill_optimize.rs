//! Purposes of skill optimization (`crates/oneiron/src/skill_optimize`).

purposes! {}

legacy_purposes! {
    /// A live goal-axis plan's digest (`skill_optimize::gate::live`): SHA-256, the tag's
    /// bytes (with its final NUL), then each side's name (`offline`, `online`) and each of
    /// its axis names, each followed by a NUL, with no lengths; written as 64 lowercase hex
    /// digits. The pull cap is not hashed. A live row stores it, and the row's report
    /// binds a proposal only while it is equal.
    LIVE_AXIS_PLAN = (Sha256, HashedFirst, "skill_optimize:live_axis_plan:v1\0");
}
