//! Purposes of self-heal (`crates/oneiron/src/self_heal`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {}

legacy_purposes! {
    /// The issue a diagnostic finding files under (`self_heal::issue_work::issue_id`). Parts: the
    /// diagnostic, the recipe.
    DIAGNOSTIC_ISSUE = (Blake3, HashedFirst, "coach.diagnostic.issue.v1");

    /// The review-only proposal a completed dev runner's diff becomes
    /// (`self_heal::repair::dev_runner::propose_dev_runner_patch`). Parts: the runner actor, the
    /// attempt.
    DEV_RUNNER_PROPOSAL = (Blake3, HashedFirst, "oneiron:self-heal:dev-runner-proposal:v1");

    /// The one repair intent of a signed tier-1 diagnostic
    /// (`self_heal::sweep::propose_tier1_repairs`). Parts: the diagnostic.
    TIER1_REPAIR = (Blake3, HashedFirst, "oneiron:self-heal:tier1-repair:v1");
}
