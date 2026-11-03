//! Skill edit cycle labels that bound their originating run identifiers.

/// Upper bound on a cycle label.
pub const SKILL_EDIT_CYCLE_MAX_BYTES: usize = 128;

/// The label prefix [`proven_cycle`] names a RUN-proven cycle with.
///
/// Pinned here because two modules have to agree on it: this one BUILDS the
/// label, and the attempt queue's run-id validator
/// (`crate::attempt_queue::validate`) sizes its own bound by subtracting this
/// prefix from [`SKILL_EDIT_CYCLE_MAX_BYTES`]. Spelling it twice is how a run
/// id the queue accepted became a cycle label nobody could name.
pub(crate) const SKILL_EDIT_CYCLE_RUN_PREFIX: &str = "run:";
