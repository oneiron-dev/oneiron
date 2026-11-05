//! Learned actor claim predicate vocabulary.

/// Distilled craft note about an actor. SET cardinality (§G.1).
pub const PREDICATE_ACTOR_LESSON: &str = "actor.lesson";
/// Recurring lapse pattern — the routing signal a spawner reads. SET.
pub const PREDICATE_ACTOR_FAILURE_MODE: &str = "actor.failure_mode";
/// What this actor is FOR, feeding spawn/routing decisions. SET.
pub const PREDICATE_ACTOR_SCOPE_NOTE: &str = "actor.scope_note";
/// Per-`(actor, skill)` effectiveness in `0..=1`. ONE per pair, superseding.
pub const PREDICATE_ACTOR_SKILL_FIT: &str = "actor.skill_fit";

/// Whether `predicate` is one of the §G.1 `actor.*` rows this module owns.
///
/// `actor.confidence_prior` is deliberately NOT here: it is
/// `provider_confidence`'s row, with its own structural validator, and
/// it shares only the reserved namespace.
#[must_use]
pub fn is_actor_claim_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        PREDICATE_ACTOR_LESSON
            | PREDICATE_ACTOR_FAILURE_MODE
            | PREDICATE_ACTOR_SCOPE_NOTE
            | PREDICATE_ACTOR_SKILL_FIT
    )
}
