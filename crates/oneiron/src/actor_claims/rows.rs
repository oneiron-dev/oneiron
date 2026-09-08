//! `actor.*` row vocabulary: predicates, bounds, row/note types, and normalization.

use rmpv::Value;

use crate::claim::{CLAIM_SCOPE_EVIDENCE_TAINT_KEY, PREDICATE_ACTOR_EDIT_COST};
use crate::entity_id::EntityId;
use crate::error::Result;

use super::invalid;

/// Distilled craft note about an actor. SET cardinality (§G.1).
pub const PREDICATE_ACTOR_LESSON: &str = "actor.lesson";
/// Recurring lapse pattern — the routing signal a spawner reads. SET.
pub const PREDICATE_ACTOR_FAILURE_MODE: &str = "actor.failure_mode";
/// What this actor is FOR, feeding spawn/routing decisions. SET.
pub const PREDICATE_ACTOR_SCOPE_NOTE: &str = "actor.scope_note";
/// Per-`(actor, skill)` effectiveness in `0..=1`. ONE per pair, superseding.
pub const PREDICATE_ACTOR_SKILL_FIT: &str = "actor.skill_fit";
/// Scope key naming the SKILL half of a [`PREDICATE_ACTOR_SKILL_FIT`] pair.
/// The scope IS the conflict set: two rows collide iff their skill matches.
pub const ACTOR_SKILL_FIT_SCOPE_KEY: &str = "skill";
/// Scope key naming the SCOPE half of a [`PREDICATE_ACTOR_EDIT_COST`] pair
/// (ED-03). Same shape and same job as [`ACTOR_SKILL_FIT_SCOPE_KEY`]: two cost
/// rows collide iff they speak about the same scope.
pub const ACTOR_EDIT_COST_SCOPE_KEY: &str = "scope";
/// Longest accepted `actor.edit_cost` scope, borrowed from the consent bound
/// the ED lane measures every other scope axis against
/// (`edit_distance::escalation`).
pub const ACTOR_EDIT_COST_SCOPE_MAX_BYTES: usize = crate::consent::MAX_CONSENT_REF_LEN;
/// [`CallPurpose::Other`] name for the CHAT-lane distillation tier, so session
/// distillation is budgeted and audited as its own class instead of hiding
/// inside consolidation's totals.
pub const ACTOR_DISTILL_CALL_PURPOSE_NAME: &str = "actor_session_distill";
/// Maximum UTF-8 length of a note. Notes are craft memory, not transcripts —
/// a row that needs more than this is citing, not distilling.
pub const ACTOR_NOTE_MAX_BYTES: usize = 1024;
/// Upper bound on the evidence refs one row cites. The trace is a citation
/// list, and a citation list that grows without bound turns a claim body into
/// a ledger (the `skill.reliability` bound, same reasoning).
pub const ACTOR_CLAIM_MAX_CITED_EVIDENCE: usize = 64;
/// The failure mode `ExecutionLapse` names.
///
/// SK-04 routes `ExecutionLapse` on exactly one fact pattern: a FAILED attempt
/// whose actor departed from a skill its pack had loaded. So this token is a
/// DERIVATION of the routing decision, not a judgement of taste — and it is a
/// token rather than prose because the router reads it back. It grows into a
/// table only when SK-04 learns to route a second lapse class.
///
/// A lapse mints this row and NOTHING else. The lesson such a lapse teaches is
/// situation-specific prose, which no deterministic router can derive — that is
/// the distiller tier's work, and inventing a house sentence here to fill the
/// slot would be the engine writing content it has no evidence for.
pub const LAPSE_FAILURE_MODE: &str = "departed_from_loaded_skill";
/// Scope key carrying the EVIDENCE MEET of a row: the [`ClaimSource`] wire
/// string of what the row actually rests on. See the module header — this is
/// the lineage `src` deliberately does not carry.
///
/// It IS the engine's `evidence_taint` key (`claim.rs`, ONE-1385), not a
/// namespace of this ledger's own: the meet is written to be read by
/// `claim_evidence_taint` and the consolidation/corroboration gates that call
/// it. A private key would stamp a fact nothing enforces.
pub const ACTOR_CLAIM_LINEAGE_KEY: &str = CLAIM_SCOPE_EVIDENCE_TAINT_KEY;
// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------
/// One `actor.*` row, before it is a claim.
///
/// Owning every shape in one enum is what makes [`write_actor_claim`] a
/// chokepoint rather than a convention: a new row kind cannot be written
/// without a variant here, and every variant lands through the same door.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ActorClaimRow {
    Lesson {
        actor: EntityId,
        text: String,
    },
    FailureMode {
        actor: EntityId,
        text: String,
    },
    ScopeNote {
        actor: EntityId,
        text: String,
    },
    SkillFit {
        actor: EntityId,
        skill: EntityId,
        fit: f32,
    },
    /// Per-`(actor, scope)` amendment cost in `0..=1` (ED-03, ONE-1759). ONE
    /// per pair, superseding — the `skill_fit` cardinality, for the same
    /// reason: it is a current estimate, not a standing fact.
    ///
    /// `cost` is an AGGREGATE the judge earned, never a raw Δ:
    /// [`crate::edit_distance::attribution::project_edit_cost_claims`] is the
    /// only writer, and it takes judgments rather than deltas so an
    /// unclassified edit has no path to this row.
    EditCost {
        actor: EntityId,
        scope: String,
        cost: f32,
    },
}
/// Which of the three SET-cardinality note rows a distilled note becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ActorNoteKind {
    Lesson,
    FailureMode,
    ScopeNote,
}
impl ActorNoteKind {
    pub(super) fn row(self, actor: EntityId, text: String) -> ActorClaimRow {
        match self {
            Self::Lesson => ActorClaimRow::Lesson { actor, text },
            Self::FailureMode => ActorClaimRow::FailureMode { actor, text },
            Self::ScopeNote => ActorClaimRow::ScopeNote { actor, text },
        }
    }
}
/// One note a distiller produced, naming the actor it is ABOUT.
///
/// The actor rides the note rather than the brief because a sitting can teach
/// about several actors at once (the agent, a peer it consulted, the human):
/// "actors = agents + humans + peers + connectors" is the namespace's whole
/// point, and a brief-level actor would flatten it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorNote {
    pub actor: EntityId,
    pub kind: ActorNoteKind,
    pub text: String,
}
impl ActorClaimRow {
    /// The predicate this row writes.
    #[must_use]
    pub const fn predicate(&self) -> &'static str {
        match self {
            Self::Lesson { .. } => PREDICATE_ACTOR_LESSON,
            Self::FailureMode { .. } => PREDICATE_ACTOR_FAILURE_MODE,
            Self::ScopeNote { .. } => PREDICATE_ACTOR_SCOPE_NOTE,
            Self::SkillFit { .. } => PREDICATE_ACTOR_SKILL_FIT,
            Self::EditCost { .. } => PREDICATE_ACTOR_EDIT_COST,
        }
    }

    /// The ACTOR entity this row is about.
    #[must_use]
    pub const fn actor(&self) -> EntityId {
        match self {
            Self::Lesson { actor, .. }
            | Self::FailureMode { actor, .. }
            | Self::ScopeNote { actor, .. }
            | Self::SkillFit { actor, .. }
            | Self::EditCost { actor, .. } => *actor,
        }
    }

    /// Validates the payload and renders `(value, scope)`.
    ///
    /// Notes normalize before they are compared, so the SET key is the note's
    /// MEANING as far as the ledger can see it: `"  Cite the receipt  "` and
    /// `"cite the receipt"` are the same standing fact and must not become two
    /// rows.
    pub(super) fn value_and_scope(&self) -> Result<(Value, Option<Value>)> {
        match self {
            Self::Lesson { text, .. }
            | Self::FailureMode { text, .. }
            | Self::ScopeNote { text, .. } => Ok((Value::from(normalize_note(text)?), None)),
            Self::SkillFit { skill, fit, .. } => {
                if !valid_unit_interval(*fit) {
                    return Err(invalid("actor.skill_fit must be a finite fit in 0..=1"));
                }
                Ok((Value::F32(*fit), Some(skill_fit_scope(skill))))
            }
            Self::EditCost { scope, cost, .. } => {
                if !valid_unit_interval(*cost) {
                    return Err(invalid("actor.edit_cost must be a finite cost in 0..=1"));
                }
                Ok((
                    Value::F32(*cost),
                    Some(edit_cost_scope(normalize_edit_cost_scope(scope)?)),
                ))
            }
        }
    }
}
/// Trims and collapses interior whitespace; rejects an empty or oversized note.
pub(super) fn normalize_note(text: &str) -> Result<String> {
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return Err(invalid("actor note must be non-empty"));
    }
    if normalized.len() > ACTOR_NOTE_MAX_BYTES {
        return Err(invalid("actor note exceeds the note length bound"));
    }
    Ok(normalized)
}
pub(super) fn skill_fit_scope(skill: &EntityId) -> Value {
    Value::Map(vec![(
        Value::from(ACTOR_SKILL_FIT_SCOPE_KEY),
        Value::Binary(skill.as_bytes().to_vec()),
    )])
}
/// The `{scope}` pair map of an `*.edit_cost` row — the writer both the
/// `actor.*` door and the `skill.*` door in
/// [`crate::edit_distance::attribution`] share, so one row shape means one
/// conflict-set key lane-wide.
pub(crate) fn edit_cost_scope(scope: &str) -> Value {
    Value::Map(vec![(
        Value::from(ACTOR_EDIT_COST_SCOPE_KEY),
        Value::from(scope),
    )])
}
/// The trimmed scope of an `actor.edit_cost` row, or the reason it is not one.
///
/// Trimmed before it becomes a conflict-set key, so `"outbound"` and
/// `" outbound "` are one pair rather than two live rows about the same thing —
/// the note rows' normalization law, applied to the axis this row is keyed on.
pub(super) fn normalize_edit_cost_scope(scope: &str) -> Result<&str> {
    let trimmed = scope.trim();
    if trimmed.is_empty() || trimmed.len() > ACTOR_EDIT_COST_SCOPE_MAX_BYTES {
        return Err(invalid(
            "actor.edit_cost scope must be non-empty and within the consent-ref bound",
        ));
    }
    Ok(trimmed)
}
/// A fit or a cost is a finite estimate in the unit interval. The finiteness
/// half is explicit: NaN fails every range comparison, so a `contains` check
/// ALONE would silently admit it and poison every downstream ranking.
pub(super) fn valid_unit_interval(estimate: f32) -> bool {
    estimate.is_finite() && (0.0..=1.0).contains(&estimate)
}
