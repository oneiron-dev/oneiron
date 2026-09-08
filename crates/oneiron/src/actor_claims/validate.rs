//! Stored-row structural validator and scope/lineage readers.

use rmpv::Value;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, PREDICATE_ACTOR_EDIT_COST,
    claim_evidence_taint,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::Result;

use super::invalid;
use super::rows::{
    ACTOR_CLAIM_LINEAGE_KEY, ACTOR_EDIT_COST_SCOPE_KEY, ACTOR_SKILL_FIT_SCOPE_KEY,
    PREDICATE_ACTOR_FAILURE_MODE, PREDICATE_ACTOR_LESSON, PREDICATE_ACTOR_SCOPE_NOTE,
    PREDICATE_ACTOR_SKILL_FIT, normalize_edit_cost_scope, normalize_note, valid_unit_interval,
};

// ---------------------------------------------------------------------------
// Structural validator (the claim.rs predicate-aware branch)
// ---------------------------------------------------------------------------
/// Whether `predicate` is one of the §G.1 `actor.*` rows this module owns.
///
/// `actor.confidence_prior` is deliberately NOT here: it is
/// [`crate::provider_confidence`]'s row, with its own structural validator, and
/// it shares only the reserved namespace.
#[must_use]
pub fn is_actor_claim_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        PREDICATE_ACTOR_LESSON
            | PREDICATE_ACTOR_FAILURE_MODE
            | PREDICATE_ACTOR_SCOPE_NOTE
            | PREDICATE_ACTOR_SKILL_FIT
            | PREDICATE_ACTOR_EDIT_COST
    )
}
/// Validates a stored `actor.*` body — the shape [`write_actor_claim`] writes.
///
/// Runs on EVERY write door including sync replay, so it is the property that
/// survives replication: a peer cannot land a bare, human-approved, or
/// wrong-typed `actor.*` row this vault would then read as its own projection.
///
/// The source pin mirrors `actor.confidence_prior`'s trust boundary exactly.
/// Same-owner multi-device sync preserves `src`, so a user's own rows replicate
/// and materialize; the cross-vault federation door restamps foreign claims
/// `src → Imported`, and this pin then rejects them. That is the intended
/// injection defense, not an oversight: a peer's opinion of who is careless
/// must never enter this vault's routing signal.
pub(crate) fn validate_actor_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(invalid("actor.* claim subject must be an entity"));
    }
    if body.confidence != 1.0 {
        return Err(invalid("actor.* claim confidence must be 1.0"));
    }
    if body.approval != ClaimApprovalStatus::Auto {
        return Err(invalid("actor.* claim approval must be auto"));
    }
    if body.source != Some(ClaimSource::Observed) {
        return Err(invalid("actor.* claim source must be observed"));
    }
    if body.evidence.is_none() {
        return Err(invalid("actor.* claim must carry the trace it rests on"));
    }
    if actor_claim_lineage(body).is_none() {
        return Err(invalid(
            "actor.* claim scope must carry a known lineage class",
        ));
    }
    // The pair key this predicate's rows are keyed on, or `None` for the SET
    // note rows — which is also what the scope check below is exact against.
    let pair_key = match body.predicate.as_str() {
        PREDICATE_ACTOR_SKILL_FIT => {
            let Value::F32(fit) = body.value else {
                return Err(invalid("actor.skill_fit value must be a fit in 0..=1"));
            };
            if !valid_unit_interval(fit) {
                return Err(invalid("actor.skill_fit must be a finite fit in 0..=1"));
            }
            if skill_fit_scope_skill(body.scope.as_ref()).is_none() {
                return Err(invalid(
                    "actor.skill_fit must scope its (actor, skill) pair",
                ));
            }
            Some(ACTOR_SKILL_FIT_SCOPE_KEY)
        }
        PREDICATE_ACTOR_EDIT_COST => {
            let Value::F32(cost) = body.value else {
                return Err(invalid("actor.edit_cost value must be a cost in 0..=1"));
            };
            if !valid_unit_interval(cost) {
                return Err(invalid("actor.edit_cost must be a finite cost in 0..=1"));
            }
            let Some(scope) = edit_cost_scope_name(body.scope.as_ref()) else {
                return Err(invalid(
                    "actor.edit_cost must scope its (actor, scope) pair",
                ));
            };
            if normalize_edit_cost_scope(scope)? != scope {
                return Err(invalid("actor.edit_cost scope must be normalized"));
            }
            Some(ACTOR_EDIT_COST_SCOPE_KEY)
        }
        _ => {
            let Some(text) = body.value.as_str() else {
                return Err(invalid("actor note value must be a string"));
            };
            if normalize_note(text)? != text {
                return Err(invalid("actor note value must be normalized"));
            }
            None
        }
    };
    // The scope map is the writer's, key for key: the lineage meet on every
    // row and the pair key on a pair-scoped row. A row carrying anything else
    // is scoping a conflict set this ledger does not define — including a
    // sensitivity or federation stamp a peer hoped this vault would honor.
    if !actor_scope_is_exact(body.scope.as_ref(), pair_key) {
        return Err(invalid(
            "actor.* claim scope carries a key this ledger does not write",
        ));
    }
    Ok(())
}
/// Whether a row's scope is EXACTLY the writer's keys: the lineage meet, plus
/// `pair_key` on a pair-scoped row, each once.
fn actor_scope_is_exact(scope: Option<&Value>, pair_key: Option<&str>) -> bool {
    let Some(Value::Map(entries)) = scope else {
        return false;
    };
    let mut lineage = 0_usize;
    let mut pair = 0_usize;
    for (key, _) in entries {
        match key.as_str() {
            Some(ACTOR_CLAIM_LINEAGE_KEY) => lineage += 1,
            Some(key) if Some(key) == pair_key => pair += 1,
            _ => return false,
        }
    }
    lineage == 1 && pair == usize::from(pair_key.is_some())
}
/// The EVIDENCE MEET a stored row rests on: `ToolOutput` for a TASK-lane row
/// citing attempt receipts, `Generated` for a CHAT-lane distilled note.
///
/// This is the lineage `src` deliberately does not carry (module header), and
/// the read ED-03 uses to tell a receipt-grounded row from a distilled one. It
/// is the ENGINE's evidence-taint read narrowed to the two meets this ledger
/// mints, so the same stamp the trust lattice enforces is the one this module
/// reasons about — one fact, one channel.
///
/// `None` means the row carries no legible lineage — including the taint
/// reader's own fail-closed answers (an unparseable or duplicated stamp reads
/// `Imported`, which this ledger never mints) — and the validator refuses that
/// on every write path.
#[must_use]
pub fn actor_claim_lineage(body: &ClaimBody) -> Option<ClaimSource> {
    match claim_evidence_taint(body) {
        Some(meet @ (ClaimSource::ToolOutput | ClaimSource::Generated)) => Some(meet),
        _ => None,
    }
}
/// The SKILL a scope map names, or `None` when it names none.
///
/// Reads the ONE pair entry rather than the whole map: an `actor.skill_fit`
/// scope also carries the row's lineage meet, and a duplicated pair key is two
/// answers to one question — so no answer, which the validator then refuses.
pub(super) fn skill_fit_scope_skill(scope: Option<&Value>) -> Option<EntityId> {
    let Some(Value::Map(entries)) = scope else {
        return None;
    };
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() != Some(ACTOR_SKILL_FIT_SCOPE_KEY) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let Value::Binary(bytes) = value else {
            return None;
        };
        let raw: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().ok()?;
        found = Some(EntityId::from_bytes(raw).ok()?);
    }
    found
}
/// The SCOPE an `*.edit_cost` scope map names, or `None` when it names none —
/// [`skill_fit_scope_skill`]'s sibling, duplicated-key rule included. Shared
/// with [`crate::edit_distance::attribution`]'s reads: a row's scope map also
/// carries the lineage meet, so a read matches on the ONE scope entry rather
/// than on the whole map.
pub(crate) fn edit_cost_scope_name(scope: Option<&Value>) -> Option<&str> {
    let Some(Value::Map(entries)) = scope else {
        return None;
    };
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() != Some(ACTOR_EDIT_COST_SCOPE_KEY) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(value.as_str()?);
    }
    found
}
