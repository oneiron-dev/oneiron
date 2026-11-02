//! The helper gate's evidence (FIX 10154, 10155): the shared paired eval
//! measurement of a helper against its parent.
//!
//! The measurement's seat names the source-family ledger that splits the
//! helper's frozen cases, in place of a hash of the helper and case ref: a
//! Development family is in-sample, and a sealed family is held out only
//! inside the cohort that measurement served and counted. Its sufficiency
//! card, the paired lower-bound not-worse verdict, is the helper's
//! not-worse check. Unknown evidence leaves the helper pending: automatic
//! activation waits, while an ordinary save or the owner's own act is never
//! refused for it.

use std::collections::BTreeSet;

use crate::Vault;
use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill_optimize::{
    EvalArmPin, EvalAxisPin, EvalMeasurement, EvalMeasurementRequest, EvalSeat, FamilyPurpose,
    FloorSlicePolicy, JUDGE_SCORE_AXIS, JUDGE_SCORE_UNITS, MeasurementMethodPin, MeasurementState,
    ScoreDirection, SufficiencyVerdict, eval_seat_canary,
};

use super::helper::{CallableCase, CaseSplit, HelperPairedVerdict};
use super::identity::SkillContentHash;
use super::lifecycle::SkillLifecycle;
use super::record::SkillRecord;
use super::role::SkillRole;

/// The decision a helper's paired measurement waits on.
const HELPER_GATE_DECISION: &str = "callable_helper_gate";

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

/// The paired measurement each callable helper awaiting its gate asks for
/// (FIX 12069), by helper: its exact content as the candidate arm against
/// its parent's as the incumbent (no skill, when it has no parent), both
/// answered by `model` at `revision` on `seat`'s newest live cohort and
/// scored by `scorer`. This is exactly the pair the gate reads
/// ([`helper_measurement`]). None when the seat has no live cohort.
///
/// # Errors
///
/// Storage errors.
pub fn callable_helper_measurement_requests(
    vault: &Vault,
    seat: &EvalSeat,
    (model, revision): (&str, &str),
    scorer: &str,
) -> Result<Vec<(EntityId, EvalMeasurementRequest)>> {
    let Some(cohort) = vault
        .eval_cohorts(seat)?
        .into_iter()
        .rev()
        .find(|cohort| cohort.retired_at.is_none())
    else {
        return Ok(Vec::new());
    };
    let arm = |skill_digest| EvalArmPin {
        model: model.to_owned(),
        revision: revision.to_owned(),
        skill_digest,
    };
    let content = |record: &SkillRecord| record.content_hash.as_ref().map(SkillContentHash::to_hex);
    let mut requests = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_SKILL)? {
        let Some(record) = vault.get_skill_record(&id)? else {
            continue;
        };
        // An agent-born helper awaiting its gate, as the measured pack load
        // admits it.
        if record.role != SkillRole::Callable
            || record.call.is_none()
            || record.lifecycle_status != SkillLifecycle::Candidate
            || record.approval_status != ClaimApprovalStatus::Proposed
        {
            continue;
        }
        let Some(candidate) = content(&record) else {
            continue;
        };
        let parent = match record.forked_from {
            Some(parent) => vault.get_skill_record(&parent)?,
            None => None,
        };
        requests.push((
            id,
            EvalMeasurementRequest {
                decision: HELPER_GATE_DECISION.to_owned(),
                seat: seat.clone(),
                incumbent: arm(parent.as_ref().and_then(content)),
                candidate: arm(Some(candidate)),
                cohort: cohort.id,
                membership_digest: cohort.membership_digest.clone(),
                rubric_revision: cohort.rubric_revision.clone(),
                scorer: scorer.to_owned(),
                axis: EvalAxisPin {
                    axis: JUDGE_SCORE_AXIS.to_owned(),
                    direction: ScoreDirection::HigherIsBetter,
                    units: JUDGE_SCORE_UNITS.to_owned(),
                },
                floor_slices: FloorSlicePolicy::default(),
                canary: eval_seat_canary(seat).map(str::to_owned),
                method: MeasurementMethodPin::current(),
            },
        ));
    }
    Ok(requests)
}

/// The measurement `digest` names, when it compares this helper's exact
/// content (its candidate arm) with its parent's (its incumbent arm, or no
/// skill when it has no parent).
pub(super) fn helper_measurement(
    vault: &Vault,
    digest: &[u8; 32],
    helper: &SkillRecord,
    parent: Option<&SkillRecord>,
) -> Result<EvalMeasurement> {
    let measurement = vault.eval_measurement(digest)?.ok_or(invalid(
        "the helper gate reads a paired measurement of the helper against its parent",
    ))?;
    let content = |record: &SkillRecord| record.content_hash.as_ref().map(SkillContentHash::to_hex);
    let candidate = content(helper);
    if candidate.is_none()
        || measurement.request.candidate.skill_digest != candidate
        || measurement.request.incumbent.skill_digest != parent.and_then(content)
    {
        return Err(invalid(
            "the paired measurement does not compare this helper's content with its parent's",
        ));
    }
    Ok(measurement)
}

/// Which side of the split each case falls on, from the measured seat's
/// source-family ledger; `None` for a case that is no promotion evidence: an
/// unassigned root, a judge-audit family, or a sealed family outside the
/// cohort the measurement served.
pub(super) fn case_splits(
    vault: &Vault,
    measurement: &EvalMeasurement,
    cases: &[CallableCase],
) -> Result<Vec<Option<CaseSplit>>> {
    let seat = &measurement.request.seat;
    // Sealed rows count only as the claim released them, its exposures
    // counted (no exposure: nothing sealed was served).
    let served: BTreeSet<EntityId> = if measurement.exposures.is_empty() {
        BTreeSet::new()
    } else {
        vault
            .eval_cohorts(seat)?
            .into_iter()
            .find(|cohort| cohort.id == measurement.request.cohort)
            .map(|cohort| cohort.families)
            .unwrap_or_default()
    };
    cases
        .iter()
        .map(|case| {
            let family = vault.eval_family_of_root(seat, &case.case_ref)?;
            Ok(family.and_then(|family| match family.purpose {
                FamilyPurpose::Development => Some(CaseSplit::InSample),
                FamilyPurpose::SealedConfirmation if served.contains(&family.id) => {
                    Some(CaseSplit::HeldOut)
                }
                FamilyPurpose::SealedConfirmation | FamilyPurpose::JudgeAudit => None,
            }))
        })
        .collect()
}

/// What the measurement's sufficiency card says of the helper: not worse
/// only on a finished card that approves, worse on one that finds it worse,
/// and pending on anything else.
pub(super) fn paired_verdict(measurement: &EvalMeasurement) -> HelperPairedVerdict {
    match (&measurement.state, &measurement.card) {
        (MeasurementState::Final, Some(card)) if card.approves() => HelperPairedVerdict::NotWorse,
        (MeasurementState::Final, Some(card)) if card.verdict == SufficiencyVerdict::Worse => {
            HelperPairedVerdict::Worse
        }
        _ => HelperPairedVerdict::Pending,
    }
}
