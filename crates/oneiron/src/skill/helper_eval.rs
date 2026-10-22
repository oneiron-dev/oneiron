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
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::skill_optimize::{EvalMeasurement, FamilyPurpose, MeasurementState, SufficiencyVerdict};

use super::helper::{CallableCase, CaseSplit, HelperPairedVerdict};
use super::identity::SkillContentHash;
use super::record::SkillRecord;

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
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
