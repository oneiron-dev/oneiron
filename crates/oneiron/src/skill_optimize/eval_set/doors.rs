//! Owner-bound eval authoring and ledger doors. Source and case writes use the
//! same transaction helpers as the Coach. Ledger reads serve metadata, never
//! sealed labels; sealed cases leave only through the counted cohort release.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::cohort::{EXPOSURE_PREFIX, cohort_in_txn, exposure_in_txn, retired_families_in_txn};
use super::{
    CASE_PREFIX, DerivationKind, EvalCase, EvalCaseDraft, EvalCohort, EvalCutAudit, EvalExposure,
    EvalExposureCounts, EvalExposureKind, EvalLabelAsk, EvalRelease, EvalSeat, FAMILY_PREFIX,
    FamilyPurpose, SourceFamily, SufficiencyCard, SufficiencyInput, assign_family_in_txn,
    record_case_in_txn, rows_in_txn, sufficiency_card,
};
use crate::attempt_queue::{AttemptId, AttemptState};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::maintenance::coach::{
    COACH_EVAL_AUTHORING_FACET, COACH_HOST_QUEUE_KIND,
};
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::{EntityId, Error, Result, Vault};

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthorNowRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringRef {
    pub attempt: EntityId,
}

/// Completion is the host queue's state. A completed pass may author nothing:
/// no available skill, model or valid plan is never a fabricated report.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringResult {
    pub attempt: EntityId,
    pub state: AttemptState,
    pub terminal: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalSeatRequest {
    pub seat: EvalSeat,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalFamilyAssignRequest {
    pub seat: EvalSeat,
    pub roots: BTreeSet<String>,
    pub purpose: FamilyPurpose,
}

/// The derivation ledger's ids, kinds and dates, without its label values.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalCaseLineage {
    pub case: EntityId,
    pub kind: DerivationKind,
    pub receipts: Vec<String>,
    pub parents: Vec<EntityId>,
    pub stratum: Option<String>,
    pub draw_probability: Option<f64>,
    pub source_at: u64,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalFamilyView {
    pub family: SourceFamily,
    pub effective_purpose: FamilyPurpose,
    pub feeds_training: bool,
    pub rows: Vec<EvalCaseLineage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalCasesRequest {
    pub seat: EvalSeat,
    /// Sealed confirmation refuses here. Use a counted cohort release.
    pub purpose: FamilyPurpose,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalCohortView {
    pub cohort: EvalCohort,
    pub exposure: EvalExposureCounts,
    pub audit: Option<EvalCutAudit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalCohortRef {
    pub cohort: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalCohortOpenRequest {
    pub cohort: EntityId,
    pub kind: EvalExposureKind,
    pub consumer: String,
    #[serde(default)]
    pub candidate_pin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalExposureLedger {
    pub cohort: EntityId,
    pub counts: EvalExposureCounts,
    pub servings: Vec<EvalExposure>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalBlockedLabelsRequest {
    #[serde(default)]
    pub seat: Option<EvalSeat>,
    #[serde(default)]
    pub decision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalLabelPickRequest {
    pub decision: String,
    pub case: EntityId,
    pub choose_b: bool,
}

/// Queue the production recipe, coalescing with the nightly pass. The caller
/// supplies neither an authoring plan nor a Coach stamp or lease.
pub fn author_now(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: EvalAuthorNowRequest,
) -> Result<EvalAuthoringRef> {
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        let outcome = DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
            txn,
            COACH_HOST_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: COACH_EVAL_AUTHORING_FACET.into(),
                input: rmpv::Value::Nil,
                parent_attempt: None,
            },
            Some(COACH_EVAL_AUTHORING_FACET.into()),
            None,
            now,
        )?;
        let status = match outcome {
            EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status) => status,
        };
        Ok(EvalAuthoringRef {
            attempt: EntityId::from_bytes(*status.attempt.id.as_bytes())?,
        })
    })
}

pub fn authoring_result(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalAuthoringRef,
) -> Result<Option<EvalAuthoringResult>> {
    owner.revalidate(vault)?;
    let id = AttemptId::from_bytes(input.attempt.as_bytes())?;
    let Some(status) = DreamerRunnerStore::new(vault).status(id)? else {
        return Ok(None);
    };
    if status.attempt.kind != COACH_HOST_QUEUE_KIND
        || status.payload.attempt_type != COACH_EVAL_AUTHORING_FACET
    {
        return Err(Error::InvalidConfig(
            "the attempt is not an eval-authoring pass".into(),
        ));
    }
    Ok(Some(EvalAuthoringResult {
        attempt: input.attempt,
        state: status.attempt.state,
        terminal: status.attempt.state.is_terminal(),
        last_error: status.attempt.last_error,
    }))
}

pub fn assign_family(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalFamilyAssignRequest,
) -> Result<SourceFamily> {
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        assign_family_in_txn(vault, txn, &input.seat, &input.roots, input.purpose, now)
    })
}

pub fn record_case(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalCaseDraft,
) -> Result<EvalCase> {
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        // The owner's receipts name no rows they were read from (FIX 5761).
        record_case_in_txn(vault, txn, &input, None, now)
    })
}

pub fn families(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalSeatRequest,
) -> Result<Vec<EvalFamilyView>> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    input.seat.token()?;
    let retired = retired_families_in_txn(vault, &txn, &input.seat)?;
    let mut cases: BTreeMap<EntityId, Vec<EvalCaseLineage>> = BTreeMap::new();
    for case in rows_in_txn::<EvalCase>(vault, &txn, CASE_PREFIX)? {
        if case.seat != input.seat {
            continue;
        }
        cases.entry(case.family).or_default().push(EvalCaseLineage {
            case: case.id,
            kind: case.kind,
            receipts: case.receipts,
            parents: case.parents,
            stratum: case.stratum,
            draw_probability: case.draw_probability,
            source_at: case.source_at,
            recorded_at: case.recorded_at,
        });
    }
    let families = rows_in_txn::<SourceFamily>(vault, &txn, FAMILY_PREFIX)?;
    drop(txn);
    let mut views = Vec::new();
    for family in families {
        if family.seat != input.seat {
            continue;
        }
        let rows = cases.remove(&family.id).unwrap_or_default();
        let effective_purpose = if retired.contains(&family.id) {
            FamilyPurpose::Development
        } else {
            family.purpose
        };
        views.push(EvalFamilyView {
            feeds_training: vault.eval_family_feeds_training(&family.id)?,
            family,
            effective_purpose,
            rows,
        });
    }
    Ok(views)
}

pub fn cases(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalCasesRequest,
) -> Result<Vec<EvalCase>> {
    owner.revalidate(vault)?;
    input.seat.token()?;
    vault.eval_cases(&input.seat, input.purpose)
}

pub fn cohorts(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalSeatRequest,
) -> Result<Vec<EvalCohortView>> {
    owner.revalidate(vault)?;
    input.seat.token()?;
    vault
        .eval_cohorts(&input.seat)?
        .into_iter()
        .map(|cohort| {
            Ok(EvalCohortView {
                exposure: vault.eval_cohort_exposure(&cohort.id)?,
                audit: vault.eval_cut_audit(&cohort.id)?,
                cohort,
            })
        })
        .collect()
}

pub fn open_cohort(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalCohortOpenRequest,
) -> Result<EvalRelease> {
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        vault.open_eval_cohort_in_txn(
            txn,
            &input.cohort,
            input.kind,
            &input.consumer,
            input.candidate_pin.as_deref(),
            now,
        )
    })
}

pub fn exposure(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalCohortRef,
) -> Result<EvalExposureLedger> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    cohort_in_txn(vault, &txn, &input.cohort)?;
    let mut servings = rows_in_txn::<EvalExposure>(
        vault,
        &txn,
        &[EXPOSURE_PREFIX, input.cohort.as_bytes()].concat(),
    )?;
    servings.sort_by_key(|row| (row.at, row.id));
    Ok(EvalExposureLedger {
        cohort: input.cohort,
        counts: exposure_in_txn(vault, &txn, &input.cohort)?,
        servings,
    })
}

/// Computes a card only from supplied measurements. It measures no quality,
/// creates no waiting decision, and neither asks for labels nor deploys a model.
pub fn sufficiency(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SufficiencyInput,
) -> Result<SufficiencyCard> {
    owner.revalidate(vault)?;
    sufficiency_card(input)
}

pub fn blocked_labels(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalBlockedLabelsRequest,
) -> Result<Vec<EvalLabelAsk>> {
    let person = owner.revalidate(vault)?;
    if let Some(seat) = &input.seat {
        seat.token()?;
    }
    Ok(vault
        .eval_label_asks_for(&person)?
        .into_iter()
        .filter(|ask| {
            input.seat.as_ref().is_none_or(|seat| &ask.seat == seat)
                && input
                    .decision
                    .as_ref()
                    .is_none_or(|decision| &ask.decision == decision)
        })
        .collect())
}

pub fn pick_label(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalLabelPickRequest,
) -> Result<EvalCase> {
    vault.record_eval_label_pick(
        owner,
        &input.decision,
        &input.case,
        input.choose_b,
        vault.now_recorded_at(),
    )
}
