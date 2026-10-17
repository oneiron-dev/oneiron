//! The one projector: anchored evidence, a prior and a window in, one
//! superseding `learning.*` head per cell out.
//!
//! Nobody writes a learning claim by hand. A claim exists only while its cell
//! has own runs; a zero-run prior is assembled at read and never minted.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning_setting::{self, LEARNING_WINDOW_HALF_LIFE_DAYS};
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Named, SideTable};
use crate::temporal::TimeRange;

use super::cell::{LearningCell, LearningPredicate};
use super::estimate::{
    ESTIMATOR_VERSION, Estimate, EstimateForm, EstimateLabels, EstimateValue, OwnTally, Window,
    fold_value,
};
use super::evidence::{Anchor, CELL, CellRow, Observation, evidence_in_txn};
use super::judge::{JudgeConversion, conversions_in_txn};
use super::prior::cell_prior_in_txn;

/// The newest receipts a learning claim cites.
const MAX_CITED_RECEIPTS: usize = 64;

/// Seconds in a day, for the window setting's unit.
const DAY_SECS: f64 = 86_400.0;

/// The longest chain of judge conversions a score follows.
const MAX_CONVERSION_HOPS: usize = 8;

/// The fitted value of a vault-scope setting cell, cached beside its claim so
/// the hot readers of [`learning_setting::setting_value`] pay one row read.
/// Key: setting key.
pub(crate) const SETTING_FIT: SideTable<String, SettingFit, Named> =
    SideTable::new(&side_table::LEARNING_SETTING_FIT);

/// The fitted value of one setting, as of its last projection.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SettingFit {
    pub value: f64,
    pub runs: f64,
    pub at: u64,
}

/// The claim value: the estimate, its cell and the derived UNTESTED mark.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct StoredEstimateClaim {
    pub(crate) kind: String,
    pub(crate) form: EstimateForm,
    pub(crate) cell: LearningCell,
    pub(crate) estimate: Estimate,
    pub(crate) untested: bool,
}

const VALUE_KIND: &str = "estimate";

impl StoredEstimateClaim {
    fn new(cell: &LearningCell, estimate: &Estimate) -> Self {
        Self {
            kind: VALUE_KIND.to_owned(),
            form: estimate.form(),
            cell: cell.clone(),
            estimate: estimate.clone(),
            untested: estimate.untested(),
        }
    }

    pub(crate) fn to_value(&self) -> Result<rmpv::Value> {
        rmpv::ext::to_value(self)
            .map_err(|_| Error::InvariantViolation("learning estimate claim encode"))
    }

    pub(crate) fn from_value(value: &rmpv::Value) -> Result<Self> {
        rmpv::ext::from_value(value.clone()).map_err(|_| {
            Error::InvalidClaimBody("a learning claim value is an estimate with its cell")
        })
    }
}

/// The structural validator every learning claim write passes.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the value is not an estimate whose cell
/// names this claim's predicate and subject, or any part is malformed.
pub(crate) fn validate_learning_claim_structure(body: &ClaimBody) -> Result<()> {
    let stored = StoredEstimateClaim::from_value(&body.value)?;
    if stored.kind != VALUE_KIND {
        return Err(Error::InvalidClaimBody(
            "a learning claim's value kind is estimate",
        ));
    }
    if stored.cell.predicate.as_str() != body.predicate {
        return Err(Error::InvalidClaimBody(
            "a learning claim's cell names its own predicate",
        ));
    }
    if body.subject != ClaimSubject::Entity(stored.cell.subject) {
        return Err(Error::InvalidClaimBody(
            "a learning claim's cell names its own subject",
        ));
    }
    stored.cell.validate()?;
    stored.estimate.validate()?;
    if stored.form != stored.estimate.form() || !stored.cell.predicate.admits_form(stored.form) {
        return Err(Error::InvalidClaimBody(
            "a learning claim's form is its estimate's and its member's",
        ));
    }
    if stored.untested != stored.estimate.untested() {
        return Err(Error::InvalidClaimBody(
            "UNTESTED is derived from own runs and the prior's weight",
        ));
    }
    Ok(())
}

/// The window in force: the catalog half-life, in seconds.
pub(crate) fn window_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Window> {
    let days =
        learning_setting::setting_value_in_txn(&vault.store, txn, &LEARNING_WINDOW_HALF_LIFE_DAYS)?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let half_life = (days * DAY_SECS).round().max(1.0) as u64;
    Ok(Window { half_life })
}

/// Folds a cell's evidence into its estimate without writing anything.
pub(crate) fn fold_cell_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &CellRow,
    digest: &[u8; 32],
    now: u64,
) -> Result<(Estimate, Vec<String>)> {
    let prior = cell_prior_in_txn(vault, txn, row, digest)?;
    let window = window_in_txn(vault, txn)?;
    let conversions = conversions_in_txn(vault, txn)?;
    let mut evidence = evidence_in_txn(vault, txn, digest)?;
    // Newest first, so the citations are the newest receipts.
    evidence.sort_by(|a, b| b.1.at.cmp(&a.1.at).then_with(|| a.0.cmp(&b.0)));

    let mut tally = OwnTally::empty(row.form);
    let mut labels = EstimateLabels::default();
    let mut outcome_counts: BTreeMap<String, f64> = BTreeMap::new();
    let mut runs = 0.0;
    let mut cited = Vec::new();
    for (receipt, ev) in &evidence {
        if ev.observation.form() != row.form {
            continue;
        }
        let mut w = ev.weight * window.decay(now.saturating_sub(ev.at));
        if w <= 0.0 {
            continue;
        }
        // A found hidden flaw counts 1/rate, with the rate its draw recorded.
        if let (Anchor::Audit { rate }, Observation::Success(false)) = (ev.anchor, &ev.observation)
            && rate > 0.0
        {
            w /= rate;
        }
        let (observation, converted) = if row.cell.predicate == LearningPredicate::Reliability
            || ev.observation.form() != EstimateForm::Beta
        {
            convert(&ev.observation, ev.judge.as_deref(), &conversions)
        } else {
            (ev.observation.clone(), false)
        };
        match (&mut tally, &observation) {
            (OwnTally::Beta { wins, losses }, Observation::Success(ok)) => {
                if *ok {
                    *wins += w;
                } else {
                    *losses += w;
                }
            }
            // A converted binary score is fractional success mass, not a
            // newly observed run. The original receipt still holds its bool.
            (OwnTally::Beta { wins, losses }, Observation::Magnitude(score)) => {
                let score = score.clamp(0.0, 1.0);
                *wins += w * score;
                *losses += w * (1.0 - score);
            }
            (
                OwnTally::Mean {
                    sum_w,
                    sum_wx,
                    sum_wxx,
                },
                Observation::Magnitude(x),
            ) => {
                *sum_w += w;
                *sum_wx += w * x;
                *sum_wxx += w * x * x;
            }
            (OwnTally::Counts { counts }, Observation::Category(name)) => {
                *counts.entry(name.clone()).or_insert(0.0) += w;
            }
            _ => continue,
        }
        runs += w;
        if converted {
            labels.converted += w;
        }
        if ev.on_judge_model {
            labels.on_judge_model += w;
        }
        *labels
            .by_judge
            .entry(ev.judge.clone().unwrap_or_else(|| "none".to_owned()))
            .or_insert(0.0) += w;
        if let Some(label) = &ev.outcome_label {
            *outcome_counts.entry(label.clone()).or_insert(0.0) += w;
        }
        let mut references = vec![receipt.as_str()];
        if let Some(pack) = &ev.pack_attribution {
            references.push(&pack.attempt_receipt);
            references.push(&pack.outcome_receipt);
        }
        for reference in references {
            if cited.len() < MAX_CITED_RECEIPTS && !cited.iter().any(|r| r == reference) {
                cited.push(reference.to_owned());
            }
        }
    }
    if !outcome_counts.is_empty() {
        labels.outcome_counts = Some(outcome_counts);
    }
    let value: EstimateValue = fold_value(&prior, &tally);
    Ok((
        Estimate {
            value,
            runs,
            prior,
            of: row.of.clone(),
            labels,
            window,
            ver: ESTIMATOR_VERSION,
        },
        cited,
    ))
}

/// Follows a score through the judge-swap maps. Converted binary scores
/// become fractional Beta mass while retaining their original run weight.
fn convert<'a>(
    observation: &Observation,
    judge: Option<&'a str>,
    conversions: &'a BTreeMap<String, JudgeConversion>,
) -> (Observation, bool) {
    let Some(mut judge) = judge else {
        return (observation.clone(), false);
    };
    let mut x = match observation {
        Observation::Magnitude(x) => *x,
        Observation::Success(ok) => {
            if *ok {
                1.0
            } else {
                0.0
            }
        }
        Observation::Category(_) => return (observation.clone(), false),
    };
    let mut converted = false;
    for _ in 0..MAX_CONVERSION_HOPS {
        let Some(conversion) = conversions.get(judge) else {
            break;
        };
        x = conversion.map(x);
        judge = &conversion.to_judge;
        converted = true;
    }
    if converted {
        (Observation::Magnitude(x), true)
    } else {
        (observation.clone(), false)
    }
}

/// Re-projects one cell and writes its head: a new superseding claim when the
/// estimate moved, nothing when one head already says it, and a retraction of
/// every head when the window has left no own runs.
pub(crate) fn project_cell_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    digest: &[u8; 32],
    now: u64,
) -> Result<Option<Estimate>> {
    let row = CELL
        .get(&vault.store, wtxn, digest)?
        .ok_or(Error::CorruptedIndex("learning cell"))?;
    let (estimate, cited) = fold_cell_in_txn(vault, wtxn, &row, digest, now)?;
    let heads = active_heads_in_txn(vault, wtxn, &row.cell)?;

    if estimate.runs <= 0.0 {
        retract_heads_in_txn(vault, wtxn, &heads, now)?;
        cache_setting_fit_in_txn(vault, wtxn, &row.cell, None, now)?;
        return Ok(None);
    }

    let stored = StoredEstimateClaim::new(&row.cell, &estimate);
    let value = stored.to_value()?;
    let evidence = rmpv::Value::Array(
        cited
            .iter()
            .map(|r| rmpv::Value::from(r.as_str()))
            .collect(),
    );
    let unchanged = match heads.as_slice() {
        [(_, body, _)] => body.value == value && body.evidence.as_ref() == Some(&evidence),
        _ => false,
    };
    if !unchanged {
        let claim_id = vault.store.clock.entity_id()?;
        let mut body = ClaimBody::new(
            row.cell.predicate.as_str(),
            ClaimSubject::Entity(row.cell.subject),
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        body.evidence = Some(evidence);
        body.source = Some(ClaimSource::Observed);
        vault.put_reserved_claim_in_txn(
            wtxn,
            &claim_id,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        // Every active head goes, not just the first: two replicas that both
        // projected this cell hold two distinct heads after a sync.
        for (head_id, _, head_start) in &heads {
            vault.supersede_reserved_claim_in_txn(
                wtxn,
                &claim_id,
                head_id,
                now.max(*head_start),
            )?;
        }
    }
    cache_setting_fit_in_txn(vault, wtxn, &row.cell, Some(&estimate), now)?;
    Ok(Some(estimate))
}

/// Re-projects every registered cell, so the window keeps fading runs with no
/// new evidence arriving. An off-hot-path sweep; returns the cells it visited.
///
/// # Errors
///
/// Storage errors; the first failing cell aborts the sweep.
pub fn reproject_all_cells(vault: &Vault, now: u64) -> Result<usize> {
    crate::critic::review::project_all_review_dissent(vault, now)?;
    let digests: Vec<[u8; 32]> = {
        let rtxn = vault.store.env.read_txn()?;
        CELL.scan_keys(&vault.store, &rtxn, &[])?
    };
    for digest in &digests {
        vault.with_write_txn_grouped(|wtxn| {
            project_cell_in_txn(vault, wtxn, digest, now).map(|_| ())
        })?;
    }
    Ok(digests.len())
}

/// Re-projects every cell fitting the setting `key`, after its seed moved.
pub(crate) fn reproject_setting_cells_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &str,
    now: u64,
) -> Result<()> {
    let digests: Vec<[u8; 32]> = CELL
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, row)| {
            row.cell.predicate == LearningPredicate::Setting
                && row.cell.setting_key.as_deref() == Some(key)
        })
        .map(|(digest, _)| digest)
        .collect();
    for digest in &digests {
        project_cell_in_txn(vault, wtxn, digest, now)?;
    }
    Ok(())
}

/// The active, engine-written heads of `cell`.
pub(crate) fn active_heads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cell: &LearningCell,
) -> Result<Vec<(EntityId, ClaimBody, u64)>> {
    let predicate = cell.predicate.as_str();
    let mut rows = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, &cell.subject)? {
        let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if body.predicate != predicate
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.source != Some(ClaimSource::Observed)
            || body.approval != ClaimApprovalStatus::Auto
        {
            continue;
        }
        let Ok(stored) = StoredEstimateClaim::from_value(&body.value) else {
            continue;
        };
        if stored.cell != *cell {
            continue;
        }
        let header = entity_header(vault, txn, &id)?;
        rows.push((id, body, header.occurred_start));
    }
    Ok(rows)
}

fn entity_header(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<EntityMetadataHeader> {
    let raw = vault
        .store
        .port_entity_record(txn, id)?
        .map(|row| row.encode())
        .ok_or(Error::CorruptedIndex("learning claim entity"))?;
    EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("learning claim header"))
}

fn retract_heads_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    heads: &[(EntityId, ClaimBody, u64)],
    now: u64,
) -> Result<()> {
    for (id, body, _) in heads {
        let header = entity_header(vault, wtxn, id)?;
        // A withdrawal stamped before the row it closes would make the re-Put
        // range invalid and roll the transaction back.
        let at = now.max(header.occurred_start);
        let mut body = body.clone();
        body.lifecycle = ClaimLifecycleStatus::Retracted;
        body.valid_to = Some(at);
        vault.put_reserved_claim_in_txn(
            wtxn,
            id,
            &body,
            TimeRange {
                start: header.occurred_start,
                end: at,
            },
            header.learned_at,
        )?;
    }
    Ok(())
}

/// Keeps the vault-scope fit cache in step with the claim: only a root-typed
/// setting cell on its knob's global subject
/// (`learning_setting::global_setting_subject`), with no executor, axis or
/// consent scope, is the vault's fit. A project's or a skill's root-typed
/// cell never writes or clears it (OF-542).
fn cache_setting_fit_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    cell: &LearningCell,
    estimate: Option<&Estimate>,
    now: u64,
) -> Result<()> {
    if cell.predicate != LearningPredicate::Setting
        || cell.executor.is_some()
        || cell.axis.is_some()
        || cell.consent_scope.is_some()
        || !cell
            .type_ref
            .as_ref()
            .is_some_and(super::cell::TypeRef::is_root)
    {
        return Ok(());
    }
    let Some(key) = cell.setting_key.clone() else {
        return Ok(());
    };
    if crate::learning_setting::global_setting_subject(&key).ok() != Some(cell.subject) {
        return Ok(());
    }
    match estimate {
        Some(estimate) => SETTING_FIT.put(
            &vault.store,
            wtxn,
            &key,
            &SettingFit {
                value: estimate.mean(),
                runs: estimate.runs,
                at: now,
            },
        ),
        None => SETTING_FIT.delete(&vault.store, wtxn, &key).map(|_| ()),
    }
}
