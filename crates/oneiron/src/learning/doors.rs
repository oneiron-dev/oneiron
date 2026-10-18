//! Owner reads of measured learning state and anchored outcome projection.
//! These doors never admit evidence or run a projector.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::ports::{EdgeDirection, EdgeStore};
use crate::skill_attribution::{LateCreditReceipt, late_credit_receipt_for_outcome};
use crate::{EntityId, Error, Result, Vault};

use super::cell::{LearningCell, LearningPredicate, TypeRef};
use super::estimate::{Estimate, EstimateLabels, EstimateValue, PriorOrigin, Window};
use super::evidence::{EvidenceRow, evidence_in_txn};
use super::project::active_heads_in_txn;
use super::read::read_learning_in_txn;

/// The four measured predicates, not the learned-setting catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum MeasuredLearningPredicate {
    #[serde(rename = "learning.reliability")]
    Reliability,
    #[serde(rename = "learning.edit_cost")]
    EditCost,
    #[serde(rename = "learning.retest_noise")]
    RetestNoise,
    #[serde(rename = "learning.setting")]
    Setting,
}

impl From<MeasuredLearningPredicate> for LearningPredicate {
    fn from(value: MeasuredLearningPredicate) -> Self {
        match value {
            MeasuredLearningPredicate::Reliability => Self::Reliability,
            MeasuredLearningPredicate::EditCost => Self::EditCost,
            MeasuredLearningPredicate::RetestNoise => Self::RetestNoise,
            MeasuredLearningPredicate::Setting => Self::Setting,
        }
    }
}

impl From<LearningPredicate> for MeasuredLearningPredicate {
    fn from(value: LearningPredicate) -> Self {
        match value {
            LearningPredicate::Reliability => Self::Reliability,
            LearningPredicate::EditCost => Self::EditCost,
            LearningPredicate::RetestNoise => Self::RetestNoise,
            LearningPredicate::Setting => Self::Setting,
        }
    }
}

/// A measured cell's key. Judge identity belongs to evidence, never this key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningCellKey {
    pub subject: String,
    pub predicate: MeasuredLearningPredicate,
    #[serde(default)]
    pub executor: Option<String>,
    #[serde(default, rename = "typeRef")]
    pub type_ref: Option<TypeRef>,
    #[serde(default)]
    pub axis: Option<String>,
    #[serde(default)]
    pub consent_scope: Option<String>,
    #[serde(default)]
    pub setting_key: Option<String>,
}

impl LearningCellKey {
    fn engine(&self) -> Result<LearningCell> {
        let cell = LearningCell {
            predicate: self.predicate.into(),
            subject: entity_id(&self.subject)?,
            executor: self.executor.clone(),
            type_ref: self.type_ref.clone(),
            axis: self.axis.clone(),
            consent_scope: self.consent_scope.clone(),
            setting_key: self.setting_key.clone(),
        };
        cell.validate()?;
        Ok(cell)
    }
}

impl From<LearningCell> for LearningCellKey {
    fn from(cell: LearningCell) -> Self {
        Self {
            subject: cell.subject.to_hex(),
            predicate: cell.predicate.into(),
            executor: cell.executor,
            type_ref: cell.type_ref,
            axis: cell.axis,
            consent_scope: cell.consent_scope,
            setting_key: cell.setting_key,
        }
    }
}

/// Read a cell, using the recorded task-type tree for its backoff chain.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningReadRequest {
    pub cell: LearningCellKey,
    /// A project's type tree, or the vault tree when absent.
    #[serde(default)]
    pub project_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningBetaValue {
    pub alpha: f64,
    pub beta: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningMeanValue {
    pub mean: f64,
    pub spread: f64,
}

/// The estimate's form selects the shape of its value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "form", content = "value", rename_all = "snake_case")]
pub enum MeasuredLearningValue {
    Beta(LearningBetaValue),
    Mean(LearningMeanValue),
    Counts(BTreeMap<String, f64>),
}

impl From<EstimateValue> for MeasuredLearningValue {
    fn from(value: EstimateValue) -> Self {
        match value {
            EstimateValue::Beta { alpha, beta } => Self::Beta(LearningBetaValue { alpha, beta }),
            EstimateValue::Mean { mean, spread } => Self::Mean(LearningMeanValue { mean, spread }),
            EstimateValue::Counts { counts } => Self::Counts(counts),
        }
    }
}

/// A prior has the same value shape as the estimate, without another form tag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum LearningPriorValue {
    Beta(LearningBetaValue),
    Mean(LearningMeanValue),
    Counts(BTreeMap<String, f64>),
}

impl From<EstimateValue> for LearningPriorValue {
    fn from(value: EstimateValue) -> Self {
        match value {
            EstimateValue::Beta { alpha, beta } => Self::Beta(LearningBetaValue { alpha, beta }),
            EstimateValue::Mean { mean, spread } => Self::Mean(LearningMeanValue { mean, spread }),
            EstimateValue::Counts { counts } => Self::Counts(counts),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningPriorView {
    pub origin: PriorOrigin,
    pub value: LearningPriorValue,
    pub weight_runs: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// The engine's estimate, with its derived UNTESTED mark and explicit prior.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MeasuredLearningEstimate {
    #[serde(flatten)]
    pub value: MeasuredLearningValue,
    pub runs: f64,
    pub prior: LearningPriorView,
    pub untested: bool,
    pub of: String,
    pub labels: EstimateLabels,
    pub window: Window,
    pub ver: String,
}

impl From<Estimate> for MeasuredLearningEstimate {
    fn from(estimate: Estimate) -> Self {
        let untested = estimate.untested();
        Self {
            value: estimate.value.into(),
            runs: estimate.runs,
            prior: LearningPriorView {
                origin: estimate.prior.origin,
                value: estimate.prior.value.into(),
                weight_runs: estimate.prior.weight_runs,
                from: estimate.prior.from,
            },
            untested,
            of: estimate.of,
            labels: estimate.labels,
            window: estimate.window,
            ver: estimate.ver.to_string(),
        }
    }
}

/// A stored projector head, including its exact citations and supersession edges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningHeadView {
    pub claim_ref: String,
    pub at: u64,
    pub evidence_receipts: Vec<String>,
    pub supersedes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningEvidenceView {
    pub receipt: String,
    pub evidence: EvidenceRow,
}

/// Provenance is separate for the requested cell and a borrowed prior's cell.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningProvenanceView {
    pub cell: LearningCellKey,
    pub heads: Vec<LearningHeadView>,
    pub evidence: Vec<LearningEvidenceView>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningCellView {
    pub cell: LearningCellKey,
    pub view: MeasuredLearningView,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MeasuredLearningView {
    pub estimate: MeasuredLearningEstimate,
    pub own: bool,
    pub borrowed_from: Option<LearningCellKey>,
    /// Anchors for this cell's own evidence, never borrowed runs.
    pub attributed_outcome_receipts: Vec<String>,
    pub provenance: LearningProvenanceView,
    pub prior_provenance: Option<LearningProvenanceView>,
}

/// Observe the atomic projection receipt for one anchored attempt outcome.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningProjectionRequest {
    pub attempt_receipt: String,
    pub outcome_receipt: String,
    pub axis: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningProjectionView {
    /// Absent means no committed projection, not an empty successful projection.
    pub receipt: Option<LateCreditReceipt>,
}

fn entity_id(reference: &str) -> Result<EntityId> {
    EntityId::from_hex(reference)
        .map_err(|_| Error::InvalidClaimBody("a learning record reference is an entity id, 32 hex"))
}

fn provenance(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cell: &LearningCell,
) -> Result<LearningProvenanceView> {
    let mut heads = Vec::new();
    for (id, body, at) in active_heads_in_txn(vault, txn, cell)? {
        let evidence_receipts = body
            .evidence
            .as_ref()
            .and_then(rmpv::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(rmpv::Value::as_str)
            .map(str::to_owned)
            .collect();
        let supersedes = vault
            .port_edge_neighbors(
                txn,
                &id,
                EdgeDirection::Out,
                Some(EdgeKind::Supersedes),
                usize::MAX,
            )?
            .into_iter()
            .map(|edge| edge.target.to_hex())
            .collect();
        heads.push(LearningHeadView {
            claim_ref: id.to_hex(),
            at,
            evidence_receipts,
            supersedes,
        });
    }
    let evidence = evidence_in_txn(vault, txn, &cell.digest())?
        .into_iter()
        .map(|(receipt, evidence)| LearningEvidenceView { receipt, evidence })
        .collect();
    Ok(LearningProvenanceView {
        cell: cell.clone().into(),
        heads,
        evidence,
    })
}

/// Reads the existing backoff projection; never folds a client-supplied estimate.
///
/// # Errors
///
/// Invalid owner proof, cell, record reference or type stamp; storage errors.
pub fn read_learning_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &LearningReadRequest,
) -> Result<LearningCellView> {
    owner.revalidate(vault)?;
    let cell = input.cell.engine()?;
    let project = input.project_ref.as_deref().map(entity_id).transpose()?;
    let parents = match &cell.type_ref {
        Some(stamp) => {
            let tree = crate::task_type::type_tree_at(vault, project, stamp.tree_version)?
                .filter(|tree| tree.contains(stamp))
                .ok_or(Error::InvalidClaimBody(
                    "the learning typeRef must name a recorded task-type tree",
                ))?;
            tree.ancestors(stamp)
        }
        None => Vec::new(),
    };
    let txn = vault.store.env.read_txn()?;
    let reading = read_learning_in_txn(vault, &txn, &cell, &parents)?;
    let provenance = provenance(vault, &txn, &cell)?;
    let prior_provenance = reading
        .borrowed_from
        .as_ref()
        .map(|source| self::provenance(vault, &txn, source))
        .transpose()?;
    let mut attributed_outcome_receipts = Vec::new();
    for row in &provenance.evidence {
        let receipt = row
            .evidence
            .pack_attribution
            .as_ref()
            .map_or(row.receipt.as_str(), |pack| pack.outcome_receipt.as_str());
        if !attributed_outcome_receipts.iter().any(|kept| kept == receipt) {
            attributed_outcome_receipts.push(receipt.to_owned());
        }
    }
    Ok(LearningCellView {
        cell: cell.into(),
        view: MeasuredLearningView {
            estimate: reading.estimate.into(),
            own: reading.own,
            borrowed_from: reading.borrowed_from.map(Into::into),
            attributed_outcome_receipts,
            provenance,
            prior_provenance,
        },
    })
}

/// Reads only the stored credit receipt. Its presence means the learning heads
/// and attribution receipt committed together, including a no-blame outcome.
///
/// # Errors
///
/// Invalid owner proof or malformed references; storage errors.
pub fn learning_projection_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &LearningProjectionRequest,
) -> Result<LearningProjectionView> {
    owner.revalidate(vault)?;
    for reference in [&input.attempt_receipt, &input.outcome_receipt, &input.axis] {
        if reference.is_empty() || reference.len() > 256 || reference.chars().any(char::is_control) {
            return Err(Error::InvalidClaimBody(
                "a projection reference is 1..=256 bytes without controls",
            ));
        }
    }
    Ok(LearningProjectionView {
        receipt: late_credit_receipt_for_outcome(
            vault,
            &input.attempt_receipt,
            &input.outcome_receipt,
            &input.axis,
        )?,
    })
}
