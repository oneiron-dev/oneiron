//! Owner reads of measured learning state and anchored outcome projection.
//! These doors never admit evidence or run a projector.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::ports::{EdgeDirection, EdgeStore};
use crate::skill_attribution::{LateCreditReceipt, late_credit_receipt_for_outcome};
use crate::{Error, Result, Vault, WriteActor};

use super::cell::{LearningCell, TypeRef};
use super::evidence::{EvidenceRow, evidence_in_txn};
use super::project::active_heads_in_txn;
use super::read::read_learning_in_txn;

pub use crate::claim::learning_predicate::MeasuredLearningPredicate;

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
    /// The project whose runs the cell counts, as an entity id; absent, the
    /// vault's (FIX 6038).
    #[serde(default)]
    pub project: Option<String>,
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
            project: self.project.as_deref().map(entity_id).transpose()?,
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
            project: cell.project.map(|project| project.to_hex()),
        }
    }
}

/// Read a cell, using the recorded task-type tree for its backoff chain.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningReadRequest {
    pub cell: LearningCellKey,
    /// A project's type tree and the cell's scope, or the vault's when
    /// absent; the key's own project names them when this is absent.
    #[serde(default)]
    pub project_ref: Option<String>,
}

#[doc(hidden)]
use oneiron_verb_wire::learning::doors::entity_id;
#[doc(hidden)]
pub use oneiron_verb_wire::learning::doors::{
    LearningBetaValue, LearningHeadView, LearningMeanValue, LearningPriorValue, LearningPriorView,
    LearningProjectionRequest, MeasuredLearningEstimate, MeasuredLearningValue,
};

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningProjectionView {
    /// Absent means no committed projection, not an empty successful projection.
    pub receipt: Option<LateCreditReceipt>,
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
    read_learning(vault, input)
}

/// [`read_learning_as_owner`] for an agent or person holding a live Steward
/// grant that names `read` (untangle 6.6c), checked at this read.
///
/// # Errors
///
/// A caller who holds no such grant; as [`read_learning_as_owner`].
pub fn read_learning_as_reader(
    vault: &Vault,
    reader: WriteActor,
    input: &LearningReadRequest,
) -> crate::memory::MemoryResult<LearningCellView> {
    crate::federation::admit_substrate_read_by(
        vault,
        reader,
        "vault.learning.read",
        crate::federation::SubstrateRead::Evidence,
    )?;
    Ok(read_learning(vault, input)?)
}

/// `vault.learning.read` on a bound handle: the embedded owner reads under
/// its own proof, any other caller as a reader.
///
/// # Errors
///
/// As [`read_learning_as_owner`] and [`read_learning_as_reader`].
pub fn read_learning_embedded(
    memory: &crate::memory::Memory<'_>,
    input: &LearningReadRequest,
) -> crate::memory::MemoryResult<LearningCellView> {
    match memory.embedded_owner("vault.learning.read") {
        Ok(owner) => Ok(read_learning_as_owner(memory.vault(), &owner, input)?),
        Err(_) => read_learning_as_reader(
            memory.vault(),
            WriteActor::new(memory.actor(), memory.actor_class()),
            input,
        ),
    }
}

fn read_learning(vault: &Vault, input: &LearningReadRequest) -> Result<LearningCellView> {
    let cell = input.cell.engine()?;
    let project = input.project_ref.as_deref().map(entity_id).transpose()?;
    // One scope steers the cell and its tree (FIX 6038).
    let project = project.or(cell.project);
    let cell = cell.with_project(project);
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
    let attributed_outcome_receipts = attributed_outcome_receipts(&provenance);
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

/// The outcome receipts `provenance`'s evidence is attributed to, each once:
/// a pack attribution's outcome receipt, else the evidence receipt.
fn attributed_outcome_receipts(provenance: &LearningProvenanceView) -> Vec<String> {
    let mut attributed = Vec::new();
    for row in &provenance.evidence {
        let receipt = row
            .evidence
            .pack_attribution
            .as_ref()
            .map_or(row.receipt.as_str(), |pack| pack.outcome_receipt.as_str());
        if !attributed.iter().any(|kept| kept == receipt) {
            attributed.push(receipt.to_owned());
        }
    }
    attributed
}

/// Keeps only `receipts` in `provenance`: its evidence rows and each head's
/// citations. Gives back how many evidence rows it dropped.
fn scope_provenance(provenance: &mut LearningProvenanceView, receipts: &BTreeSet<String>) -> u64 {
    let all = provenance.evidence.len();
    provenance
        .evidence
        .retain(|row| receipts.contains(&row.receipt));
    for head in &mut provenance.heads {
        head.evidence_receipts
            .retain(|receipt| receipts.contains(receipt));
    }
    u64::try_from(all.saturating_sub(provenance.evidence.len())).unwrap_or(u64::MAX)
}

/// `cell`'s reading in one snapshot, with its provenance cut to `receipts`, as
/// a critic review's own read shows its critics' cells (`vault.critic.findings`).
/// The estimate is the whole cell's, while evidence rows, head citations and
/// attributed receipts, a borrowed prior's too, name only `receipts`. Also gives
/// back how many of the cell's own evidence rows are not shown. It writes
/// nothing and runs no projector.
///
/// # Errors
///
/// An invalid cell or type stamp; storage errors.
pub(crate) fn receipt_scoped_cell_view(
    vault: &Vault,
    cell: &LearningCell,
    parents: &[TypeRef],
    receipts: &BTreeSet<String>,
) -> Result<(LearningCellView, u64)> {
    let txn = vault.store.env.read_txn()?;
    let reading = read_learning_in_txn(vault, &txn, cell, parents)?;
    let mut own = provenance(vault, &txn, cell)?;
    let undisclosed = scope_provenance(&mut own, receipts);
    let prior_provenance = reading
        .borrowed_from
        .as_ref()
        .map(|source| {
            let mut prior = provenance(vault, &txn, source)?;
            scope_provenance(&mut prior, receipts);
            Ok::<_, Error>(prior)
        })
        .transpose()?;
    let attributed_outcome_receipts = attributed_outcome_receipts(&own);
    let view = LearningCellView {
        cell: cell.clone().into(),
        view: MeasuredLearningView {
            estimate: reading.estimate.into(),
            own: reading.own,
            borrowed_from: reading.borrowed_from.map(Into::into),
            attributed_outcome_receipts,
            provenance: own,
            prior_provenance,
        },
    };
    Ok((view, undisclosed))
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
        if reference.is_empty() || reference.len() > 256 || reference.chars().any(char::is_control)
        {
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
