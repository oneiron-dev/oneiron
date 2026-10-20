//! The lineage fixed code resolves for a candidate, from the existing
//! readers' explicit links only: the amendments a host grounded on its
//! receipt and the TURNs their proposals came from, the owner's picks on a
//! preference pair that holds it, and its run's derived-from chain as its
//! close witnessed it. Similarity never adds a root.
use std::collections::{BTreeMap, BTreeSet};

use super::CandidateLabel;
use crate::Vault;
use crate::edit_distance::attribution::amendments_by_attempt;
use crate::edit_distance::delta::amendment_delta;
use crate::edit_distance::reservoir::AMENDMENT_RECEIPT_ID_PREFIX;
use crate::edit_distance::{ProposalArtifactRef, finalized_proposal_text};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::{FIELD_EXECUTOR_SEAT, ReceiptRecord};
use crate::registry::ENTITY_TYPE_TURN;
use crate::skill_optimize::{
    EvalLabelKind, EvalSeat, PreferredResponse, ResponsePairPick, model_role_seat,
    response_pair_picks,
};

/// The root spelling of a TURN a candidate's text came from, as the training
/// split spells it.
pub(in crate::skill_optimize::eval_set) const SOURCE_TURN_ROOT: &str = "source_turn:";
/// The root spelling of any other entity on a run's derived-from chain.
const ENTITY_ROOT: &str = "entity:";
const AMENDED: &str = "amended";
const KEPT: &str = "kept";
const PREFERRED: &str = "preferred";
const NOT_PREFERRED: &str = "not_preferred";

/// The artifact an amendment receipt id names, if it is one.
pub(in crate::skill_optimize::eval_set) fn amendment_artifact(receipt: &str) -> Option<EntityId> {
    receipt
        .strip_prefix(AMENDMENT_RECEIPT_ID_PREFIX)
        .and_then(|hex| EntityId::from_hex(hex).ok())
}

/// One amendment the host grounded on an attempt's receipt.
struct AmendmentLink {
    receipt: String,
    artifact: EntityId,
    /// `amended` or `kept`, from its measured edit; `None` when unmeasured.
    outcome: Option<&'static str>,
    at: u64,
}

/// What fixed code resolved of one receipt's lineage, from explicit links
/// only.
#[derive(Debug, Default)]
pub(in crate::skill_optimize::eval_set) struct ReceiptLineage {
    pub(in crate::skill_optimize::eval_set) roots: BTreeSet<String>,
    /// TURNs behind it: its amendments' proposal sources, and the TURNs on
    /// its run's derived-from chain.
    pub(in crate::skill_optimize::eval_set) turns: BTreeSet<EntityId>,
    /// The proposal artifacts its amendments were made on.
    pub(in crate::skill_optimize::eval_set) artifacts: BTreeSet<EntityId>,
    pub(in crate::skill_optimize::eval_set) labels: Vec<CandidateLabel>,
    /// A TURN behind it lives in an off-record session, which derives
    /// nothing.
    pub(in crate::skill_optimize::eval_set) off_record: bool,
    /// The rows the receipt's attempt read, when the receipt keeps a
    /// complete set of them (FIX 5761). A pack receipt keeps none, so this
    /// stays `None`, unknown: the links above are inputs, not that set.
    pub(in crate::skill_optimize::eval_set) sources: Option<Vec<EntityId>>,
}

/// The existing readers' links, read once per pass: the amendments grounded
/// on each attempt receipt, and the owner's preference picks.
pub(in crate::skill_optimize::eval_set) struct LineageReader {
    amendments: BTreeMap<String, Vec<AmendmentLink>>,
    picks: Vec<ResponsePairPick>,
}

impl LineageReader {
    /// Reads the links. The amendments are the evidence ledger's grounded
    /// attempt joins, judged or not: an unjudged but measured amendment
    /// labels as a judged one does, and a judge's verdict never is the label.
    pub(in crate::skill_optimize::eval_set) fn read(vault: &Vault) -> Result<Self> {
        let mut amendments: BTreeMap<String, Vec<AmendmentLink>> = BTreeMap::new();
        for (attempt, evidence) in amendments_by_attempt(vault)? {
            let mut links = Vec::new();
            for evidence in evidence {
                let Some(artifact) = amendment_artifact(&evidence.receipt_id) else {
                    continue;
                };
                let outcome = amendment_delta(vault, &evidence.receipt_id)?
                    .map(|delta| if delta.d_norm > 0.0 { AMENDED } else { KEPT });
                links.push(AmendmentLink {
                    receipt: evidence.receipt_id,
                    artifact,
                    outcome,
                    at: evidence.at,
                });
            }
            if !links.is_empty() {
                amendments.insert(attempt, links);
            }
        }
        Ok(Self {
            amendments,
            picks: response_pair_picks(vault)?,
        })
    }

    /// The roots, sources and labels of `receipt`, from its grounded
    /// amendments, the owner's picks and its run's derived-from chain.
    pub(in crate::skill_optimize::eval_set) fn resolve(
        &self,
        vault: &Vault,
        receipt: &ReceiptRecord,
    ) -> Result<ReceiptLineage> {
        let mut lineage = ReceiptLineage::default();
        lineage.roots.insert(receipt.receipt_id.clone());
        for link in self
            .amendments
            .get(&receipt.receipt_id)
            .into_iter()
            .flatten()
        {
            lineage.roots.insert(link.receipt.clone());
            lineage.artifacts.insert(link.artifact);
            if let Some(outcome) = link.outcome {
                // The measured edit is read from the proposal artifact.
                lineage.labels.push(world_label(
                    outcome,
                    &link.receipt,
                    link.at,
                    Some(vec![link.artifact]),
                ));
            }
            if let Some(proposal) =
                finalized_proposal_text(vault, ProposalArtifactRef::new(link.artifact))?
                && let Some(turn) = proposal.source_turn_ref
            {
                lineage.turns.insert(turn);
            }
        }
        for pick in &self.picks {
            let Some((first, second)) = pick.pair_ref.split_once('|') else {
                continue;
            };
            let side = if first == receipt.receipt_id {
                PreferredResponse::First
            } else if second == receipt.receipt_id {
                PreferredResponse::Second
            } else {
                continue;
            };
            let value = if pick.preferred == side {
                PREFERRED
            } else {
                NOT_PREFERRED
            };
            // The pair names its responses by receipt key only: unknown.
            lineage
                .labels
                .push(world_label(value, &pick.pair_ref, pick.picked_at, None));
        }
        // The run's derived-from chain, as its close witnessed it. A receipt
        // no host attributed carries none.
        if let Ok(fields) = receipt.pack_attribution_fields() {
            let txn = vault.store.env.read_txn()?;
            for node in fields
                .used_edges
                .iter()
                .flat_map(|edge| [edge.derived, edge.source])
            {
                if vault.get_entity_type_in_txn(&txn, &node)? == Some(ENTITY_TYPE_TURN) {
                    lineage.turns.insert(node);
                } else {
                    lineage
                        .roots
                        .insert(format!("{ENTITY_ROOT}{}", node.to_hex()));
                }
            }
        }
        for turn in &lineage.turns {
            if vault.store.off_record_sessions.contains_entity(turn)? {
                lineage.off_record = true;
            }
            lineage
                .roots
                .insert(format!("{SOURCE_TURN_ROOT}{}", turn.to_hex()));
        }
        Ok(lineage)
    }
}

fn world_label(
    value: &str,
    reference: &str,
    at: u64,
    source_rows: Option<Vec<EntityId>>,
) -> CandidateLabel {
    CandidateLabel {
        kind: EvalLabelKind::WorldOutcome,
        value: value.to_owned(),
        reference: reference.to_owned(),
        at,
        held: false,
        source_rows,
    }
}

/// The seat a pack receipt records: the role seat of the functional role its
/// executor ran as (OF-578), the seat a training offer for that role reads.
/// A receipt no role ran keeps the template seat its run was configured with
/// (`executor_seat`, a `provider/name@revision` model id), less its revision,
/// since a seat outlives its checkpoint. `None` when the receipt names
/// neither, records a role it cannot decode, or names one no seat name can
/// hold.
pub(super) fn receipt_seat(receipt: &ReceiptRecord) -> Option<EvalSeat> {
    if let Some(role) = receipt.executor_role().ok()? {
        return Some(model_role_seat(role));
    }
    let configured = receipt.fields.get(FIELD_EXECUTOR_SEAT)?;
    let model = configured
        .rsplit_once('@')
        .map_or(configured.as_str(), |(model, _)| model);
    let seat = EvalSeat::Named(model.replace('/', "."));
    seat.token().is_ok().then_some(seat)
}
