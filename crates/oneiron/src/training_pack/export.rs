//! The existing consented reservoir becomes a reproducible, source-grouped split.
use std::collections::BTreeSet;

use serde_json::Value;

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edit_distance::reservoir::{ReservoirScope, amendment_receipt_id, export_reservoir};
use crate::edit_distance::{ProposalArtifactRef, finalized_proposal_text};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::ModelLocality;
use crate::llm::run_admission::{PaidConnector, Payer};
use crate::skill_optimize::FamilyPurpose;

use super::custody::keep_bytes;
use super::{
    ComputeChoice, ComputePin, CorpusSplit, RUNS, SplitRow, SplitSide, TrainingPackDraft,
    TrainingRun, TrainingState, hash_json, invalid,
};

struct SplitBytes {
    training: Vec<u8>,
    held_out: Vec<u8>,
    rows: Vec<SplitRow>,
    overlaps: u64,
}

fn split_bytes(
    vault: &Vault,
    draft: &TrainingPackDraft,
    body: &[u8],
    cohort: &crate::skill_optimize::EvalCohort,
) -> Result<SplitBytes> {
    let mut split = SplitBytes {
        training: Vec::new(),
        held_out: Vec::new(),
        rows: Vec::new(),
        overlaps: 0,
    };
    let mut train_hashes = BTreeSet::new();
    let mut held_hashes = BTreeSet::new();
    for line in body
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let pair: Value =
            serde_json::from_slice(line).map_err(|_| invalid("invalid reservoir JSONL"))?;
        let id = EntityId::from_hex(
            pair["receipt_ref"]
                .as_str()
                .ok_or_else(|| invalid("reservoir pair has no receipt"))?,
        )?;
        let receipt = amendment_receipt_id(id);
        let family = vault
            .eval_family_of_root(&draft.plan.seat, &receipt)?
            .ok_or_else(|| {
                invalid("assign each reservoir receipt's eval family before splitting")
            })?;
        // A turn's amendments must share a family, even if their receipt ids differ.
        if let Some(proposal) = finalized_proposal_text(vault, ProposalArtifactRef::new(id))?
            && let Some(turn) = proposal.source_turn_ref
        {
            let source = format!("source_turn:{}", turn.to_hex());
            let roots = BTreeSet::from([receipt.clone(), source]);
            vault.assign_eval_family(
                &draft.plan.seat,
                &roots,
                family.purpose,
                family.assigned_at,
            )?;
        }
        let side = match family.purpose {
            FamilyPurpose::Development => SplitSide::Training,
            FamilyPurpose::SealedConfirmation if cohort.families.contains(&family.id) => {
                SplitSide::HeldOut
            }
            // Judge-audit, other sealed and retired sealed families never feed training.
            _ => continue,
        };
        let content_hash = hash_json(&(&pair["chosen"], &pair["rejected"]))?;
        let out = match side {
            SplitSide::Training => {
                train_hashes.insert(content_hash);
                &mut split.training
            }
            SplitSide::HeldOut => {
                held_hashes.insert(content_hash);
                &mut split.held_out
            }
        };
        out.extend_from_slice(line);
        out.push(b'\n');
        split.rows.push(SplitRow {
            receipt,
            family: family.id,
            content_blake3: content_hash,
            side,
        });
    }
    if split.training.is_empty() || split.held_out.is_empty() {
        return Err(invalid(
            "a training pack needs training and held-out rows in separate source families",
        ));
    }
    split.overlaps = train_hashes.intersection(&held_hashes).count() as u64;
    Ok(split)
}

impl Vault {
    /// Owner-triggered: the OF-400 exporter remains the only corpus door.
    /// Inputs are not recovered by joining a receipt to unconsented prompt text.
    pub fn prepare_training_pack(
        &self,
        owner: &AuthenticatedOwner,
        draft: &TrainingPackDraft,
        scope: ReservoirScope,
        connector: &PaidConnector,
    ) -> Result<TrainingRun> {
        self.recheck_owner(owner)?;
        draft.plan.validate()?;
        if draft.quantity == 0 || connector.connector.trim().is_empty() {
            return Err(invalid(
                "a training run needs a connector and a positive service quantity",
            ));
        }
        if draft.compute == ComputeChoice::OwnerMachines
            && (connector.locality == ModelLocality::ThirdParty || connector.payer == Payer::Host)
        {
            return Err(invalid(
                "off-owner compute needs an explicit external choice for this run",
            ));
        }
        let cohort = self
            .eval_cohorts(&draft.plan.seat)?
            .into_iter()
            .find(|row| row.id == draft.split.held_out_cohort && row.retired_at.is_none())
            .ok_or_else(|| invalid("training split needs a live sealed cohort for its seat"))?;
        let mut body = Vec::new();
        let manifest = export_reservoir(self, scope, &mut body)?;
        let split = split_bytes(self, draft, &body, &cohort)?;
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            draft.plan.starting_checkpoint.verify(self, txn)?;
            let id = self.store.clock.entity_id()?;
            let corpus = CorpusSplit {
                export_receipt: manifest.receipt,
                export: keep_bytes(self, txn, actor, id, "reservoir.jsonl", &body)?,
                training: keep_bytes(self, txn, actor, id, "training.jsonl", &split.training)?,
                held_out: keep_bytes(self, txn, actor, id, "held-out.jsonl", &split.held_out)?,
                cohort: cohort.clone(),
                rows: split.rows,
                exact_hash_overlaps: split.overlaps,
            };
            let compute = ComputePin {
                choice: draft.compute,
                connector: connector.connector.clone(),
                adapter: connector.route.adapter().to_owned(),
                origin: connector.route.origin().to_owned(),
                locality: connector.locality,
                payer: connector.payer,
                binding_blake3: hash_json(connector)?,
                quantity: draft.quantity,
                unit_cost: connector.unit_cost,
                cost_unit: connector.cost_unit.clone(),
            };
            let run = TrainingRun {
                id,
                owner: actor,
                created_at: self.store.clock.now_recorded_at(),
                spec_blake3: hash_json(&(&draft.plan, &compute, &corpus))?,
                plan: draft.plan.clone(),
                compute,
                corpus,
                state: TrainingState::Prepared,
                dispatch: None,
                result: None,
                evaluation: None,
                eval_exposure: None,
            };
            RUNS.put(&self.store, txn, &id, &run)?;
            Ok(run)
        })
    }
}
