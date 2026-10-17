//! Held-out scoring releases a counted cohort. Binding is a separate owner act.
use std::collections::BTreeSet;

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::manifest::{ModelRole, TeacherProbeApproval};
use crate::skill_optimize::{EvalExposure, EvalExposureKind, EvalSeat};

use super::custody::read_pin;
use super::{
    HeldOutResult, PinnedCheckpoint, ROLES, RUNS, RoleSwapReceipt, SWAPS, SourcePin, SplitSide,
    SwapChoice, TrainingRun, TrainingState, invalid, run_in_txn,
};

#[derive(Debug)]
pub struct TrainingEvalInput {
    pub exposure: EvalExposure,
    pub checkpoint: PinnedCheckpoint,
    pub harness: SourcePin,
    pub held_out_jsonl: Vec<u8>,
}

fn role_key(role: ModelRole) -> Result<String> {
    serde_json::to_string(&role).map_err(|_| invalid("training role encoding failed"))
}

fn validate_eval(run: &TrainingRun, eval: &HeldOutResult) -> Result<()> {
    let result = run
        .result
        .as_ref()
        .ok_or_else(|| invalid("training checkpoint has not returned"))?;
    let cases = run
        .corpus
        .rows
        .iter()
        .filter(|row| row.side == SplitSide::HeldOut)
        .count() as u64;
    if eval.checkpoint_blake3 != result.exported_checkpoint.content_hash()?
        || eval.held_out_blake3 != run.corpus.held_out.blake3
        || !run
            .eval_exposure
            .as_ref()
            .is_some_and(|exposure| exposure.id == eval.exposure)
        || eval.cases != cases
        || cases == 0
        || eval.metrics.is_empty()
        || eval
            .metrics
            .iter()
            .any(|(name, value)| name.trim().is_empty() || !value.is_finite())
        || eval.verifier_logs.is_empty()
    {
        return Err(invalid(
            "held-out result needs the exact checkpoint, split, exposure, metrics and verifier logs",
        ));
    }
    eval.harness.validate()?;
    if matches!(
        run.plan.seat,
        EvalSeat::Decision | EvalSeat::ExtractionTagger | EvalSeat::Router
    ) && eval.calibration.is_none()
    {
        return Err(invalid("a probability seat also reports calibration"));
    }
    if let Some(calibration) = &eval.calibration
        && (!calibration.temperature.is_finite()
            || calibration.temperature <= 0.0
            || !calibration.brier_score.is_finite()
            || calibration.brier_score < 0.0
            || !calibration.calibration_error.is_finite()
            || !(0.0..=1.0).contains(&calibration.calibration_error))
    {
        return Err(invalid("invalid training calibration report"));
    }
    Ok(())
}

impl Vault {
    /// The evaluator, not the trainer, gets these bytes after a counted OF-578
    /// serving. The run keeps the exposure so a result cannot name another one.
    pub fn open_training_held_out(&self, id: &EntityId) -> Result<TrainingEvalInput> {
        let run = self
            .training_run(id)?
            .ok_or_else(|| invalid("training run not found"))?;
        let result = run
            .result
            .as_ref()
            .ok_or_else(|| invalid("training checkpoint has not returned"))?;
        if run.evaluation.is_some() || run.state != TrainingState::Returned {
            return Err(invalid(
                "held-out scoring requires an unscored returned checkpoint",
            ));
        }
        let candidate = blake3::Hash::from(result.exported_checkpoint.content_hash()?)
            .to_hex()
            .to_string();
        let release = self.open_eval_cohort(
            &run.corpus.cohort.id,
            EvalExposureKind::Candidate,
            &run.admission_ref(),
            Some(&candidate),
            self.store.clock.now_recorded_at(),
        )?;
        let receipts: BTreeSet<_> = release
            .cases
            .iter()
            .flat_map(|case| case.receipts.iter().map(String::as_str))
            .collect();
        if run
            .corpus
            .rows
            .iter()
            .any(|row| row.side == SplitSide::HeldOut && !receipts.contains(row.receipt.as_str()))
        {
            return Err(invalid(
                "training held-out rows must be cases in the sealed cohort",
            ));
        }
        let held_out_jsonl = self.read_training_artifact(&run.corpus.held_out)?;
        self.with_write_txn_grouped(|txn| {
            let mut current = run_in_txn(self, txn, id)?;
            if current.state != TrainingState::Returned || current.evaluation.is_some() {
                return Err(invalid("training run was scored while opening its cohort"));
            }
            current.eval_exposure = Some(release.exposure.clone());
            RUNS.put(&self.store, txn, id, &current)
        })?;
        Ok(TrainingEvalInput {
            exposure: release.exposure,
            checkpoint: result.exported_checkpoint.clone(),
            harness: run.plan.harness,
            held_out_jsonl,
        })
    }

    /// A trusted evaluator supplies measurements, not an instruction to deploy.
    /// A different harness is retained on the result and blocks a normal proposal.
    pub fn record_training_evaluation(
        &self,
        id: &EntityId,
        evaluation: &HeldOutResult,
    ) -> Result<TrainingRun> {
        self.with_write_txn_grouped(|txn| {
            let mut run = run_in_txn(self, txn, id)?;
            if let Some(existing) = &run.evaluation {
                if existing == evaluation {
                    return Ok(run);
                }
                return Err(invalid("a training evaluation is immutable"));
            }
            if run.state != TrainingState::Returned {
                return Err(invalid(
                    "training evaluation requires a returned checkpoint",
                ));
            }
            validate_eval(&run, evaluation)?;
            for log in &evaluation.verifier_logs {
                read_pin(self, txn, log)?;
            }
            run.evaluation = Some(evaluation.clone());
            run.state = TrainingState::Scored;
            RUNS.put(&self.store, txn, id, &run)?;
            Ok(run)
        })
    }

    /// No connector, completion or evaluation calls this door. The owner is
    /// revalidated in the transaction that writes both manifest and swap receipt.
    pub fn approve_training_role_swap(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        choice: SwapChoice,
        teacher_approval: Option<&TeacherProbeApproval>,
    ) -> Result<RoleSwapReceipt> {
        self.recheck_owner(owner)?;
        let promotion_exposure = if matches!(&choice, SwapChoice::Evaluated) {
            let run = self
                .training_run(id)?
                .ok_or_else(|| invalid("training run not found"))?;
            if !run.can_propose_swap() {
                return Err(invalid("training checks block a swap proposal"));
            }
            let result = run
                .result
                .as_ref()
                .ok_or_else(|| invalid("training checkpoint has not returned"))?;
            let candidate = blake3::Hash::from(result.exported_checkpoint.content_hash()?)
                .to_hex()
                .to_string();
            Some(
                self.open_eval_cohort(
                    &run.corpus.cohort.id,
                    EvalExposureKind::Promotion,
                    &run.admission_ref(),
                    Some(&candidate),
                    self.store.clock.now_recorded_at(),
                )?
                .exposure,
            )
        } else {
            None
        };
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let mut run = run_in_txn(self, txn, id)?;
            match &choice {
                SwapChoice::Evaluated if !run.can_propose_swap() => {
                    return Err(invalid(
                        "training export, overlap or held-out checks block a swap proposal",
                    ));
                }
                SwapChoice::ExplicitOverride { reason } if reason.trim().is_empty() => {
                    return Err(invalid(
                        "an explicit checkpoint choice records the owner's reason",
                    ));
                }
                _ => {}
            }
            let result = run
                .result
                .as_ref()
                .ok_or_else(|| invalid("training checkpoint has not returned"))?;
            result.exported_checkpoint.verify(self, txn)?;
            let mut manifest =
                crate::llm::manifest::read_manifest(&self.store, txn)?.ok_or_else(|| {
                    invalid("configure the model manifest before binding a trained checkpoint")
                })?;
            let role = run.plan.role;
            let key = role_key(role)?;
            if let Some(current) = ROLES.get(&self.store, txn, &key)?
                && current.run == *id
                && manifest.roles.get(&role) == Some(&current.binding)
            {
                return Ok(current);
            }
            let previous = manifest.roles.get(&role).cloned();
            if previous
                .as_ref()
                .is_some_and(|binding| binding.slot != run.plan.output_binding.slot)
            {
                return Err(invalid(
                    "a trained checkpoint cannot move its role to another slot",
                ));
            }
            manifest.roles.insert(role, run.plan.output_binding.clone());
            self.write_model_manifest_in_txn(txn, &manifest, teacher_approval, None)?;
            let receipt = RoleSwapReceipt {
                id: self.store.clock.entity_id()?,
                run: *id,
                owner: actor,
                at: self.store.clock.now_recorded_at(),
                role,
                previous,
                binding: run.plan.output_binding.clone(),
                checkpoint: result.exported_checkpoint.clone(),
                evaluation: run.evaluation.clone(),
                checks: result.checks.clone(),
                exact_hash_overlaps: run.corpus.exact_hash_overlaps,
                promotion_exposure: promotion_exposure.clone(),
                choice,
            };
            SWAPS.put(&self.store, txn, &receipt.id, &receipt)?;
            ROLES.put(&self.store, txn, &key, &receipt)?;
            run.state = TrainingState::Bound;
            RUNS.put(&self.store, txn, id, &run)?;
            Ok(receipt)
        })
    }

    /// Host loader seam. An unrelated manifest edit makes the old custody
    /// binding inapplicable; it never silently loads an earlier checkpoint.
    pub fn training_role_checkpoint(&self, role: ModelRole) -> Result<Option<PinnedCheckpoint>> {
        let txn = self.store.env.read_txn()?;
        let Some(receipt) = ROLES.get(&self.store, &txn, &role_key(role)?)? else {
            return Ok(None);
        };
        let manifest = crate::llm::manifest::read_manifest(&self.store, &txn)?;
        if manifest
            .as_ref()
            .and_then(|manifest| manifest.roles.get(&role))
            != Some(&receipt.binding)
        {
            return Ok(None);
        }
        receipt.checkpoint.verify(self, &txn)?;
        Ok(Some(receipt.checkpoint))
    }
}
