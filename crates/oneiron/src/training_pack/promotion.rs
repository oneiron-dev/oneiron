//! Held-out scoring releases a counted cohort. Binding is a separate owner act.
//! Only a role run binds here: a question head has no role, no incumbent and
//! no manifest row, whatever the owner's choice.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::embed::{BindingSource, PendingEmbedderBinding};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::manifest::{ModelBinding, ModelManifest, ModelRole, TeacherProbeApproval};
use crate::skill_optimize::{EvalExposure, EvalExposureKind, EvalSeat};

use super::custody::read_pin;
use super::{
    HeldOutResult, PinnedCheckpoint, ROLES, RUNS, RoleSwapReceipt, SWAPS, SourcePin, SplitSide,
    SwapChoice, TrainingOwner, TrainingRun, TrainingState, hash_json, invalid, run_in_txn,
};

#[derive(Debug)]
pub struct TrainingEvalInput {
    pub exposure: EvalExposure,
    pub checkpoint: PinnedCheckpoint,
    pub harness: SourcePin,
    pub held_out_jsonl: Vec<u8>,
}

/// What a swap of one run binds against: the run's spec, exported
/// checkpoint and stored evaluation, and the role's model it replaces. An
/// approval taken under it refuses once any of them moved, so an old choice
/// never overwrites a newer one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapExpectation {
    pub spec_blake3: [u8; 32],
    /// The exported checkpoint's full load-set hash.
    pub checkpoint_blake3: [u8; 32],
    /// The stored `HeldOutResult`'s hash; an unscored run hashes its absence.
    pub evaluation_blake3: [u8; 32],
    pub incumbent: Option<ModelBinding>,
}

impl SwapExpectation {
    /// What a swap of `run` binds against while `manifest` stands.
    /// # Errors
    /// A question run, a run whose checkpoint has not returned, or a pin that
    /// does not encode.
    pub fn of(run: &TrainingRun, manifest: Option<&ModelManifest>) -> Result<Self> {
        let (role, _) = run
            .plan
            .target
            .role_binding()
            .ok_or_else(|| invalid(QUESTION_HAS_NO_ROLE))?;
        let result = run
            .result
            .as_ref()
            .ok_or_else(|| invalid("training checkpoint has not returned"))?;
        Ok(Self {
            spec_blake3: run.spec_blake3,
            checkpoint_blake3: result.exported_checkpoint.content_hash()?,
            evaluation_blake3: hash_json(&run.evaluation)?,
            incumbent: manifest
                .and_then(|manifest| manifest.roles.get(&role))
                .cloned(),
        })
    }
}

/// What the owner's direct swap door did with the result they viewed.
#[derive(Debug)]
pub enum ViewedSwap {
    /// The role binds the run's checkpoint, now or already.
    Bound(Box<RoleSwapReceipt>),
    /// The run's spec or returned checkpoint is not the one viewed; nothing
    /// changed.
    Stale,
    /// An embedder's swap stages a re-embed through a space move, so this
    /// door binds nothing.
    Embedder,
}

/// What the owner's swap choice did: bound its role, or, for a trained embedder, staged its
/// binding through a space move (O3b PR B; ARCH-0053 R13: search uses the old index meanwhile).
#[derive(Debug)]
pub enum RoleSwapOutcome {
    /// The role binds the run's checkpoint, now or already.
    Bound(Box<RoleSwapReceipt>),
    /// The embedder binding waits on its move; its receipt and `Bound` commit at that swap.
    Staged(Box<PendingEmbedderBinding>),
}

/// Why no role door binds a question head.
const QUESTION_HAS_NO_ROLE: &str = "a question head binds no role; its approval is separate";

fn role_key(role: ModelRole) -> Result<String> {
    serde_json::to_string(&role).map_err(|_| invalid("training role encoding failed"))
}

/// Binds a trained embedder's staged swap at its move's swap, in the write that applies its
/// manifest binding (O3b PR B): the receipt the owner's choice staged, the role's current
/// receipt and the run's `Bound`.
///
/// # Errors
///
/// A run that is gone, or storage errors.
pub(crate) fn bind_staged_role_swap_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &RoleSwapReceipt,
) -> Result<()> {
    let mut run = run_in_txn(vault, txn, &receipt.run)?;
    SWAPS.put(&vault.store, txn, &receipt.id, receipt)?;
    ROLES.put(&vault.store, txn, &role_key(receipt.role)?, receipt)?;
    run.state = TrainingState::Bound;
    RUNS.put(&vault.store, txn, &receipt.run, &run)
}

/// Every training run as `txn` reads it, in id order. Read-only.
pub(crate) fn training_runs_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<TrainingRun>> {
    RUNS.iter_from(&vault.store, txn, &[])?
        .map(|row| row.map(|(_, run)| run))
        .collect()
}

/// One training run as `txn` reads it. Read-only.
pub(crate) fn training_run_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<TrainingRun>> {
    RUNS.get(&vault.store, txn, id)
}

/// The receipt of the swap that last bound `role`, if any. Read-only.
pub(crate) fn role_swap_receipt_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    role: ModelRole,
) -> Result<Option<RoleSwapReceipt>> {
    ROLES.get(&vault.store, txn, &role_key(role)?)
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
            // The evaluator scores the released cases and labels (FIX 5760),
            // less a source an erase reached since (FIX 6933).
            let sources = crate::skill_optimize::union_source_rows([
                current.source_rows.take(),
                release.source_rows(),
            ]);
            current.source_rows = crate::skill_optimize::live_source_rows_in(self, txn, sources)?;
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
            // The scores are the verifier logs' (FIX 5760), less a source an
            // erase reached since (FIX 6933).
            let logs = evaluation.verifier_logs.iter().map(|log| log.artifact);
            let sources = crate::skill_optimize::union_source_rows([
                run.source_rows.take(),
                Some(logs.collect::<Vec<_>>()),
            ]);
            run.source_rows = crate::skill_optimize::live_source_rows_in(self, txn, sources)?;
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
    ) -> Result<RoleSwapOutcome> {
        self.recheck_owner(owner)?;
        self.with_write_txn_grouped(|txn| {
            self.approve_training_role_swap_in_txn(txn, owner, id, choice, teacher_approval, None)
        })
    }

    /// The owner's direct swap of the result they viewed (OF-577). In one
    /// writer the expectation is taken from the run and the manifest as they
    /// stand, the viewed spec and checkpoint must be the run's, and the swap
    /// binds against it; the run's open swap asks are cut Stale in the same
    /// commit. An explicit override is chosen only here, never asked.
    pub fn approve_viewed_training_role_swap(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        choice: SwapChoice,
        spec_blake3: &[u8; 32],
        checkpoint_blake3: &[u8; 32],
    ) -> Result<ViewedSwap> {
        self.recheck_owner(owner)?;
        self.with_write_txn_grouped(|txn| {
            let run = run_in_txn(self, txn, id)?;
            let (role, _) = run
                .plan
                .target
                .role_binding()
                .ok_or_else(|| invalid(QUESTION_HAS_NO_ROLE))?;
            if role == ModelRole::RetrievalEmbedder {
                return Ok(ViewedSwap::Embedder);
            }
            let manifest = crate::llm::manifest::read_manifest(&self.store, txn)?;
            let expected = SwapExpectation::of(&run, manifest.as_ref())?;
            if expected.spec_blake3 != *spec_blake3
                || expected.checkpoint_blake3 != *checkpoint_blake3
            {
                return Ok(ViewedSwap::Stale);
            }
            let outcome = self.approve_training_role_swap_in_txn(
                txn,
                owner,
                id,
                choice,
                None,
                Some(&expected),
            )?;
            let now = self.store.clock.now_recorded_at();
            crate::task_verb::void_training_swap_asks_in(self, txn, id, None, now)?;
            Ok(match outcome {
                RoleSwapOutcome::Bound(receipt) => ViewedSwap::Bound(receipt),
                RoleSwapOutcome::Staged(_) => ViewedSwap::Embedder,
            })
        })
    }

    /// The swap under the caller's writer: the counted Promotion exposure,
    /// the manifest, the receipt and `Bound` commit or roll back together.
    /// With `expected`, a run or role binding that moved since it was taken
    /// refuses. The same run already bound returns its receipt, serving no
    /// exposure. A trained embedder stages its binding through a space move
    /// instead (O3b PR B): the exposure counts now, and the manifest, the
    /// receipt and `Bound` commit at that move's swap; the same run staged
    /// again returns its pending binding.
    pub(crate) fn approve_training_role_swap_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        choice: SwapChoice,
        teacher_approval: Option<&TeacherProbeApproval>,
        expected: Option<&SwapExpectation>,
    ) -> Result<RoleSwapOutcome> {
        let actor = owner.revalidate_in_txn(self, txn)?;
        let mut run = run_in_txn(self, txn, id)?;
        // A question head binds no role, explicit override or not.
        let (role, binding) = run
            .plan
            .target
            .role_binding()
            .map(|(role, binding)| (role, binding.clone()))
            .ok_or_else(|| invalid(QUESTION_HAS_NO_ROLE))?;
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
        if let Some(expected) = expected
            && *expected != SwapExpectation::of(&run, Some(&manifest))?
        {
            return Err(invalid(
                "the training result or the role's model moved since this swap was asked",
            ));
        }
        let key = role_key(role)?;
        if let Some(current) = ROLES.get(&self.store, txn, &key)?
            && current.run == *id
            && manifest.roles.get(&role) == Some(&current.binding)
        {
            return Ok(RoleSwapOutcome::Bound(Box::new(current)));
        }
        if role == ModelRole::RetrievalEmbedder
            && let Some(pending) = crate::embed::live_binding_move_in(self, txn, id)?
        {
            return Ok(RoleSwapOutcome::Staged(Box::new(pending)));
        }
        let previous = manifest.roles.get(&role).cloned();
        if previous
            .as_ref()
            .is_some_and(|current| current.slot != binding.slot)
        {
            return Err(invalid(
                "a trained checkpoint cannot move its role to another slot",
            ));
        }
        let promotion_exposure = if matches!(&choice, SwapChoice::Evaluated) {
            let candidate = blake3::Hash::from(result.exported_checkpoint.content_hash()?)
                .to_hex()
                .to_string();
            Some(
                self.open_eval_cohort_in_txn(
                    txn,
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
        let receipt = RoleSwapReceipt {
            id: self.store.clock.entity_id()?,
            run: *id,
            owner: TrainingOwner::Actor(actor),
            at: self.store.clock.now_recorded_at(),
            role,
            previous,
            binding,
            checkpoint: result.exported_checkpoint.clone(),
            evaluation: run.evaluation.clone(),
            checks: result.checks.clone(),
            exact_hash_overlaps: run.corpus.exact_hash_overlaps,
            promotion_exposure,
            choice,
        };
        if role == ModelRole::RetrievalEmbedder {
            // The old index serves while the candidate space fills (ARCH-0053 R13).
            let previous = receipt.previous.clone();
            let binding = receipt.binding.clone();
            let source = BindingSource::Training {
                receipt: Box::new(receipt),
            };
            let pending =
                crate::embed::stage_embedder_binding_in_txn(self, txn, source, previous, binding)?;
            return Ok(RoleSwapOutcome::Staged(Box::new(pending)));
        }
        manifest.roles.insert(role, receipt.binding.clone());
        self.write_model_manifest_in_txn(txn, &manifest, teacher_approval, None)?;
        SWAPS.put(&self.store, txn, &receipt.id, &receipt)?;
        ROLES.put(&self.store, txn, &key, &receipt)?;
        run.state = TrainingState::Bound;
        RUNS.put(&self.store, txn, id, &run)?;
        Ok(RoleSwapOutcome::Bound(Box::new(receipt)))
    }

    /// Every swap receipt that bound `run`, oldest first.
    pub fn training_run_swap_receipts(&self, run: &EntityId) -> Result<Vec<RoleSwapReceipt>> {
        let txn = self.store.env.read_txn()?;
        let mut receipts = SWAPS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .filter(|receipt| receipt.run == *run)
            .collect::<Vec<_>>();
        receipts.sort_by_key(|receipt| (receipt.at, receipt.id));
        Ok(receipts)
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
