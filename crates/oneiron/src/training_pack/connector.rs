//! One long-running connector verb. The durable run is written before dispatch;
//! no LMDB transaction is held while the GPU runs.
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;

use serde_json::Value;

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::run_admission::{CallOutcome, PaidConnector, RunAdmission};

use super::custody::{keep_checkpoint, read_pin};
use super::{
    CheckpointUpload, ComputePin, ExportCheck, PinnedCheckpoint, ProbeMeasurement, RUNS, SourcePin,
    TrainingDispatch, TrainingPlan, TrainingResult, TrainingRun, TrainingState, hash_json, invalid,
    json_value, run_in_txn,
};

#[derive(Debug)]
pub struct TrainRequest {
    pub run: EntityId,
    pub spec_blake3: [u8; 32],
    pub plan: TrainingPlan,
    pub compute: ComputePin,
    pub training_jsonl: Vec<u8>,
    pub training_blake3: [u8; 32],
}

/// The adapter supplies measurements and returns files, not a deployed model.
#[derive(Debug)]
pub struct TrainOutput {
    pub run: EntityId,
    pub spec_blake3: [u8; 32],
    pub training_checkpoint: CheckpointUpload,
    pub exported_checkpoint: CheckpointUpload,
    pub probe_training_blake3: [u8; 32],
    pub probe_export_blake3: [u8; 32],
    pub probes: Vec<ProbeMeasurement>,
    pub settings: Value,
    pub harness: SourcePin,
    pub receipt: Value,
    pub service_units: u64,
}

pub type TrainingFuture<'a> = Pin<Box<dyn Future<Output = Result<TrainOutput>> + Send + 'a>>;

/// A host adapter may wait hours. It uses (run, spec_blake3) as the provider's
/// idempotency key and uses this admission for any teacher calls. Only training
/// rows are passed; sealed rows are not part of the connector request. The host
/// resolves starting files from their pins, never a mutable repository head.
pub trait TrainingConnector: Send + Sync {
    fn train<'a>(
        &'a self,
        request: TrainRequest,
        admission: &'a RunAdmission,
    ) -> TrainingFuture<'a>;
}

impl TrainingPlan {
    pub(super) fn validate(&self) -> Result<()> {
        self.harness.validate()?;
        let mut probes = BTreeSet::new();
        if self.purpose.trim().is_empty()
            || !self
                .settings
                .as_object()
                .is_some_and(|settings| !settings.is_empty())
            || !self.output_binding.route_models.is_empty()
            || self.probes.is_empty()
            || self
                .starting_checkpoint
                .files
                .iter()
                .any(|file| file.declared_blake3 != file.content.blake3)
            || !self.export_logit_tolerance.is_finite()
            || self.export_logit_tolerance < 0.0
            || self
                .probes
                .iter()
                .any(|probe| probe.id.trim().is_empty() || !probes.insert(&probe.id))
        {
            return Err(invalid(
                "training needs settings, purpose, a fixed probe set and a finite tolerance",
            ));
        }
        Ok(())
    }
}

fn check_export(
    run: &TrainingRun,
    output: &TrainOutput,
    training: &PinnedCheckpoint,
    exported: &PinnedCheckpoint,
) -> Result<ExportCheck> {
    let mut hash_mismatches = Vec::new();
    for (label, checkpoint) in [("training", training), ("export", exported)] {
        for file in &checkpoint.files {
            if file.declared_blake3 != file.content.blake3 {
                hash_mismatches.push(format!("{label}:{}", file.name));
            }
        }
    }
    let expected: BTreeMap<_, _> = run
        .plan
        .probes
        .iter()
        .map(|probe| Ok((probe.id.clone(), hash_json(&probe.input)?)))
        .collect::<Result<_>>()?;
    let mut actual = BTreeMap::new();
    let mut unique = true;
    let mut flips = 0;
    let mut max_difference: f64 = 0.0;
    for probe in &output.probes {
        if !probe.max_logit_difference.is_finite() || probe.max_logit_difference < 0.0 {
            return Err(invalid(
                "probe logit differences must be finite and nonnegative",
            ));
        }
        unique &= actual
            .insert(probe.probe_id.clone(), probe.input_blake3)
            .is_none();
        flips += u64::from(probe.training_argmax != probe.export_argmax);
        max_difference = max_difference.max(probe.max_logit_difference);
    }
    Ok(ExportCheck {
        hash_mismatches,
        probe_coverage_matches: unique && actual == expected,
        probe_checkpoints_match: output.probe_training_blake3 == training.content_hash()?
            && output.probe_export_blake3 == exported.content_hash()?,
        settings_match: output.settings == run.plan.settings,
        harness_matches: output.harness == run.plan.harness,
        argmax_flips: flips,
        max_logit_difference: max_difference,
        tolerance: run.plan.export_logit_tolerance,
    })
}

impl Vault {
    /// Start only after the owner's per-run compute choice. Admission reserves
    /// the declared service cost before the connector can send anything.
    pub async fn run_training_pack(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        admission: &RunAdmission,
        binding: &PaidConnector,
        connector: &dyn TrainingConnector,
    ) -> Result<TrainingRun> {
        let run = self
            .training_run(id)?
            .ok_or_else(|| invalid("training run not found"))?;
        if admission.run() != run.admission_ref()
            || !admission.declaration().is_declared()
            || run.compute.binding_blake3 != hash_json(binding)?
        {
            return Err(invalid(
                "training admission or compute binding differs from the owner-pinned run",
            ));
        }
        if let Some(teachers) = admission.declaration().teachers()
            && (teachers.target() != run.plan.output_binding.model.as_str()
                || teachers.purpose() != run.plan.purpose)
        {
            return Err(invalid(
                "training declaration target or purpose differs from the plan",
            ));
        }
        let training_jsonl = self.read_training_artifact(&run.corpus.training)?;
        let permit = admission
            .admit_paid(binding, run.compute.quantity)
            .map_err(|e| invalid(&e.to_string()))?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let mut current = run_in_txn(self, txn, id)?;
            if current.state != TrainingState::Prepared {
                return Err(invalid(
                    "a training run dispatches once; a late result uses completion",
                ));
            }
            current.plan.starting_checkpoint.verify(self, txn)?;
            current.state = TrainingState::Running;
            current.dispatch = Some(TrainingDispatch {
                declaration_revision: permit.revision(),
                budget: admission.declaration().budget().clone(),
                permit: json_value(permit.facts())?,
                dispatched: false,
            });
            RUNS.put(&self.store, txn, id, &current)
        })?;
        if let Err(error) = admission.dispatch_paid(permit.lease(), binding) {
            self.mark_training_connector_failed(id)?;
            return Err(invalid(&error.to_string()));
        }
        self.with_write_txn_grouped(|txn| {
            let mut current = run_in_txn(self, txn, id)?;
            current
                .dispatch
                .as_mut()
                .ok_or_else(|| invalid("missing training dispatch"))?
                .dispatched = true;
            RUNS.put(&self.store, txn, id, &current)
        })?;
        let request = TrainRequest {
            run: *id,
            spec_blake3: run.spec_blake3,
            plan: run.plan,
            compute: run.compute,
            training_jsonl,
            training_blake3: run.corpus.training.blake3,
        };
        let output = match connector.train(request, admission).await {
            Ok(output) => output,
            Err(error) => {
                self.mark_training_connector_failed(id)?;
                return Err(error);
            }
        };
        let settlement = permit.settle(CallOutcome::Used(output.service_units));
        // Keep completed work even when the meter reports a settlement error.
        let result = self.complete_training_pack(admission, output)?;
        settlement.map_err(|e| invalid(&e.to_string()))?;
        Ok(result)
    }

    fn mark_training_connector_failed(&self, id: &EntityId) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let mut run = run_in_txn(self, txn, id)?;
            if run.state == TrainingState::Running {
                run.state = TrainingState::ConnectorFailed;
                RUNS.put(&self.store, txn, id, &run)?;
            }
            Ok(())
        })
    }

    /// Trusted host completion door, also for a delayed callback after the
    /// original waiter was lost. No second dispatch or role write happens here.
    pub fn complete_training_pack(
        &self,
        admission: &RunAdmission,
        output: TrainOutput,
    ) -> Result<TrainingRun> {
        let teachers = json_value(&admission.teacher_report())?;
        self.with_write_txn_grouped(|txn| {
            let mut run = run_in_txn(self, txn, &output.run)?;
            if admission.run() != run.admission_ref()
                || output.spec_blake3 != run.spec_blake3
                || !run
                    .dispatch
                    .as_ref()
                    .is_some_and(|dispatch| dispatch.dispatched)
                || output.training_checkpoint.model != run.plan.output_binding.model
                || output.exported_checkpoint.model != run.plan.output_binding.model
                || !output
                    .receipt
                    .as_object()
                    .is_some_and(|receipt| !receipt.is_empty())
            {
                return Err(invalid(
                    "training result does not match its dispatched spec",
                ));
            }
            if let Some(result) = &run.result {
                if result.training_checkpoint.content_hash()?
                    != output.training_checkpoint.content_hash()?
                    || result.exported_checkpoint.content_hash()?
                        != output.exported_checkpoint.content_hash()?
                    || result.probes != output.probes
                    || result.service_units != output.service_units
                    || result.settings != output.settings
                    || result.harness != output.harness
                    || result.connector_receipt != output.receipt
                {
                    return Err(invalid("a completed training run cannot be replaced"));
                }
                return Ok(run);
            }
            let training =
                keep_checkpoint(self, txn, run.owner, run.id, &output.training_checkpoint)?;
            let exported =
                keep_checkpoint(self, txn, run.owner, run.id, &output.exported_checkpoint)?;
            // Re-read stored files before accepting custody; producer hash mismatches
            // remain on the failed check, rather than dropping the evidence.
            for file in training.files.iter().chain(&exported.files) {
                read_pin(self, txn, &file.content)?;
            }
            let checks = check_export(&run, &output, &training, &exported)?;
            run.result = Some(TrainingResult {
                training_checkpoint: training,
                exported_checkpoint: exported,
                probes: output.probes,
                checks,
                connector_receipt: output.receipt,
                settings: output.settings,
                harness: output.harness,
                teachers,
                service_units: output.service_units,
            });
            run.state = TrainingState::Returned;
            RUNS.put(&self.store, txn, &run.id, &run)?;
            Ok(run)
        })
    }
}
