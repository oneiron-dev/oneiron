//! A drafter version's training job (FIX 14974, FIX 12569 slice 3): the
//! engine's side of the host that trains a `prepared` version.
//!
//! The night ([`super::nightly`]) prepares a version and hands it to the
//! host as a [`DrafterTrainingJob`] when a trainer connector on the host
//! lists the recipe's trainer family. The host then:
//! - admits the recipe's GPU seconds under its connector's quote and moves
//!   the version to `training` in one write ([`Vault::begin_drafter_training`]):
//!   the version must still be prepared at the generation the night wrote,
//!   the policy on with the same recipe, and no other version of the target
//!   training. The generation bumps, and the completion names the new one;
//! - asks [`Vault::drafter_training_watch`] while the trainer runs, and stops
//!   the trainer when an erase, the off switch or another recipe lands;
//! - on a receipt that verifies, records its measurements
//!   ([`Vault::record_drafter_training_receipt`]) and seals the output
//!   through `begin_drafter_artifact`, `DrafterSealing::seal_file` and
//!   `publish_drafter_artifact`, which check the generation again, so an
//!   erase during training refuses the publication and retires its key;
//! - otherwise records why ([`Vault::fail_drafter_training`]): the version
//!   is `rejected` and every key it holds retires.
//!
//! The trainer gets the training side of the corpus only
//! ([`Vault::drafter_training_corpus`]) and, for a version continued from a
//! kept one, that version's trainable files
//! ([`Vault::materialize_drafter_parent`]). It sets no binding, picks no
//! held-out example and never sees one.

use heed::{RoTxn, RwTxn};

use super::{
    DrafterArtifactFile, DrafterCorpusFile, DrafterHoldReason, DrafterRecipe,
    DrafterRetrainOutcome, DrafterServing, DrafterTarget, DrafterTraining, DrafterTrainingFailure,
    DrafterVersion, DrafterVersionState, VERSIONS, ancestry_names_world, invalid, policy_in_txn,
    versions_by_id,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::dreamer_runner::maintenance::coach::COACH_DRAFTER_RETRAIN_FACET;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::drafter_custody::retire_drafter_artifact_keys_in_txn;

/// What a trained version's load set names its trainable state with: the
/// files a version continued from it trains from. The serving runtime loads
/// none of them.
pub const DRAFTER_TRAINABLE_PREFIX: &str = "trainable-";

/// A kept version's trainable files, as a continued version's job names
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrafterParentLoadSet {
    pub version: EntityId,
    /// The parent's sealed artifact's random id.
    pub artifact: [u8; 16],
    /// Its files whose names open with [`DRAFTER_TRAINABLE_PREFIX`].
    pub files: Vec<DrafterArtifactFile>,
}

/// One version as its trainer host reads it: what to train, from what, on
/// which corpus pin, and where its job stands. Ids, pins and counts only.
#[derive(Debug, Clone, PartialEq)]
pub struct DrafterTrainingJob {
    pub version: EntityId,
    /// The night that prepared it.
    pub attempt: Option<AttemptId>,
    pub state: DrafterVersionState,
    pub generation: u64,
    pub target: DrafterTarget,
    pub parent: DrafterServing,
    pub recipe: DrafterRecipe,
    pub spec_blake3: [u8; 32],
    /// The form every corpus example takes.
    pub corpus_form: String,
    /// The training side's pin: its examples, length and BLAKE3.
    pub training_corpus: DrafterCorpusFile,
    /// The records the version's own corpus holds: what the run admission
    /// names as the call's sources.
    pub sources: Vec<EntityId>,
    pub training: Option<DrafterTraining>,
    /// The parent's trainable files; `None` for stock, and for a parent
    /// that keeps no artifact.
    pub parent_load_set: Option<DrafterParentLoadSet>,
}

/// The connector and quote a dispatch runs under, as the host resolved
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrafterTrainingDispatch {
    pub connector: String,
    pub connector_revision: Option<String>,
    pub quoted_units: u64,
    pub unit_cost: u64,
    pub cost_unit: String,
}

/// One version's place in its night, for the host's recovery pass: its id,
/// the night that prepared it, its state and its generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrafterTrainingMark {
    pub version: EntityId,
    pub attempt: Option<AttemptId>,
    pub state: DrafterVersionState,
    pub generation: u64,
}

/// `row`'s job, read with `versions` for its parent; `None` for a version
/// that keeps no corpus or spec.
pub(super) fn job_of(
    versions: &std::collections::BTreeMap<EntityId, DrafterVersion>,
    row: &DrafterVersion,
) -> Option<DrafterTrainingJob> {
    let corpus = row.corpus.as_ref()?;
    let spec_blake3 = row.spec_blake3?;
    let parent_load_set = row.parent.version().and_then(|parent| {
        let artifact = versions.get(&parent)?.artifact.as_ref()?;
        Some(DrafterParentLoadSet {
            version: parent,
            artifact: artifact.id,
            files: artifact
                .files
                .iter()
                .filter(|file| file.name.starts_with(DRAFTER_TRAINABLE_PREFIX))
                .cloned()
                .collect(),
        })
    });
    Some(DrafterTrainingJob {
        version: row.id,
        attempt: row.job,
        state: row.state,
        generation: row.generation,
        target: row.target.clone(),
        parent: row.parent,
        recipe: row.recipe.clone(),
        spec_blake3,
        corpus_form: corpus.form.clone(),
        training_corpus: corpus.training.clone(),
        sources: row.dependencies.sources.clone(),
        training: row.training.clone(),
        parent_load_set,
    })
}

/// Whether a version of `target` other than `except` trains in `txn`.
pub(super) fn target_training_in(
    store: &Store,
    txn: &RoTxn<'_>,
    target: &DrafterTarget,
    except: Option<EntityId>,
) -> Result<bool> {
    Ok(versions_by_id(store, txn)?.values().any(|row| {
        row.state == DrafterVersionState::Training
            && row.target == *target
            && Some(row.id) != except
    }))
}

/// How the night that prepared `row` ended, when its training did: trained
/// once its load set is published, failed with the job's reason once it was
/// rejected or erased; `None` while it is prepared or trains.
pub(super) fn night_outcome_of(row: &DrafterVersion) -> Option<DrafterRetrainOutcome> {
    let failed = |reason| DrafterRetrainOutcome::Failed {
        version: row.id,
        reason,
    };
    match row.state {
        DrafterVersionState::Prepared | DrafterVersionState::Training => None,
        DrafterVersionState::Returned | DrafterVersionState::Qualified => {
            Some(DrafterRetrainOutcome::Trained { version: row.id })
        }
        DrafterVersionState::Rejected => Some(failed(
            row.training
                .as_ref()
                .and_then(|training| training.failure)
                .unwrap_or(DrafterTrainingFailure::Refused),
        )),
        DrafterVersionState::Erased => Some(failed(DrafterTrainingFailure::Erased)),
    }
}

/// The version night `attempt` prepared, in `txn`: the newest when several
/// name it.
pub(super) fn version_of_night_in(
    store: &Store,
    txn: &RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<DrafterVersion>> {
    Ok(versions_by_id(store, txn)?
        .into_values()
        .filter(|row| row.job == Some(attempt))
        .max_by_key(|row| row.id))
}

/// Rejects `row`, a version that never trained or whose job ended without
/// a trained head, in `txn`: every key it holds retires and its generation
/// bumps, which fences any completion still out.
fn reject_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    mut row: DrafterVersion,
    at: u64,
) -> Result<DrafterVersion> {
    retire_drafter_artifact_keys_in_txn(store, txn, &row.id)?;
    row.state = DrafterVersionState::Rejected;
    row.generation += 1;
    row.updated_at = at;
    VERSIONS.put(store, txn, &row.id, &row)?;
    Ok(row)
}

/// `row`, still training at `generation`; otherwise `None`.
fn training_at(row: Option<DrafterVersion>, generation: u64) -> Option<DrafterVersion> {
    row.filter(|row| row.state == DrafterVersionState::Training && row.generation == generation)
}

impl Vault {
    /// The training job of version `version`, as its host reads it; `None`
    /// for an unknown version or one that keeps no corpus.
    ///
    /// # Errors
    /// Storage faults.
    pub fn drafter_training_job(&self, version: &EntityId) -> Result<Option<DrafterTrainingJob>> {
        let txn = self.store.env.read_txn()?;
        let versions = versions_by_id(&self.store, &txn)?;
        Ok(versions.get(version).and_then(|row| job_of(&versions, row)))
    }

    /// Every version a night prepared, with where it stands: the host's
    /// recovery pass finds a job a restart left training, and a night still
    /// parked on a job that ended.
    ///
    /// # Errors
    /// Storage faults.
    pub fn drafter_training_marks(&self) -> Result<Vec<DrafterTrainingMark>> {
        let txn = self.store.env.read_txn()?;
        Ok(versions_by_id(&self.store, &txn)?
            .into_values()
            .filter(|row| row.job.is_some())
            .map(|row| DrafterTrainingMark {
                version: row.id,
                attempt: row.job,
                state: row.state,
                generation: row.generation,
            })
            .collect())
    }

    /// The host's door to dispatch version `version`'s training, once its
    /// run admission is in hand: in one write the version must still be
    /// prepared at `expected_generation`, the policy on with the version's
    /// recipe, and no other version of its target training. Then it is
    /// `training`, its generation bumps and its job record names `dispatch`.
    /// Returns the new generation, which the completion names.
    ///
    /// # Errors
    /// An unknown version, any check above that fails, and storage faults.
    pub fn begin_drafter_training(
        &self,
        version: &EntityId,
        expected_generation: u64,
        dispatch: DrafterTrainingDispatch,
    ) -> Result<u64> {
        self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            let mut row = VERSIONS
                .get(store, txn, version)?
                .ok_or(Error::EntityNotFound)?;
            if row.state != DrafterVersionState::Prepared || row.generation != expected_generation {
                return Err(invalid(
                    "the drafter version is no longer prepared at the generation its night wrote",
                ));
            }
            let policy = policy_in_txn(store, txn)?;
            if !policy.enabled || policy.recipe.as_ref() != Some(&row.recipe) {
                return Err(invalid(
                    "the drafter policy moved since the version was prepared",
                ));
            }
            // A world the owner excluded since the night prepared it fences
            // the version, its ancestry included: its corpus never reaches
            // a trainer.
            if ancestry_names_world(&versions_by_id(store, txn)?, &row, &policy.excluded_worlds) {
                return Err(invalid(
                    "the drafter version read a world the policy now excludes",
                ));
            }
            if target_training_in(store, txn, &row.target, Some(row.id))? {
                return Err(invalid("another version of the drafter target trains"));
            }
            let at = self.now_recorded_at();
            row.state = DrafterVersionState::Training;
            row.generation += 1;
            row.training = Some(DrafterTraining {
                connector: dispatch.connector,
                connector_revision: dispatch.connector_revision,
                quoted_units: dispatch.quoted_units,
                unit_cost: dispatch.unit_cost,
                cost_unit: dispatch.cost_unit,
                generation: row.generation,
                dispatched_at: at,
                gpu_seconds: None,
                receipt_blake3: None,
                finished_at: None,
                failure: None,
            });
            row.updated_at = at;
            VERSIONS.put(store, txn, version, &row)?;
            Ok(row.generation)
        })
    }

    /// Whether version `version`'s trainer, dispatched at `generation`, may
    /// go on: `None` while it may; otherwise why the host stops it. An
    /// erase reached it (`erased`), or it is no longer training at that
    /// generation, the policy is off, its recipe is no longer the version's,
    /// or the policy now excludes a world it or its ancestry read
    /// (`cancelled`).
    ///
    /// # Errors
    /// Storage faults.
    pub fn drafter_training_watch(
        &self,
        version: &EntityId,
        generation: u64,
    ) -> Result<Option<DrafterTrainingFailure>> {
        let txn = self.store.env.read_txn()?;
        let Some(row) = VERSIONS.get(&self.store, &txn, version)? else {
            return Ok(Some(DrafterTrainingFailure::Erased));
        };
        if row.state == DrafterVersionState::Erased {
            return Ok(Some(DrafterTrainingFailure::Erased));
        }
        if row.state != DrafterVersionState::Training || row.generation != generation {
            return Ok(Some(DrafterTrainingFailure::Cancelled));
        }
        let policy = policy_in_txn(&self.store, &txn)?;
        if !policy.enabled || policy.recipe.as_ref() != Some(&row.recipe) {
            return Ok(Some(DrafterTrainingFailure::Cancelled));
        }
        if ancestry_names_world(
            &versions_by_id(&self.store, &txn)?,
            &row,
            &policy.excluded_worlds,
        ) {
            return Ok(Some(DrafterTrainingFailure::Cancelled));
        }
        Ok(None)
    }

    /// The host's door to record the trainer's receipt of version
    /// `version`, dispatched at `generation`, before its load set is sealed:
    /// the receipt's BLAKE3 and the GPU wall seconds it measured, in one
    /// write that leaves the generation as it is. `false` when the version
    /// is no longer training at that generation.
    ///
    /// # Errors
    /// Storage faults.
    pub fn record_drafter_training_receipt(
        &self,
        version: &EntityId,
        generation: u64,
        receipt_blake3: [u8; 32],
        gpu_seconds: u64,
    ) -> Result<bool> {
        self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            let Some(mut row) = training_at(VERSIONS.get(store, txn, version)?, generation) else {
                return Ok(false);
            };
            let at = self.now_recorded_at();
            if let Some(training) = row.training.as_mut() {
                training.receipt_blake3 = Some(receipt_blake3);
                training.gpu_seconds = Some(gpu_seconds);
                training.finished_at = Some(at);
            }
            row.updated_at = at;
            VERSIONS.put(store, txn, version, &row)?;
            Ok(true)
        })
    }

    /// The host's door to end version `version`'s training, dispatched at
    /// `generation`, without a trained head: in one write, a version still
    /// training at that generation is `rejected` with `failure` and the
    /// receipt's measurements where there was one, its generation bumps and
    /// every key it holds retires. `false` when the version is no longer
    /// training at that generation: an erase or another write took it first.
    ///
    /// # Errors
    /// Storage and custody faults.
    pub fn fail_drafter_training(
        &self,
        version: &EntityId,
        generation: u64,
        failure: DrafterTrainingFailure,
        receipt: Option<([u8; 32], Option<u64>)>,
    ) -> Result<bool> {
        self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            let Some(mut row) = training_at(VERSIONS.get(store, txn, version)?, generation) else {
                return Ok(false);
            };
            let at = self.now_recorded_at();
            if let Some(training) = row.training.as_mut() {
                training.failure = Some(failure);
                training.finished_at = Some(at);
                if let Some((blake3, gpu_seconds)) = receipt {
                    training.receipt_blake3 = Some(blake3);
                    training.gpu_seconds = gpu_seconds;
                }
            }
            reject_in_txn(store, txn, row, at)?;
            Ok(true)
        })
    }

    /// The host's door to end night `attempt` without training the version
    /// it prepared, for `reason`: in one write, a version still prepared is
    /// `rejected` (its corpus keys retire) and the night's one retrain event
    /// records `held` with that reason. A version whose job already ended
    /// records how it ended instead. The same attempt again returns the
    /// outcome it recorded.
    ///
    /// # Errors
    /// An attempt that is not this facet's under the Coach's stamp, a
    /// version that still trains, and storage and custody faults.
    pub fn hold_drafter_night(
        &self,
        attempt: &DreamerAdmittedAttempt,
        reason: DrafterHoldReason,
    ) -> Result<DrafterRetrainOutcome> {
        self.require_coach_attempt(attempt, COACH_DRAFTER_RETRAIN_FACET)?;
        let attempt_id = attempt.status.attempt.id;
        self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            if let Some(outcome) = super::nightly::recorded_outcome_in(store, txn, attempt_id)? {
                return Ok(outcome);
            }
            let at = self.now_recorded_at();
            let row = version_of_night_in(store, txn, attempt_id)?;
            let (outcome, revision, cutoff) = match row {
                Some(row) if row.state == DrafterVersionState::Training => {
                    return Err(invalid(
                        "the night's drafter version trains: a hold does not end it",
                    ));
                }
                Some(row) if row.state == DrafterVersionState::Prepared => {
                    let row = reject_in_txn(store, txn, row, at)?;
                    (
                        DrafterRetrainOutcome::Held { reason },
                        row.policy_revision,
                        row.cutoff,
                    )
                }
                Some(row) => (
                    night_outcome_of(&row).unwrap_or(DrafterRetrainOutcome::Held { reason }),
                    row.policy_revision,
                    row.cutoff,
                ),
                None => (
                    DrafterRetrainOutcome::Held { reason },
                    policy_in_txn(store, txn)?.revision,
                    at,
                ),
            };
            super::nightly::record_retrain_in(
                store, txn, attempt_id, revision, cutoff, outcome, at,
            )?;
            Ok(outcome)
        })
    }

    /// Opens `job`'s parent's trainable files into the new private
    /// directory `dir`, each file's length and BLAKE3 checked as it is
    /// opened, for the trainer of a version continued from a kept one. On
    /// any failure nothing stays in `dir`.
    ///
    /// # Errors
    /// A job continued from stock, a parent that keeps no trainable file,
    /// whose key is retired or whose artifact moved, a damaged file, and
    /// custody and I/O faults.
    pub fn materialize_drafter_parent(
        &self,
        job: &DrafterTrainingJob,
        dir: &std::path::Path,
    ) -> Result<Vec<DrafterArtifactFile>> {
        let parent = job
            .parent_load_set
            .as_ref()
            .filter(|parent| !parent.files.is_empty())
            .ok_or_else(|| invalid("the drafter version's parent keeps no trainable file"))?;
        let sealing = self
            .drafter_artifact_sealing(&parent.version)?
            .ok_or_else(|| invalid("the parent drafter's artifact key is no longer live"))?;
        if sealing.artifact() != parent.artifact {
            return Err(invalid("the parent drafter's artifact moved"));
        }
        self.open_drafter_load_set(&sealing, &parent.files, dir)?;
        Ok(parent.files.clone())
    }
}
