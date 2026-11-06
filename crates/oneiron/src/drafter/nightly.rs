//! The nightly drafter retrain, `coach.drafter_retrain` (FIX 12569,
//! I5-DRAFTER = A): Coach-owned work on the shared night scheduler.
//!
//! Its prepare step (FIX 14973): with the policy on, a recipe chosen that a
//! trainer connector of the host lists, and a target the host serves a
//! drafter for, the night exports the vault's corpus for that target
//! ([`super::corpus`]). Then, in one write, it checks the policy again and
//! every record the corpus read, splits the corpus, supersedes the target's
//! earlier version still prepared (it never trained: `rejected`, its corpus
//! keys retired), mints the two corpus keys and writes a `DrafterVersion` in
//! state `prepared` with its corpus and its dependency set, the parent's
//! whole ancestry included. Once that write commits, the two sides are
//! sealed and written.
//!
//! Its train step (FIX 14974): the prepared version goes to the host
//! ([`DrafterNightStep::Train`]), which trains it ([`super::training`]) and
//! parks the night meanwhile, so the night's root stays open while the GPU
//! works. Once the job ends the host resumes the night, and the same attempt
//! records how it ended: `trained`, naming the version, or `failed` with the
//! job's reason.
//!
//! A night that trains nothing records one retrain event and says why:
//! `skipped` (`policy_off`) or `held` (`no_trainer_recipe`,
//! `no_drafter_target`, `training_in_progress`, `policy_moved`,
//! `empty_corpus`, and from the host `no_admission` or `corpus_missing`).
//! A night never reports a successful empty retrain. The same attempt again
//! returns the outcome it recorded and writes nothing.

use heed::{RoTxn, RwTxn};

use super::corpus::{
    CorpusSide, CorpusSideToSeal, DRAFTER_CORPUS_FORM, DrafterExport, live_examples_in,
    mint_side_in, split_examples, union_dependencies,
};
use super::training::{
    DrafterTrainingJob, night_outcome_of, target_training_in, version_of_night_in,
};
use super::{
    BINDINGS, DrafterActor, DrafterCorpus, DrafterEventKind, DrafterHoldReason, DrafterPolicy,
    DrafterRecipe, DrafterRetrainOutcome, DrafterServing, DrafterSkipReason, DrafterTarget,
    DrafterVersion, DrafterVersionState, EVENTS, VERSIONS, ancestry, hash_json, policy_in_txn,
    record_event_in_txn, versions_by_id,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::dreamer_runner::maintenance::coach::COACH_DRAFTER_RETRAIN_FACET;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::drafter_custody::retire_drafter_artifact_keys_in_txn;

/// What one night's step leaves its host.
#[derive(Debug, Clone, PartialEq)]
pub enum DrafterNightStep {
    /// The night ended with this outcome, its one retrain event recorded.
    Ended(DrafterRetrainOutcome),
    /// The night prepared this version, or dispatched it before: the host
    /// trains it, or recovers its job, and the night stays open until the
    /// job ends.
    Train(Box<DrafterTrainingJob>),
}

/// What one night's write decided: its outcome when it ended, and the
/// version whose corpus it prepared with that corpus's two sides, waiting
/// to be sealed.
struct PreparedNight {
    outcome: Option<DrafterRetrainOutcome>,
    corpus: Option<(EntityId, Vec<CorpusSideToSeal>)>,
}

impl PreparedNight {
    fn ended(outcome: DrafterRetrainOutcome) -> Self {
        Self {
            outcome: Some(outcome),
            corpus: None,
        }
    }
}

/// The outcome attempt `attempt` recorded in `txn`, if it ran already. A row
/// that does not decode is no record of this attempt.
pub(super) fn recorded_outcome_in(
    store: &Store,
    txn: &RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<DrafterRetrainOutcome>> {
    for row in EVENTS.iter_raw_from(store, txn, &[])? {
        let (_, value) = row?;
        if let Ok(event) = EVENTS.decode_value(&value)
            && let DrafterEventKind::Retrain {
                attempt: recorded,
                outcome,
                ..
            } = event.kind
            && recorded == attempt
        {
            return Ok(Some(outcome));
        }
    }
    Ok(None)
}

/// Records the night's one retrain event in `txn`, at `at`.
pub(super) fn record_retrain_in(
    store: &Store,
    txn: &mut RwTxn<'_>,
    attempt: AttemptId,
    policy_revision: u64,
    cutoff: u64,
    outcome: DrafterRetrainOutcome,
    at: u64,
) -> Result<()> {
    record_event_in_txn(
        store,
        txn,
        DrafterActor::Coach,
        DrafterEventKind::Retrain {
            attempt,
            policy_revision,
            cutoff,
            outcome,
        },
        None,
        at,
    )?;
    Ok(())
}

/// Why a night under `policy` trains nothing before any export, for
/// `target` in `txn`; `None` when it may prepare a version. `trains` says
/// whether a trainer connector of the host lists a recipe's family.
fn unplanned_in(
    store: &Store,
    txn: &RoTxn<'_>,
    policy: &DrafterPolicy,
    target: Option<&DrafterTarget>,
    trains: &dyn Fn(&DrafterRecipe) -> bool,
) -> Result<Option<DrafterRetrainOutcome>> {
    let held = |reason| Some(DrafterRetrainOutcome::Held { reason });
    if !policy.enabled {
        return Ok(Some(DrafterRetrainOutcome::Skipped {
            reason: DrafterSkipReason::PolicyOff,
        }));
    }
    if !policy.recipe.as_ref().is_some_and(|recipe| trains(recipe)) {
        return Ok(held(DrafterHoldReason::NoTrainerRecipe));
    }
    let Some(target) = target else {
        return Ok(held(DrafterHoldReason::NoDrafterTarget));
    };
    if target_training_in(store, txn, target, None)? {
        return Ok(held(DrafterHoldReason::TrainingInProgress));
    }
    Ok(None)
}

/// Where the version a night prepared stands for that night.
enum NightVersion {
    /// It is prepared or trains: the host trains it or recovers its job.
    Train(Box<DrafterTrainingJob>),
    /// Its job ended, or it keeps no corpus to train on.
    Ended,
}

/// Where the version night `attempt` prepared stands, in `txn`; `None` when
/// the night prepared none.
fn night_version_in(
    store: &Store,
    txn: &RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<NightVersion>> {
    let Some(row) = version_of_night_in(store, txn, attempt)? else {
        return Ok(None);
    };
    if night_outcome_of(&row).is_some() {
        return Ok(Some(NightVersion::Ended));
    }
    let versions = versions_by_id(store, txn)?;
    Ok(Some(match super::training::job_of(&versions, &row) {
        Some(job) => NightVersion::Train(Box::new(job)),
        None => NightVersion::Ended,
    }))
}

/// Records `outcome` as night `attempt`'s retrain event in `txn`, at the
/// policy revision, cutoff and clock of `pins`, and ends the night.
fn end_in(
    store: &Store,
    txn: &mut RwTxn<'_>,
    attempt: AttemptId,
    pins: (u64, u64, u64),
    outcome: DrafterRetrainOutcome,
) -> Result<PreparedNight> {
    let (revision, cutoff, at) = pins;
    record_retrain_in(store, txn, attempt, revision, cutoff, outcome, at)?;
    Ok(PreparedNight::ended(outcome))
}

/// The night's write after its export: the attempt not yet recorded, the
/// policy unchanged since the export judged under it, no version of the
/// target training, every record the corpus read still live, and both sides
/// of the split filled. Then the target's earlier prepared versions are
/// superseded and the new version is written `prepared` with its corpus and
/// dependency set; the night stays open for its training. Otherwise the
/// night's event records why it trains nothing.
fn prepare_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    attempt: AttemptId,
    target: &DrafterTarget,
    recipe: &DrafterRecipe,
    export: DrafterExport,
) -> Result<PreparedNight> {
    let store = &vault.store;
    if let Some(outcome) = recorded_outcome_in(store, txn, attempt)? {
        return Ok(PreparedNight::ended(outcome));
    }
    let policy = policy_in_txn(store, txn)?;
    let at = vault.now_recorded_at();
    let DrafterExport {
        cutoff,
        policy_revision,
        examples,
        mut omitted,
    } = export;
    if !policy.enabled {
        let reason = DrafterSkipReason::PolicyOff;
        return end_in(
            store,
            txn,
            attempt,
            (policy.revision, cutoff, at),
            DrafterRetrainOutcome::Skipped { reason },
        );
    }
    if policy.revision != policy_revision || policy.recipe.as_ref() != Some(recipe) {
        let reason = DrafterHoldReason::PolicyMoved;
        return end_in(
            store,
            txn,
            attempt,
            (policy.revision, cutoff, at),
            DrafterRetrainOutcome::Held { reason },
        );
    }
    if target_training_in(store, txn, target, None)? {
        let reason = DrafterHoldReason::TrainingInProgress;
        return end_in(
            store,
            txn,
            attempt,
            (policy.revision, cutoff, at),
            DrafterRetrainOutcome::Held { reason },
        );
    }
    let examples = live_examples_in(store, txn, examples, &mut omitted)?;
    let Some(split) = split_examples(examples, &mut omitted)? else {
        let reason = DrafterHoldReason::EmptyCorpus;
        return end_in(
            store,
            txn,
            attempt,
            (policy.revision, cutoff, at),
            DrafterRetrainOutcome::Held { reason },
        );
    };
    let versions = versions_by_id(store, txn)?;
    // The night continues from the head its target serves, when that head is
    // a kept version; never from a candidate that did not qualify.
    let serving = BINDINGS
        .get(store, txn, &target.key()?)?
        .map(|binding| binding.serving);
    let parent = match serving {
        Some(DrafterServing::Version(id))
            if versions
                .get(&id)
                .is_some_and(|row| row.state == DrafterVersionState::Qualified) =>
        {
            DrafterServing::Version(id)
        }
        _ => DrafterServing::Stock,
    };
    let mut dependencies = split.dependencies;
    if let Some(row) = parent.version().and_then(|id| versions.get(&id)) {
        for step in ancestry(&versions, row) {
            union_dependencies(&mut dependencies, &step.dependencies);
        }
    }
    // A version this target's earlier night prepared never trained.
    for (id, mut row) in versions {
        if row.state != DrafterVersionState::Prepared || row.target != *target {
            continue;
        }
        retire_drafter_artifact_keys_in_txn(store, txn, &id)?;
        row.state = DrafterVersionState::Rejected;
        row.generation += 1;
        row.updated_at = at;
        VERSIONS.put(store, txn, &id, &row)?;
    }
    let id = store.clock.entity_id()?;
    let training = mint_side_in(store, txn, id, CorpusSide::Training, split.training)?;
    let held_out = mint_side_in(store, txn, id, CorpusSide::HeldOut, split.held_out)?;
    let corpus = DrafterCorpus {
        form: DRAFTER_CORPUS_FORM.to_owned(),
        training: training.file.clone(),
        held_out: held_out.file.clone(),
        held_out_families_blake3: split.held_out_families_blake3,
        omitted,
    };
    let spec_blake3 = hash_json(&(
        target,
        &parent,
        recipe,
        policy.revision,
        cutoff,
        &dependencies,
        &corpus,
    ))?;
    let version = DrafterVersion {
        id,
        target: target.clone(),
        parent,
        recipe: recipe.clone(),
        policy_revision: policy.revision,
        cutoff,
        dependencies,
        job: Some(attempt),
        spec_blake3: Some(spec_blake3),
        state: DrafterVersionState::Prepared,
        generation: 0,
        artifact: None,
        corpus: Some(corpus),
        evaluation: None,
        training: None,
        created_at: at,
        updated_at: at,
    };
    VERSIONS.put(store, txn, &id, &version)?;
    Ok(PreparedNight {
        outcome: None,
        corpus: Some((id, vec![training, held_out])),
    })
}

impl Vault {
    /// `coach.drafter_retrain` as the Coach, under a leased Coach-stamped
    /// attempt, for `target`, the target the host serves a drafter for
    /// (`None` while it serves none); `trains` says whether a trainer
    /// connector of the host lists a recipe's trainer family.
    ///
    /// The first run of a night pins the policy revision and the cutoff.
    /// Off: skipped. On, with a recipe a trainer here lists, a target and no
    /// version of it training: the corpus is exported, a `prepared` version
    /// with its corpus and dependency set is written, its two sides are
    /// sealed once that write commits, and the version goes to the host to
    /// train ([`DrafterNightStep::Train`]). Otherwise held, with its reason.
    /// A run of the same night while its version is prepared or trains hands
    /// the version to the host again; once its job ended, the night records
    /// `trained` or `failed`. A night that recorded its outcome returns it
    /// and writes nothing.
    ///
    /// # Errors
    /// An attempt that is not this facet's under the Coach's stamp, and
    /// storage, custody and I/O faults. A corpus that is not written once
    /// its version committed is logged; the host holds the night with
    /// `corpus_missing`.
    pub fn run_coach_drafter_retrain(
        &self,
        attempt: &DreamerAdmittedAttempt,
        target: Option<&DrafterTarget>,
        trains: &dyn Fn(&DrafterRecipe) -> bool,
        now: u64,
    ) -> Result<DrafterNightStep> {
        self.require_coach_attempt(attempt, COACH_DRAFTER_RETRAIN_FACET)?;
        let attempt_id = attempt.status.attempt.id;
        let policy = {
            let txn = self.store.env.read_txn()?;
            if let Some(outcome) = recorded_outcome_in(&self.store, &txn, attempt_id)? {
                return Ok(DrafterNightStep::Ended(outcome));
            }
            match night_version_in(&self.store, &txn, attempt_id)? {
                Some(NightVersion::Train(job)) => return Ok(DrafterNightStep::Train(job)),
                Some(NightVersion::Ended) => {
                    drop(txn);
                    return self.end_trained_night(attempt_id, now);
                }
                None => {}
            }
            let policy = policy_in_txn(&self.store, &txn)?;
            if let Some(outcome) = unplanned_in(&self.store, &txn, &policy, target, trains)? {
                drop(txn);
                return self.record_unplanned_night(attempt_id, outcome, now);
            }
            policy
        };
        let (Some(recipe), Some(target)) = (policy.recipe.clone(), target.cloned()) else {
            return self.record_unplanned_night(
                attempt_id,
                DrafterRetrainOutcome::Held {
                    reason: DrafterHoldReason::NoTrainerRecipe,
                },
                now,
            );
        };
        self.sweep_drafter_corpora_logged();
        let export = self.export_drafter_corpus(&target, &policy)?;
        let night = self.with_write_txn_grouped(|txn| {
            prepare_in_txn(self, txn, attempt_id, &target, &recipe, export)
        })?;
        let prepared = night.corpus.as_ref().map(|(version, _)| *version);
        if let Some((version, sides)) = night.corpus
            && let Err(error) = self.write_drafter_corpus(&version, sides)
        {
            tracing::warn!(
                kind = ?error.kind(),
                "a drafter corpus was not written; its night holds with corpus_missing"
            );
        }
        // An erase may have reached the version while its sides were written,
        // and the write superseded earlier ones: their sealed bytes go now.
        self.sweep_drafter_corpora_logged();
        if let Some(outcome) = night.outcome {
            return Ok(DrafterNightStep::Ended(outcome));
        }
        let job = prepared
            .map(|version| self.drafter_training_job(&version))
            .transpose()?
            .flatten();
        match job {
            Some(job) => Ok(DrafterNightStep::Train(Box::new(job))),
            // An erase took the version before the host read it.
            None => self.end_trained_night(attempt_id, now),
        }
    }

    /// Records `outcome` as night `attempt`'s one retrain event, unless the
    /// night recorded one already, under the policy revision that stands.
    fn record_unplanned_night(
        &self,
        attempt: AttemptId,
        outcome: DrafterRetrainOutcome,
        now: u64,
    ) -> Result<DrafterNightStep> {
        self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            if let Some(recorded) = recorded_outcome_in(store, txn, attempt)? {
                return Ok(DrafterNightStep::Ended(recorded));
            }
            let revision = policy_in_txn(store, txn)?.revision;
            record_retrain_in(store, txn, attempt, revision, now, outcome, now)?;
            Ok(DrafterNightStep::Ended(outcome))
        })
    }

    /// Records how night `attempt`'s training ended, from the version it
    /// prepared: `trained` once its load set is published, `failed` with its
    /// job's reason once it was rejected or erased. A version that is still
    /// prepared or trains goes back to the host instead.
    fn end_trained_night(&self, attempt: AttemptId, now: u64) -> Result<DrafterNightStep> {
        let step = self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            if let Some(recorded) = recorded_outcome_in(store, txn, attempt)? {
                return Ok(Ok(DrafterNightStep::Ended(recorded)));
            }
            let Some(row) = version_of_night_in(store, txn, attempt)? else {
                return Ok(Err(()));
            };
            let Some(outcome) = night_outcome_of(&row) else {
                return Ok(Err(()));
            };
            record_retrain_in(
                store,
                txn,
                attempt,
                row.policy_revision,
                row.cutoff,
                outcome,
                now,
            )?;
            Ok(Ok(DrafterNightStep::Ended(outcome)))
        })?;
        match step {
            Ok(step) => Ok(step),
            Err(()) => {
                let txn = self.store.env.read_txn()?;
                match night_version_in(&self.store, &txn, attempt)? {
                    Some(NightVersion::Train(job)) => Ok(DrafterNightStep::Train(job)),
                    _ => {
                        drop(txn);
                        let reason = DrafterHoldReason::CorpusMissing;
                        self.record_unplanned_night(
                            attempt,
                            DrafterRetrainOutcome::Held { reason },
                            now,
                        )
                    }
                }
            }
        }
    }

    /// [`Self::sweep_drafter_corpora`], a fault logged: the next sweep takes
    /// what this one left.
    fn sweep_drafter_corpora_logged(&self) {
        if let Err(error) = self.sweep_drafter_corpora() {
            tracing::warn!(kind = ?error.kind(), "the drafter corpus sweep did not finish");
        }
    }
}
