//! The nightly drafter retrain, `coach.drafter_retrain` (FIX 12569,
//! I5-DRAFTER = A): Coach-owned work on the shared night scheduler.
//!
//! Its prepare step (FIX 14973): with the policy on, a recipe chosen and a
//! target the host serves a drafter for, the night exports the vault's
//! corpus for that target ([`super::corpus`]). Then, in one write, it checks
//! the policy again and every record the corpus read, splits the corpus,
//! supersedes the target's earlier version still prepared (it never trained:
//! `rejected`, its corpus keys retired), mints the two corpus keys and writes
//! a `DrafterVersion` in state `prepared` with its corpus and its dependency
//! set, the parent's whole ancestry included, beside the night's retrain
//! event. Once that write commits, the two sides are sealed and written.
//!
//! No trainer recipe is wired on any host yet (FIX 14974), so every night
//! with the policy on still ends held with `no_trainer_recipe`: nothing
//! trains and every binding stays as it is. A night with no recipe or no
//! target, a policy that moved during the export, or a corpus with no
//! training or no held-out example writes no version. A night never reports
//! a successful empty retrain. The same attempt again returns the outcome it
//! recorded and writes nothing.

use heed::{RoTxn, RwTxn};

use super::corpus::{
    CorpusSide, CorpusSideToSeal, DRAFTER_CORPUS_FORM, DrafterExport, live_examples_in,
    mint_side_in, split_examples, union_dependencies,
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

/// What one night's write decided: its outcome, and the version whose corpus
/// it prepared with that corpus's two sides, waiting to be sealed.
struct PreparedNight {
    outcome: DrafterRetrainOutcome,
    corpus: Option<(EntityId, Vec<CorpusSideToSeal>)>,
}

/// The outcome attempt `attempt` recorded in `txn`, if it ran already. A row
/// that does not decode is no record of this attempt.
fn recorded_outcome_in(
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

/// How a night that prepares nothing under `policy` ends: skipped when the
/// policy is off, held otherwise.
fn unprepared(policy: &DrafterPolicy) -> DrafterRetrainOutcome {
    if policy.enabled {
        DrafterRetrainOutcome::Held {
            reason: DrafterHoldReason::NoTrainerRecipe,
        }
    } else {
        DrafterRetrainOutcome::Skipped {
            reason: DrafterSkipReason::PolicyOff,
        }
    }
}

/// Records the night's one retrain event in `txn`.
fn record_retrain_in(
    store: &Store,
    txn: &mut RwTxn<'_>,
    attempt: AttemptId,
    policy_revision: u64,
    cutoff: u64,
    outcome: DrafterRetrainOutcome,
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
        cutoff,
    )?;
    Ok(())
}

/// The night's write after its export: the attempt not yet recorded, the
/// policy unchanged since the export judged under it, every record the
/// corpus read still live, and both sides of the split filled. Then the
/// target's earlier prepared versions are superseded, the new version is
/// written `prepared` with its corpus and dependency set, and the night's
/// event is recorded; otherwise only the event.
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
        return Ok(PreparedNight {
            outcome,
            corpus: None,
        });
    }
    let policy = policy_in_txn(store, txn)?;
    let DrafterExport {
        cutoff,
        policy_revision,
        examples,
        mut omitted,
    } = export;
    let unchanged = policy.enabled
        && policy.revision == policy_revision
        && policy.recipe.as_ref() == Some(recipe);
    let split = if unchanged {
        let examples = live_examples_in(store, txn, examples, &mut omitted)?;
        split_examples(examples, &mut omitted)?
    } else {
        None
    };
    let Some(split) = split else {
        let outcome = unprepared(&policy);
        record_retrain_in(store, txn, attempt, policy.revision, cutoff, outcome)?;
        return Ok(PreparedNight {
            outcome,
            corpus: None,
        });
    };
    let at = vault.now_recorded_at();
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
        created_at: at,
        updated_at: at,
    };
    VERSIONS.put(store, txn, &id, &version)?;
    // No trainer recipe is wired on any host yet (FIX 14974).
    let outcome = DrafterRetrainOutcome::Held {
        reason: DrafterHoldReason::NoTrainerRecipe,
    };
    record_retrain_in(store, txn, attempt, policy.revision, cutoff, outcome)?;
    Ok(PreparedNight {
        outcome,
        corpus: Some((id, vec![training, held_out])),
    })
}

impl Vault {
    /// `coach.drafter_retrain` as the Coach, under a leased Coach-stamped
    /// attempt, for `target`, the target the host serves a drafter for
    /// (`None` while it serves none): pins the policy revision and the
    /// cutoff and records the night's outcome as one event. Off: skipped,
    /// with its reason. On, with a recipe chosen and a target: the corpus is
    /// exported, a `prepared` version with its corpus and dependency set is
    /// written beside the event, and its two sides are sealed once that
    /// write commits; the night is held, `no_trainer_recipe`. On otherwise:
    /// held, `no_trainer_recipe`, nothing exported. The same attempt again
    /// returns the outcome it recorded and writes nothing.
    ///
    /// # Errors
    /// An attempt that is not this facet's under the Coach's stamp, and
    /// storage, custody and I/O faults. A corpus that is not written once
    /// its version committed is logged; the next night supersedes it.
    pub fn run_coach_drafter_retrain(
        &self,
        attempt: &DreamerAdmittedAttempt,
        target: Option<&DrafterTarget>,
        now: u64,
    ) -> Result<DrafterRetrainOutcome> {
        self.require_coach_attempt(attempt, COACH_DRAFTER_RETRAIN_FACET)?;
        let attempt_id = attempt.status.attempt.id;
        let policy = {
            let txn = self.store.env.read_txn()?;
            if let Some(outcome) = recorded_outcome_in(&self.store, &txn, attempt_id)? {
                return Ok(outcome);
            }
            policy_in_txn(&self.store, &txn)?
        };
        let plan = match (policy.enabled, policy.recipe.as_ref(), target) {
            (true, Some(recipe), Some(target)) => Some((recipe.clone(), target.clone())),
            _ => None,
        };
        let Some((recipe, target)) = plan else {
            return self.with_write_txn_grouped(|txn| {
                let store = &self.store;
                if let Some(outcome) = recorded_outcome_in(store, txn, attempt_id)? {
                    return Ok(outcome);
                }
                let policy = policy_in_txn(store, txn)?;
                let outcome = unprepared(&policy);
                record_retrain_in(store, txn, attempt_id, policy.revision, now, outcome)?;
                Ok(outcome)
            });
        };
        self.sweep_drafter_corpora_logged();
        let export = self.export_drafter_corpus(&target, &policy)?;
        let night = self.with_write_txn_grouped(|txn| {
            prepare_in_txn(self, txn, attempt_id, &target, &recipe, export)
        })?;
        if let Some((version, sides)) = night.corpus
            && let Err(error) = self.write_drafter_corpus(&version, sides)
        {
            tracing::warn!(
                kind = ?error.kind(),
                "a drafter corpus was not written; the next night supersedes its version"
            );
        }
        // An erase may have reached the version while its sides were written,
        // and the write superseded earlier ones: their sealed bytes go now.
        self.sweep_drafter_corpora_logged();
        Ok(night.outcome)
    }

    /// [`Self::sweep_drafter_corpora`], a fault logged: the next sweep takes
    /// what this one left.
    fn sweep_drafter_corpora_logged(&self) {
        if let Err(error) = self.sweep_drafter_corpora() {
            tracing::warn!(kind = ?error.kind(), "the drafter corpus sweep did not finish");
        }
    }
}
