//! The owner's authorization of one prepared run, and the host's record of
//! why a run that waits on it cannot advance. An authorization pins the
//! exact spec and run declaration; the host dispatches nothing else, and no
//! credential, key, lease or permit is kept with it.
use rmpv::Value;

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::maintenance::coach::enqueue_coach_training_run_in_txn;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::run_admission::RunDeclaration;

use super::{
    RUNS, TrainingAuthorization, TrainingAuthorizationSource, TrainingDeclarationPin, TrainingHold,
    TrainingOwner, TrainingRun, TrainingState, TrainingTeachersPin, invalid, run_in_txn,
};

/// A `coach.training_run` job's input: the run and the spec its owner
/// authorized, as hex.
pub(crate) fn training_run_job_input(run: &EntityId, spec_blake3: &[u8; 32]) -> Value {
    let spec = blake3::Hash::from(*spec_blake3).to_hex().to_string();
    Value::Map(vec![
        (Value::from("run"), Value::from(run.to_hex())),
        (Value::from("spec"), Value::from(spec)),
    ])
}

/// The run and spec a `coach.training_run` job's input names.
fn training_run_job_target(input: &Value) -> Result<(EntityId, [u8; 32])> {
    let field = |name: &str| match input {
        Value::Map(fields) => fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .and_then(|(_, value)| value.as_str())
            .ok_or_else(|| invalid("a training run job names its run and spec")),
        _ => Err(invalid("a training run job names its run and spec")),
    };
    let run = EntityId::from_hex(field("run")?)?;
    let spec = blake3::Hash::from_hex(field("spec")?)
        .map_err(|_| invalid("a training run job's spec is 64 hex"))?;
    Ok((run, *spec.as_bytes()))
}

impl TrainingDeclarationPin {
    /// The facts of `declaration` a dispatch checks, read through its own
    /// accessors: its teachers with their target and purpose, and its budget
    /// line. Its aliases, connector names and custody overrides have no
    /// public reader and are not pinned. An undeclared run is refused.
    pub fn of(declaration: &RunDeclaration) -> Result<Self> {
        if !declaration.is_declared() {
            return Err(invalid("a training run is admitted under a declared run"));
        }
        Ok(Self {
            teachers: declaration.teachers().map(|teachers| TrainingTeachersPin {
                models: teachers.models().cloned().collect(),
                target: teachers.target().to_owned(),
                purpose: teachers.purpose().to_owned(),
            }),
            budget: declaration.budget().clone(),
        })
    }
}

impl TrainingAuthorization {
    /// The same owner choice: spec, declaration and source. Who gave it and
    /// when may differ on a retry.
    fn same_choice(&self, other: &Self) -> bool {
        self.spec_blake3 == other.spec_blake3
            && self.declaration == other.declaration
            && self.source == other.source
    }
}

impl TrainingRun {
    /// Whether the run waits on the host: authorized and not yet dispatched,
    /// or returned and not yet scored.
    pub fn awaits_host(&self) -> bool {
        self.state == TrainingState::Authorized
            || (self.state == TrainingState::Returned && self.evaluation.is_none())
    }
}

impl Vault {
    /// The owner's authorization of one prepared run at the exact spec they
    /// saw, under the declaration the host admits it with, in `txn`. It
    /// queues the run for the host's Coach in the same commit. The same
    /// choice again returns the run as it stands; any other state refuses.
    #[expect(
        clippy::too_many_arguments,
        reason = "the owner door's arguments, its writer and the authorization's source"
    )]
    pub(crate) fn authorize_training_pack_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        expected_spec: &[u8; 32],
        declaration: TrainingDeclarationPin,
        source: TrainingAuthorizationSource,
        at: u64,
    ) -> Result<TrainingRun> {
        let actor = owner.revalidate_in_txn(self, txn)?;
        let mut run = run_in_txn(self, txn, id)?;
        if run.spec_blake3 != *expected_spec {
            return Err(invalid(
                "the authorized spec is not the run's prepared spec",
            ));
        }
        let authorization = TrainingAuthorization {
            owner: TrainingOwner::Actor(actor),
            at,
            spec_blake3: run.spec_blake3,
            declaration,
            source,
        };
        let repeated = run.state == TrainingState::Authorized
            && run
                .authorization
                .as_ref()
                .is_some_and(|given| given.same_choice(&authorization));
        if repeated {
            return Ok(run);
        }
        if run.state != TrainingState::Prepared {
            return Err(invalid("only a prepared run is authorized, and only once"));
        }
        run.state = TrainingState::Authorized;
        run.authorization = Some(authorization);
        RUNS.put(&self.store, txn, id, &run)?;
        enqueue_coach_training_run_in_txn(self, txn, id, &run.spec_blake3, at)?;
        Ok(run)
    }

    /// The owner's own door to authorize one prepared run at the spec they
    /// saw, in its own writer. The run is queued for the host's Coach in the
    /// same commit; the host dispatches it without the owner's proof.
    pub fn authorize_training_pack(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        expected_spec: &[u8; 32],
        declaration: TrainingDeclarationPin,
        at: u64,
    ) -> Result<TrainingRun> {
        self.with_write_txn_grouped(|txn| {
            self.authorize_training_pack_in_txn(
                txn,
                owner,
                id,
                expected_spec,
                declaration,
                TrainingAuthorizationSource::Direct,
                at,
            )
        })
    }

    /// Trusted host door: why the host cannot advance a run that waits on
    /// it (no trainer, no evaluator, no admission). A different hold replaces
    /// it; the same one again writes nothing. The run's state does not move.
    pub fn hold_training_run(
        &self,
        id: &EntityId,
        code: &str,
        detail: &str,
        at: u64,
    ) -> Result<TrainingRun> {
        if code.trim().is_empty() {
            return Err(invalid("a training hold names its code"));
        }
        self.with_write_txn_grouped(|txn| {
            let mut run = run_in_txn(self, txn, id)?;
            if !run.awaits_host() {
                return Err(invalid("only a run that waits on the host is held"));
            }
            if run
                .hold
                .as_ref()
                .is_some_and(|hold| hold.code == code && hold.detail == detail)
            {
                return Ok(run);
            }
            run.hold = Some(TrainingHold {
                code: code.to_owned(),
                detail: detail.to_owned(),
                at,
            });
            RUNS.put(&self.store, txn, id, &run)?;
            Ok(run)
        })
    }

    /// Every run that waits on the host: authorized and not yet dispatched,
    /// or returned and not yet scored.
    pub fn authorized_training_runs(&self) -> Result<Vec<TrainingRun>> {
        Ok(self
            .training_runs()?
            .into_iter()
            .filter(TrainingRun::awaits_host)
            .collect())
    }

    /// The run a `coach.training_run` job's input names, while it still
    /// waits on the host at that spec; `None` once it moved on.
    pub(crate) fn queued_training_run(&self, input: &Value) -> Result<Option<TrainingRun>> {
        let (id, spec) = training_run_job_target(input)?;
        Ok(self
            .training_run(&id)?
            .filter(|run| run.spec_blake3 == spec && run.awaits_host()))
    }

    /// Queues each run that waits on the host for its Coach job again, for
    /// the nightly offer pass; the queue's dedupe keeps one job per run.
    pub(crate) fn requeue_authorized_training_runs(&self, now: u64) -> Result<()> {
        let runs = self.authorized_training_runs()?;
        if runs.is_empty() {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| {
            for run in &runs {
                enqueue_coach_training_run_in_txn(self, txn, &run.id, &run.spec_blake3, now)?;
            }
            Ok(())
        })
    }
}
