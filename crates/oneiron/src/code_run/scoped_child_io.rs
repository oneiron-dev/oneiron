//! A host's own scoped child, end to end (FIX 7508): the inputs a host
//! commits for it as its parent run's result occurrences, the per-job
//! profile its runner runs it on, the one-child wait over it, and its
//! report.
//!
//! Every body goes through the vault's one routed result store: a host
//! input or a staged draft is published as its parent run's own complete
//! occurrence, so a loan, a scoped read, the replay record and an erase all
//! meet it as any other result of the run. No second store, no synced row.
//!
//! A profile is the host's word on how one queued scoped child runs: the
//! backend and meter its own model calls take (its parent's, never the
//! host's shared code-mode meter), the model they name and the ports its
//! lent verbs run on. The host registers it by the child's task before it
//! queues the child and removes it once it stops waiting on it; a child
//! with no profile runs as every scoped child does.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use crate::code_run::{
    CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord, DelegatedSource, ReaderJob,
    ReaderJobs, ScopedChildPorts, TaskWaitPolicy, TaskWaitSet, TaskWaitSetResult, reader_task_id,
    reader_wait_id, reduce_task_wait_set,
};
use crate::engine_executor::EngineExecutorConfig;
use crate::llm::{BudgetGuard, LlmBackend, ModelId, ModelLocality};
use crate::{EntityId, Error, Result, Vault};

/// The step key a host's one-child wait is keyed by.
const HOST_CHILD_WAIT_KEY: &str = "host-scoped-child";

/// One input a host commits for a scoped child it queues: the name the
/// child reads it by, its path in the parent run, its bytes, and the rows it
/// was drawn from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInput {
    pub name: String,
    pub path: String,
    pub body: Vec<u8>,
    pub rows: Option<Vec<EntityId>>,
}

/// Commits `inputs` on `vault` as run `parent_run`'s own complete result
/// occurrences, in its replay record, and answers each as a loan lends it:
/// by its name, its whole body. An input whose path the record already
/// holds answers the occurrence it holds.
///
/// # Errors
///
/// The store's own errors.
pub fn commit_host_inputs(
    vault: &Vault,
    parent_run: EntityId,
    inputs: Vec<HostInput>,
) -> Result<BTreeMap<String, DelegatedSource>> {
    let stored = vault.get_code_run_replay_record(&parent_run)?;
    let mut published = stored.is_none();
    let mut record = stored.unwrap_or_else(|| {
        CodeRunReplayRecord::new(parent_run, CodeRunDeterminism::new(0, [0; 32]))
    });
    let mut lent = BTreeMap::new();
    for input in inputs {
        let output = match record
            .outputs
            .iter()
            .find(|output| output.path == input.path)
        {
            Some(output) => output.clone(),
            None => {
                let output = publish(vault, parent_run, input.path, &input.body)?;
                record.outputs.push(output.clone());
                published = true;
                output
            }
        };
        lent.insert(
            input.name,
            DelegatedSource {
                owner: parent_run,
                path: output.path,
                handle: output.handle,
                range: (0, output.raw_len),
                rows: input.rows,
            },
        );
    }
    if published {
        vault.put_code_run_replay_record(&record)?;
    }
    Ok(lent)
}

/// Stages `body` as run `parent_run`'s own output at `path`, beside its
/// inputs; an output already at `path` answers as it stands.
///
/// # Errors
///
/// The store's own errors; [`Error::InvalidConfig`] for a run with no
/// record.
pub fn stage_host_output(
    vault: &Vault,
    parent_run: EntityId,
    path: String,
    body: &[u8],
) -> Result<CodeRunRawOutput> {
    let mut record = vault
        .get_code_run_replay_record(&parent_run)?
        .ok_or_else(|| Error::InvalidConfig("a staged output needs its run's record".to_owned()))?;
    if let Some(output) = record.outputs.iter().find(|output| output.path == path) {
        return Ok(output.clone());
    }
    let output = publish(vault, parent_run, path, body)?;
    record.outputs.push(output.clone());
    vault.put_code_run_replay_record(&record)?;
    Ok(output)
}

/// Run `parent_run`'s output at `path`, read whole, when it has one.
///
/// # Errors
///
/// The store's own errors.
pub fn read_host_output(
    vault: &Vault,
    parent_run: EntityId,
    path: &str,
) -> Result<Option<Vec<u8>>> {
    let Some(output) = vault
        .get_code_run_replay_record(&parent_run)?
        .and_then(|record| {
            record
                .outputs
                .into_iter()
                .find(|output| output.path == path)
        })
    else {
        return Ok(None);
    };
    read_whole(vault, &output)
}

/// Whether run `run` has a replay record on `vault`.
///
/// # Errors
///
/// The store's own errors.
pub fn host_run_recorded(vault: &Vault, run: EntityId) -> Result<bool> {
    Ok(vault.get_code_run_replay_record(&run)?.is_some())
}

/// The task the scoped child `parent_run` queues under `intent_key` is: a
/// host registers its profile by it before the child is queued.
///
/// # Errors
///
/// An id that derives to a reserved one.
pub fn scoped_child_task(parent_run: EntityId, intent_key: &str) -> Result<EntityId> {
    reader_task_id(parent_run, intent_key)
}

/// The one-child wait (`n_of` = 1) over scoped child `task` of `parent_run`,
/// reduced as `tasks.wait` reduces one at `now_ms`, until the child's own
/// cutoff: its row and the reduction once it is done, `None` while it waits.
///
/// # Errors
///
/// The route's own read errors.
pub fn collect_scoped_child(
    vault: &Vault,
    parent_run: EntityId,
    task: EntityId,
    now_ms: u64,
) -> Result<Option<(ReaderJob, TaskWaitSetResult)>> {
    let job = ReaderJobs::canonical(vault).job(task)?;
    let Some(row) = job.clone() else {
        return Ok(None);
    };
    let set = TaskWaitSet {
        id: reader_wait_id(parent_run, HOST_CHILD_WAIT_KEY)?,
        parent_run,
        tasks: vec![task],
        policy: TaskWaitPolicy::NOf { n: 1 },
        until_ms: row.binding.child_cutoff_unix_ms,
        step_key: HOST_CHILD_WAIT_KEY.to_owned(),
        settled_at_ms: None,
        settled: None,
    };
    let result = reduce_task_wait_set(&set, &[(task, job)], now_ms);
    Ok(result.done.then_some((row, result)))
}

/// The report scoped child `job` settled with, read whole from its own run,
/// when it reported one.
///
/// # Errors
///
/// The store's own errors.
pub fn read_scoped_finding(vault: &Vault, job: &ReaderJob) -> Result<Option<Vec<u8>>> {
    let Some(found) = &job.finding else {
        return Ok(None);
    };
    let Some(output) = vault
        .get_code_run_replay_record(&found.owner)?
        .and_then(|record| {
            record
                .outputs
                .into_iter()
                .find(|output| output.path == found.path && output.handle == found.handle)
        })
    else {
        return Ok(None);
    };
    read_whole(vault, &output)
}

/// Publishes `body` as `owner`'s complete output at `path`.
fn publish(vault: &Vault, owner: EntityId, path: String, body: &[u8]) -> Result<CodeRunRawOutput> {
    let mut sink = vault.code_run_output_sink()?;
    sink.write(body)?;
    vault.publish_code_run_output(path, sink, true, Some(owner))
}

/// `output`'s whole body.
fn read_whole(vault: &Vault, output: &CodeRunRawOutput) -> Result<Option<Vec<u8>>> {
    let len = usize::try_from(output.raw_len)
        .map_err(|_| Error::ArithmeticOverflow("host scoped output length"))?;
    vault.read_code_run_raw_output_range(output, 0, len)
}

/// A host's stop of one scoped child: set once, with the code it settles
/// with; read by its ports, its backend and its runner.
#[derive(Debug, Clone, Default)]
pub struct ScopedChildStop(Arc<OnceLock<&'static str>>);

impl ScopedChildStop {
    /// Stops the child with `code`; a later stop keeps the first code.
    pub fn stop(&self, code: &'static str) {
        let _ = self.0.set(code);
    }

    /// The code the child was stopped with, if it was.
    #[must_use]
    pub fn code(&self) -> Option<&'static str> {
        self.0.get().copied()
    }
}

/// How one scoped child its host queued runs: the backend its own model
/// calls go through and the meter they spend on (its parent's), the model
/// and locality they name, the ports its lent verbs run on, and its stop.
#[derive(Clone)]
pub struct ScopedChildProfile {
    pub backend: Arc<dyn LlmBackend>,
    pub guard: BudgetGuard,
    pub model: ModelId,
    pub locality: ModelLocality,
    pub ports: Arc<dyn ScopedChildPorts>,
    pub stop: ScopedChildStop,
}

impl ScopedChildProfile {
    /// Binds the profile's model into a run's `config`: the run generates on
    /// it unless a seat its vault requires binds another.
    pub fn bind_config(&self, config: &mut EngineExecutorConfig) {
        config.model = self.model.clone();
        config.model_locality = self.locality;
    }
}

/// The profiles a provider's scoped children run on, by task. A provider
/// holds one; nothing here is process-wide.
#[derive(Default)]
pub struct ScopedChildHosts {
    profiles: Mutex<HashMap<EntityId, ScopedChildProfile>>,
}

impl ScopedChildHosts {
    /// `profile` for scoped child `task`, in place of any before it.
    pub fn register(&self, task: EntityId, profile: ScopedChildProfile) {
        self.lock().insert(task, profile);
    }

    /// Forgets `task`'s profile.
    pub fn remove(&self, task: EntityId) {
        self.lock().remove(&task);
    }

    /// The profile `task` runs on, if its host registered one.
    #[must_use]
    pub fn profile(&self, task: EntityId) -> Option<ScopedChildProfile> {
        self.lock().get(&task).cloned()
    }

    /// The ports `task`'s profile lends, if it has one.
    #[must_use]
    pub fn ports(&self, task: EntityId) -> Option<Arc<dyn ScopedChildPorts>> {
        self.lock()
            .get(&task)
            .map(|profile| Arc::clone(&profile.ports))
    }

    /// Every entry is one insert or remove, so a holder that panicked left
    /// the map whole.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<EntityId, ScopedChildProfile>> {
        self.profiles.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
