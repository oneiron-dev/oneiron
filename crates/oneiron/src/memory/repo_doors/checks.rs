//! `self.code.checks.start` and `self.code.checks.finish` (ARCH-0068 RC5, FIX
//! [L4-30-CHECK-REUSE-RECORD]): a leased run records a native check it ran in
//! its own checkout.
//!
//! The engine captures every input version it can see and mints the record;
//! the agent never supplies them (CHECK-VERBS = A). Start admits the run's own
//! live checkout lease and records HEAD's tree when the worktree is clean, the
//! command, toolchain and environment digests, and the TASK's request revision.
//! Finish captures the tree and the revision again and stores the observed pass
//! and output. Environment values are never stored: only their names and the
//! whole map's digest. A world check is recorded with its flag; reuse never
//! takes one (WORLD-REUSE = A, enforced by PR 3).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{RepoRunAnswer, RepoRunBinding};
use crate::EntityId;
use crate::check_record::{
    AttemptCheckRecord, CHECK_RECORDS, CheckAfter, CheckFinish, CheckInputVersions, CheckProducer,
};
use crate::git_wire::GitWire;
use crate::memory::checkout_doors::refusal as checkout_refusal;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::store::attempt_result::AttemptResultRef;
use crate::task_verb::linear_store::task_revision_in_txn;

/// `self.code.checks.start`: records the native check the run is about to run
/// in its own live checkout. The engine captures the input versions; the agent
/// supplies the command it will run and the toolchain and environment it
/// declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoCheckStartInput {
    /// The CODE anchor the run's Grant admits; its stored repo is the served store.
    pub repo: EntityId,
    /// The full Git ref the run edits through this checkout.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The checkout id, 32 lower-hex characters.
    pub checkout: String,
    /// The live lease epoch.
    pub epoch: u64,
    /// The native command the run is about to run, argv in order.
    pub command: Vec<String>,
    /// The declared toolchain identities, names to values; stored and digested.
    #[serde(default)]
    pub toolchain: BTreeMap<String, String>,
    /// The declared environment, names to values; only the names are stored,
    /// the whole map is digested.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Whether the check depends on the world outside the checkout; a world check is never reused.
    #[serde(default)]
    pub world: bool,
}

/// `self.code.checks.start`'s answer: the minted check id and its captured inputs.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoCheckStartOutput {
    /// The engine-minted check id.
    pub check: EntityId,
    /// The input versions the engine captured before the command ran.
    pub inputs: CheckInputVersions,
}

/// `self.code.checks.finish`: stores what the run's native check observed: its
/// exit status and the stored output artifact. The engine captures the inputs
/// again and answers whether the check passed and held still.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoCheckFinishInput {
    /// The CODE anchor the run's Grant admits; its stored repo is the served store.
    pub repo: EntityId,
    /// The full Git ref the run edits through this checkout.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The checkout id, 32 lower-hex characters.
    pub checkout: String,
    /// The live lease epoch.
    pub epoch: u64,
    /// The check id `self.code.checks.start` minted for this run.
    pub check: EntityId,
    /// The command's exit status; `None` when a signal ended it.
    pub exit_status: Option<i32>,
    /// The stored artifact version holding the command's output, by its id.
    #[schemars(with = "String")]
    pub output: AttemptResultRef,
}

/// `self.code.checks.finish`'s answer: the observed pass and stability beside the captured inputs.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoCheckFinishOutput {
    /// The finished check id.
    pub check: EntityId,
    /// The observed pass: the command exited zero.
    pub passed: bool,
    /// The inputs held still across the run.
    pub stable: bool,
    /// The input versions the engine captured before the command ran.
    pub inputs: CheckInputVersions,
    /// What the engine captured again after the command ended.
    pub after: CheckAfter,
}

/// The most argv entries a native check command holds.
const MAX_COMMAND_ARGS: usize = 64;
/// The most bytes one argv entry holds.
const MAX_COMMAND_ARG_BYTES: usize = 4096;
/// The most entries a declared toolchain or environment holds.
const MAX_DECLARED_ENTRIES: usize = 64;
/// The most bytes one declared name holds.
const MAX_DECLARED_KEY_BYTES: usize = 128;
/// The most bytes one toolchain value holds.
const MAX_TOOLCHAIN_VALUE_BYTES: usize = 512;

/// The start's command, within its bounds: 1 to 64 argv entries, each at most
/// 4096 bytes with no NUL.
fn validate_command(command: &[String]) -> MemoryResult<()> {
    if command.is_empty() || command.len() > MAX_COMMAND_ARGS {
        return Err(MemoryError::bad_request(
            "command must hold 1 to 64 arguments",
        ));
    }
    if command
        .iter()
        .any(|arg| arg.len() > MAX_COMMAND_ARG_BYTES || arg.contains('\0'))
    {
        return Err(MemoryError::bad_request(
            "command arguments must be at most 4096 bytes with no NUL",
        ));
    }
    Ok(())
}

/// A declared toolchain or environment within its bounds: at most 64 entries, keys 1 to 128 bytes.
fn validate_declared(map: &BTreeMap<String, String>, what: &str) -> MemoryResult<()> {
    if map.len() > MAX_DECLARED_ENTRIES {
        return Err(MemoryError::bad_request(format!(
            "{what} must hold at most 64 entries"
        )));
    }
    if map
        .keys()
        .any(|key| key.is_empty() || key.len() > MAX_DECLARED_KEY_BYTES)
    {
        return Err(MemoryError::bad_request(format!(
            "{what} keys must be 1 to 128 bytes"
        )));
    }
    Ok(())
}

/// The start's toolchain within its bounds: the declared bounds, and values at most 512 bytes.
fn validate_toolchain(toolchain: &BTreeMap<String, String>) -> MemoryResult<()> {
    validate_declared(toolchain, "toolchain")?;
    if toolchain
        .values()
        .any(|value| value.len() > MAX_TOOLCHAIN_VALUE_BYTES)
    {
        return Err(MemoryError::bad_request(
            "toolchain values must be at most 512 bytes",
        ));
    }
    Ok(())
}

/// A finish against its start's record: unfinished, on the same checkout,
/// started under this generation.
fn check_finish_open(
    record: &AttemptCheckRecord,
    input: &RepoCheckFinishInput,
    generation: u32,
) -> MemoryResult<()> {
    if record.finish.is_some() {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the check is already finished",
            &[],
        ));
    }
    if record.producer.generation != generation {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the check started under another generation",
            &["Start the check and finish it in one generation."],
        ));
    }
    if record.repo != input.repo
        || record.git_ref != input.git_ref
        || record.checkout != input.checkout
        || record.epoch != input.epoch
    {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the finish names another checkout than the start",
            &["Finish the check on the checkout it started on."],
        ));
    }
    Ok(())
}

impl Memory<'_> {
    /// `self.code.checks.start` for a run: admits the run's own live checkout
    /// lease, captures the input versions, and stores the unfinished record
    /// under a minted check id. The worktree must be materialized; a dirty
    /// tree records an unpinned one, never a refusal.
    pub fn repo_checks_start_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoCheckStartInput,
    ) -> MemoryResult<RepoRunAnswer<RepoCheckStartOutput>> {
        validate_command(&input.command)?;
        validate_toolchain(&input.toolchain)?;
        validate_declared(&input.environment, "environment")?;
        let own = self.repo_run_checkout(
            binding,
            input.repo,
            &input.git_ref,
            &input.checkout,
            input.epoch,
            BTreeSet::new(),
        )?;
        let wire = GitWire::new(self.vault)?;
        let tree_path = wire
            .checkout_worktree_path(&own.lease)
            .map_err(checkout_refusal)?;
        if !tree_path.is_dir() {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the run's checkout is not materialized",
                &["Bind it first with self.code.checkout.bind."],
            ));
        }
        let tree = wire
            .checkout_head_tree(&own.lease)
            .map_err(checkout_refusal)?
            .map(|oid| oid.as_str().to_owned());
        let producer = CheckProducer {
            attempt: own.attempt,
            generation: own.generation,
            executor_run: binding.executor_run,
            task: binding.task,
            project: own.project,
        };
        let environment_names: Vec<String> = input.environment.keys().cloned().collect();
        let command = input.command;
        let toolchain = input.toolchain;
        let git_ref = input.git_ref;
        let checkout = input.checkout;
        let (check, inputs) = self.vault.with_write_txn_grouped(|txn| {
            let revision = task_revision_in_txn(&self.vault.store, txn, binding.task)?;
            let inputs = CheckInputVersions::capture(
                &command,
                &toolchain,
                &input.environment,
                tree,
                revision,
            )?;
            let check = EntityId::now();
            CHECK_RECORDS.put(
                &self.vault.store,
                txn,
                &(producer.attempt, check),
                &AttemptCheckRecord {
                    check,
                    producer,
                    repo: input.repo,
                    git_ref,
                    checkout,
                    epoch: input.epoch,
                    command,
                    toolchain,
                    environment_names,
                    world: input.world,
                    inputs: inputs.clone(),
                    finish: None,
                },
            )?;
            Ok((check, inputs))
        })?;
        Ok(RepoRunAnswer {
            rows: vec![input.repo],
            output: RepoCheckStartOutput { check, inputs },
        })
    }

    /// `self.code.checks.finish` for a run: admits the run's own live checkout
    /// lease, captures the inputs again, and stores what the check observed.
    /// Another attempt's check reads as not found, so no run finishes a
    /// peer's record; a finished check, another checkout, or another
    /// generation is refused. The output names a stored artifact the run's
    /// own read lane reads.
    pub fn repo_checks_finish_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoCheckFinishInput,
    ) -> MemoryResult<RepoRunAnswer<RepoCheckFinishOutput>> {
        let own = self.repo_run_checkout(
            binding,
            input.repo,
            &input.git_ref,
            &input.checkout,
            input.epoch,
            BTreeSet::new(),
        )?;
        let key = (own.attempt, input.check);
        let record = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            CHECK_RECORDS.get(&self.vault.store, &txn, &key)?
        };
        let Some(record) = record else {
            return Err(MemoryError::not_found("check record not found"));
        };
        check_finish_open(&record, &input, own.generation)?;
        let artifact = EntityId::from_hex(input.output.as_str()).map_err(|_| {
            MemoryError::bad_request("output must name a stored artifact by its id")
        })?;
        self.repo_lane_reads(binding, &[artifact])?;
        let wire = GitWire::new(self.vault)?;
        let tree = wire
            .checkout_head_tree(&own.lease)
            .map_err(checkout_refusal)?
            .map(|oid| oid.as_str().to_owned());
        let output = self.vault.with_write_txn_grouped(|txn| {
            let revision = task_revision_in_txn(&self.vault.store, txn, binding.task)?;
            let after = CheckAfter {
                tree,
                request_revision: revision,
            };
            let Some(mut record) = CHECK_RECORDS.get(&self.vault.store, txn, &key)? else {
                return Ok(Err(MemoryError::not_found("check record not found")));
            };
            if let Err(refused) = check_finish_open(&record, &input, own.generation) {
                return Ok(Err(refused));
            }
            let finish = CheckFinish::observe(
                after,
                input.exit_status,
                input.output.clone(),
                &record.inputs,
            );
            let output = RepoCheckFinishOutput {
                check: input.check,
                passed: finish.passed,
                stable: finish.stable,
                inputs: record.inputs.clone(),
                after: finish.after.clone(),
            };
            record.finish = Some(finish);
            CHECK_RECORDS.put(&self.vault.store, txn, &key, &record)?;
            Ok(Ok(output))
        })?;
        let output = output?;
        Ok(RepoRunAnswer {
            rows: vec![input.repo],
            output,
        })
    }
}
