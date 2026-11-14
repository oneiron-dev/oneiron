//! `self.code.checks.reuse` (ARCH-0068 RC5, FIX
//! [L4-30-CHECK-REUSE-RECORD]): a leased run reuses a peer's recorded native
//! check on matching inputs instead of running it.
//!
//! The engine captures the receiver's input versions as `start` does and
//! takes a recorded check only when every canon condition still holds on
//! the stored record: it passed, its source TASK stands on the recorded
//! revision, its inputs held still, the receiver's inputs match, it is not
//! world, and its PROJECT is the receiver's own (REUSE-SCOPE = B, through
//! the receiver's own live admission; a peer's claim alone never counts as
//! a pass). The receiver's record names the source attempt; completion
//! checks the tree again. With no match the door answers `None` and writes
//! nothing, so the run calls `start` and `finish` instead: the
//! force-refresh option is always there. This door never runs anything.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::checks::{validate_command, validate_declared, validate_toolchain};
use super::{RepoRunAnswer, RepoRunBinding};
use crate::EntityId;
use crate::check_record::reuse::{ReuseRequest, find_reusable_in_txn, record_reuse_in_txn};
use crate::check_record::{
    AttemptCheckRecord, CheckInputVersions, CheckProducer, CheckReuseSource, CheckReuseSourceView,
};
use crate::git_wire::GitWire;
use crate::memory::checkout_doors::refusal as checkout_refusal;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::task_verb::linear_store::task_revision_in_txn;

/// `self.code.checks.reuse`: reuses the recorded native check matching the
/// receiver's inputs. The engine captures the input versions; the agent
/// supplies the command it would run and the toolchain and environment it
/// declares. No `world` field: a world check is never reused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoCheckReuseInput {
    /// The CODE anchor the run's Grant admits; its stored repo is the served store.
    pub repo: EntityId,
    /// The full Git ref the run edits through this checkout.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The checkout id, 32 lower-hex characters.
    pub checkout: String,
    /// The live lease epoch.
    pub epoch: u64,
    /// The native command the run would run, argv in order.
    pub command: Vec<String>,
    /// The declared toolchain identities, names to values; stored and digested.
    #[serde(default)]
    pub toolchain: BTreeMap<String, String>,
    /// The declared environment, names to values; only the names are stored,
    /// the whole map is digested.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

/// The reused check: the receiver's new record, the source it names, and the
/// receiver's captured inputs.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoCheckReused {
    /// The receiver's new record id.
    pub check: EntityId,
    /// The source check this record reused instead of running.
    pub reused_from: CheckReuseSourceView,
    /// The input versions the engine captured for the receiver.
    pub inputs: CheckInputVersions,
}

/// `self.code.checks.reuse`'s answer: `None` means no recorded check
/// matches, so the run runs it with `start` and `finish`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoCheckReuseOutput {
    /// The reuse, or `None` when no recorded check matches.
    pub reused: Option<RepoCheckReused>,
}

impl Memory<'_> {
    /// `self.code.checks.reuse` for a run: admits the run's own live
    /// checkout lease, captures the receiver's input versions, and reuses
    /// the newest recorded check every canon condition still holds for. No
    /// match answers `reused: None` and writes nothing. A match mints the
    /// receiver's record with the source's observed finish and files it
    /// under the receiver's checkout for the completion re-check. The
    /// answer names the source only; no field of the peer's record rides
    /// it (DLM-004: peer status grants no read of a peer's private work).
    pub fn repo_checks_reuse_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoCheckReuseInput,
    ) -> MemoryResult<RepoRunAnswer<RepoCheckReuseOutput>> {
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
        let RepoCheckReuseInput {
            repo,
            git_ref,
            checkout,
            epoch,
            command,
            toolchain,
            environment,
        } = input;
        let producer = CheckProducer {
            attempt: own.attempt,
            generation: own.generation,
            executor_run: binding.executor_run,
            task: binding.task,
            project: own.project,
        };
        let checkout_id = own.lease.checkout_id;
        let project = own.project;
        let environment_names: Vec<String> = environment.keys().cloned().collect();
        let output = self.vault.with_write_txn_grouped(|txn| {
            let revision = task_revision_in_txn(&self.vault.store, txn, binding.task)?;
            let inputs =
                CheckInputVersions::capture(&command, &toolchain, &environment, tree, revision)?;
            let request = ReuseRequest {
                repo,
                git_ref: &git_ref,
                project,
                inputs: &inputs,
            };
            let Some(source) = find_reusable_in_txn(&self.vault.store, txn, &request)? else {
                return Ok(RepoCheckReuseOutput { reused: None });
            };
            let reused_from = CheckReuseSource {
                attempt: source.producer.attempt,
                generation: source.producer.generation,
                check: source.check,
            };
            let check = EntityId::now();
            let record = AttemptCheckRecord {
                check,
                producer,
                repo,
                git_ref,
                checkout,
                epoch,
                command,
                toolchain,
                environment_names,
                world: false,
                inputs,
                finish: source.finish,
                reused_from: Some(reused_from),
                voided: false,
            };
            record_reuse_in_txn(&self.vault.store, txn, &record, checkout_id)?;
            Ok(RepoCheckReuseOutput {
                reused: Some(RepoCheckReused {
                    check,
                    reused_from: CheckReuseSourceView::from(&reused_from),
                    inputs: record.inputs,
                }),
            })
        })?;
        Ok(RepoRunAnswer {
            rows: vec![repo],
            output,
        })
    }
}
