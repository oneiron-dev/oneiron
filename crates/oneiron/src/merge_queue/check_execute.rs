//! One check execution body for both check paths (FIX 6868): the low-level
//! callback `check` and the bound `check_with_inputs`. They share the staged
//! path resolution, the verdict slot settlement and the binding comparison
//! `all_paths_green` and `settle_slow` read; only the bound path runs the
//! frozen plan through a [`QueueCheckHost`] and keeps a receipt.
use std::collections::BTreeMap;

use super::check_inputs::{
    QUEUE_CHECK_CANDIDATE_PREFIX, QueueCheckExecution, QueueCheckHold, QueueCheckHoldReason,
    QueueCheckHost, QueueCheckInputs, QueueCheckInvocation, QueueCheckNeed, QueueCheckReceipt,
    QueueCheckRun, QueueCheckTarget,
};
use super::check_store::{
    QueueCheckConfiguration, QueueCheckRequest, QueueCheckStatus, QueueCheckWork, WorkUpdate,
};
use super::plan::RepoCheckPlan;
use super::{BatchState, CheckPhase, MergeBatch, MergeQueue, SpeculativePath};
use crate::Vault;
use crate::codebase::RepoRef;
use crate::contract_oracle::{CommandOutput, ContractOracle, ContractVerdict, invalid};
use crate::error::{Error, Result};
use crate::git_wire::lock_repository;

impl MergeQueue<'_> {
    /// The staged path a check of `phase` on `mask` runs on, and the verdict
    /// its slot already holds. A slow check names the landed batch and runs
    /// on its landed checkout.
    pub(super) fn check_path(
        &self,
        batch: &MergeBatch,
        mask: u64,
        phase: CheckPhase,
    ) -> Result<(SpeculativePath, Option<String>)> {
        let mut path = batch
            .paths
            .iter()
            .find(|path| path.mask == mask)
            .ok_or_else(|| invalid("speculative path not staged"))?
            .clone();
        let prior = match phase {
            CheckPhase::Fast => path.verdict.clone(),
            CheckPhase::Slow => {
                if mask != self.landed_path(batch)?.mask || batch.state != BatchState::HeadAdvanced
                {
                    return Err(invalid("slow check must name the landed full batch"));
                }
                batch.slow_verdict.clone()
            }
        };
        if prior.is_none() {
            if phase == CheckPhase::Fast
                && !matches!(batch.state, BatchState::Staged | BatchState::Ready)
            {
                return Err(invalid("batch is not accepting fast checks"));
            }
            if phase == CheckPhase::Slow {
                path = self.landed_check_path(batch, &path)?;
            }
        }
        Ok((path, prior))
    }

    /// Fills the current batch's verdict slot for `phase` on `mask` with
    /// `verdict`, under the repository lock the caller holds. A fast batch
    /// whose every path now passes is ready. `pending` is a receipt whose
    /// verdict is not stored with its work yet.
    pub(super) fn settle_slot(
        &self,
        current: &mut MergeBatch,
        mask: u64,
        phase: CheckPhase,
        commit: &str,
        verdict: &str,
        pending: Option<&QueueCheckReceipt>,
    ) -> Result<()> {
        let slot = match phase {
            CheckPhase::Fast => {
                if !matches!(current.state, BatchState::Staged | BatchState::Ready) {
                    return Err(Error::ConcurrentWrite("batch changed during fast check"));
                }
                &mut current.paths[(mask - 1) as usize].verdict
            }
            CheckPhase::Slow => {
                if current.state != BatchState::HeadAdvanced
                    || current.landed_head.as_deref() != Some(commit)
                {
                    return Err(Error::ConcurrentWrite("batch changed during slow check"));
                }
                &mut current.slow_verdict
            }
        };
        if let Some(prior) = slot {
            if prior != verdict {
                return Err(Error::ConcurrentWrite(
                    "check already settled with another result",
                ));
            }
        } else {
            *slot = Some(verdict.to_owned());
        }
        if phase == CheckPhase::Fast && self.all_paths_green_with(current, pending)? {
            current.state = BatchState::Ready;
        }
        Ok(())
    }

    /// Whether stored `verdict` binds `batch`'s path `mask` on `tree` for
    /// `phase`; `commit` is the speculative commit of a fast check and the
    /// landed one of a slow check. A verdict the low-level callback path
    /// recorded keeps today's comparison. A bound verdict's receipt must
    /// rebuild from the frozen configuration and this exact path to the
    /// digest its candidate names.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn require_check_binding(
        &self,
        batch: &MergeBatch,
        mask: u64,
        tree: &str,
        commit: &str,
        phase: CheckPhase,
        verdict: &ContractVerdict,
        pending: Option<&QueueCheckReceipt>,
    ) -> Result<bool> {
        if verdict.baseline_id != batch.baseline_id {
            return Ok(false);
        }
        let Some(digest) = verdict.candidate.strip_prefix(QUEUE_CHECK_CANDIDATE_PREFIX) else {
            let expected = match phase {
                CheckPhase::Fast => format!("{}:{mask}:Fast:{tree}", batch.id),
                CheckPhase::Slow => format!("{}:{mask}:Slow:{tree}:{commit}", batch.id),
            };
            return Ok(verdict.candidate == expected);
        };
        let receipt = match pending.filter(|receipt| {
            receipt.inputs_digest == digest
                && receipt.verdict_ref.as_deref() == Some(verdict.id.as_str())
        }) {
            Some(receipt) => receipt.clone(),
            None => match self.bound_receipt(digest, &verdict.id)? {
                Some(receipt) => receipt,
                None => return Ok(false),
            },
        };
        let Some(config) = self.checker_configuration()? else {
            return Ok(false);
        };
        let Ok(plan) = config.plan.plan() else {
            return Ok(false);
        };
        let rebuilt = QueueCheckInputs {
            store: self.repo.identity().as_hex(),
            repo: config.repo,
            target: QueueCheckTarget::Candidate {
                batch: batch.id.clone(),
                mask,
                phase,
                commit: commit.to_owned(),
                tree: tree.to_owned(),
            },
            baseline_id: Some(batch.baseline_id.clone()),
            plan_digest: config.plan.digest.clone(),
            commands: plan.phase(phase).to_vec(),
            contract_outputs: plan.contract_outputs.clone(),
            environment: receipt.inputs.environment.clone(),
        };
        Ok(rebuilt.digest()? == digest && receipt.inputs.digest()? == digest)
    }

    /// `check` with the bound inputs of claimed check `work`: the frozen
    /// plan's phase commands on the exact staged path, run through `host`,
    /// with a receipt bound to the verdict's candidate key. A held or
    /// unconfigured execution records no verdict.
    ///
    /// # Errors
    /// A store failure or a stale completion.
    pub fn check_with_inputs(
        &self,
        work: &QueueCheckWork,
        host: &mut dyn QueueCheckHost,
        stop: &dyn Fn() -> bool,
    ) -> Result<QueueCheckWork> {
        let QueueCheckRequest::Check {
            batch,
            mask,
            phase,
            force_refresh,
        } = &work.request
        else {
            return Err(invalid("work is not a queue check"));
        };
        let (config, plan) = match self.checked_plan()? {
            Ok(found) => found,
            Err(need) => {
                return self.finish_status(work, QueueCheckStatus::NeedsConfiguration(need));
            }
        };
        let step = BoundCheck {
            batch: batch.clone(),
            mask: *mask,
            phase: *phase,
            force_refresh: *force_refresh,
            inline: false,
        };
        self.bound_step(work, &config, &plan, &step, host, stop)
    }

    /// The initialized configuration and its decoded plan, or the need a
    /// bound check names without them.
    pub(super) fn checked_plan(
        &self,
    ) -> Result<std::result::Result<(QueueCheckConfiguration, RepoCheckPlan), QueueCheckNeed>> {
        let config = match self.initialized_configuration()? {
            Ok(config) => config,
            Err(need) => return Ok(Err(need)),
        };
        Ok(match config.plan.plan() {
            Ok(plan) => Ok((config, plan)),
            Err(reason) => Err(QueueCheckNeed::new(&[super::REPO_CHECK_PLAN_PATH], reason)),
        })
    }

    /// One bound fast or slow check of claimed `work`; the work as it then
    /// stands. An inline step that reached a verdict leaves it running.
    pub(super) fn bound_step(
        &self,
        work: &QueueCheckWork,
        config: &QueueCheckConfiguration,
        plan: &RepoCheckPlan,
        step: &BoundCheck,
        host: &mut dyn QueueCheckHost,
        stop: &dyn Fn() -> bool,
    ) -> Result<QueueCheckWork> {
        let batch = self.batch(&step.batch)?;
        let (path, prior) = self.check_path(&batch, step.mask, step.phase)?;
        if let Some(verdict_ref) = prior {
            let status = QueueCheckStatus::Settled {
                verdict_ref: verdict_ref.clone(),
            };
            return self.finish_step(work, step, status, None, Some(verdict_ref), None);
        }
        let environment = match host.environment() {
            Ok(environment) => environment,
            Err(need) => {
                let status = QueueCheckStatus::NeedsConfiguration(need);
                return self.finish_step(work, step, status, None, None, None);
            }
        };
        let inputs = QueueCheckInputs {
            store: self.repo.identity().as_hex(),
            repo: config.repo,
            target: QueueCheckTarget::Candidate {
                batch: batch.id.clone(),
                mask: step.mask,
                phase: step.phase,
                commit: path.commit.clone(),
                tree: path.tree.clone(),
            },
            baseline_id: Some(batch.baseline_id.clone()),
            plan_digest: config.plan.digest.clone(),
            commands: plan.phase(step.phase).to_vec(),
            contract_outputs: plan.contract_outputs.clone(),
            environment,
        };
        let mut receipt = new_receipt(work, inputs)?;
        if !step.force_refresh
            && receipt.inputs.reusable()
            && let Some(prior) = self.reusable_receipt(&receipt.inputs_digest)?
        {
            receipt.reused_from = Some(prior.inputs_digest);
            receipt.tests_passed = prior.tests_passed;
            receipt.verdict_ref = prior.verdict_ref;
        }
        if receipt.verdict_ref.is_none() {
            if let Some(status) = self.run_bound(&batch, &path, &mut receipt, host, stop)? {
                return self.finish_step(work, step, status, Some(receipt), None, None);
            }
        }
        let verdict_ref = receipt
            .verdict_ref
            .clone()
            .ok_or(Error::InvariantViolation("bound check has no verdict"))?;
        let passed = ContractOracle::new(self.vault)
            .verdict(&verdict_ref)?
            .ok_or(Error::CorruptedIndex("merge verdict is missing"))?
            .passes();
        let _guard = lock_repository(self.repo.common_dir())?;
        let mut current = self.batch(&step.batch)?;
        if let Err(error) = self.settle_slot(
            &mut current,
            step.mask,
            step.phase,
            &path.commit,
            &verdict_ref,
            Some(&receipt),
        ) {
            let status = QueueCheckStatus::Held(QueueCheckHold::new(
                QueueCheckHoldReason::Refused,
                error.to_string(),
            ));
            return self.finish_step(work, step, status, Some(receipt), None, None);
        }
        let status = QueueCheckStatus::Completed { passed };
        let key = self.batch_key(&current.id);
        self.finish_step(
            work,
            step,
            status,
            Some(receipt),
            Some(verdict_ref),
            Some((key, &current)),
        )
    }

    /// Runs `receipt`'s commands on `path` and records the verdict, or the
    /// status that keeps the work without one.
    fn run_bound(
        &self,
        batch: &MergeBatch,
        path: &SpeculativePath,
        receipt: &mut QueueCheckReceipt,
        host: &mut dyn QueueCheckHost,
        stop: &dyn Fn() -> bool,
    ) -> Result<Option<QueueCheckStatus>> {
        if let Err(error) = self.verify_worktree(path) {
            return Ok(Some(held(
                QueueCheckHoldReason::TreeUnavailable,
                format!("the staged path is not as tested: {error}"),
            )));
        }
        let tree = self.pinned_tree(&path.tree)?;
        let invocation = QueueCheckInvocation {
            target: &receipt.inputs.target,
            tree: &tree,
        };
        let run = match host.execute(&invocation, &receipt.inputs, stop)? {
            QueueCheckExecution::Completed(run) => run,
            QueueCheckExecution::Held(hold) => {
                receipt.hold = Some(hold.clone());
                return Ok(Some(QueueCheckStatus::Held(hold)));
            }
            QueueCheckExecution::NeedsConfiguration(need) => {
                receipt.need = Some(need.clone());
                return Ok(Some(QueueCheckStatus::NeedsConfiguration(need)));
            }
        };
        let judged = judge_run(&receipt.inputs, &run);
        receipt.run = Some(run);
        let (tests_passed, outputs) = match judged {
            Ok(judged) => judged,
            Err(hold) => {
                receipt.hold = Some(hold.clone());
                return Ok(Some(QueueCheckStatus::Held(hold)));
            }
        };
        if let Err(error) = self.verify_worktree(path) {
            let hold = QueueCheckHold::new(
                QueueCheckHoldReason::UnstableInputs,
                format!("the staged path changed while it was checked: {error}"),
            );
            receipt.hold = Some(hold.clone());
            return Ok(Some(QueueCheckStatus::Held(hold)));
        }
        let oracle = ContractOracle::new(self.vault);
        let baseline = oracle
            .baseline(&batch.baseline_id)?
            .ok_or(Error::CorruptedIndex("merge baseline is missing"))?;
        let snapshot = ContractOracle::capture(&baseline.spec, &path.worktree, outputs)?;
        self.verify_worktree(path)?;
        let verdict = oracle.compare_and_record(
            &batch.baseline_id,
            &receipt.inputs.candidate_key()?,
            &snapshot,
            tests_passed,
        )?;
        receipt.tests_passed = Some(tests_passed);
        receipt.verdict_ref = Some(verdict.id);
        Ok(None)
    }

    /// Commits one bound step: a whole check ends its work; an inline step
    /// of a diagnosis keeps it running unless it could not reach a verdict.
    #[allow(clippy::too_many_arguments)]
    fn finish_step(
        &self,
        work: &QueueCheckWork,
        step: &BoundCheck,
        status: QueueCheckStatus,
        receipt: Option<QueueCheckReceipt>,
        verdict_ref: Option<String>,
        batch: Option<(String, &MergeBatch)>,
    ) -> Result<QueueCheckWork> {
        let ends = !step.inline
            || !matches!(
                status,
                QueueCheckStatus::Completed { .. } | QueueCheckStatus::Settled { .. }
            );
        self.vault.finish_queue_check(
            work,
            WorkUpdate {
                status: ends.then_some(status),
                receipts: receipt.into_iter().collect(),
                verdict_ref,
                batch,
                ..WorkUpdate::default()
            },
        )
    }

    /// Ends claimed `work` with `status` and nothing else.
    pub(super) fn finish_status(
        &self,
        work: &QueueCheckWork,
        status: QueueCheckStatus,
    ) -> Result<QueueCheckWork> {
        self.vault.finish_queue_check(
            work,
            WorkUpdate {
                status: Some(status),
                ..WorkUpdate::default()
            },
        )
    }
}

/// One bound check a work runs: its batch path and phase, and whether it is
/// an inline step of a longer work.
pub(super) struct BoundCheck {
    pub(super) batch: String,
    pub(super) mask: u64,
    pub(super) phase: CheckPhase,
    pub(super) force_refresh: bool,
    pub(super) inline: bool,
}

/// A fresh receipt of claimed `work` for `inputs`.
pub(super) fn new_receipt(
    work: &QueueCheckWork,
    inputs: QueueCheckInputs,
) -> Result<QueueCheckReceipt> {
    let lease = work
        .lease
        .clone()
        .ok_or(Error::InvariantViolation("an unclaimed queue check ran"))?;
    Ok(QueueCheckReceipt {
        inputs_digest: inputs.digest()?,
        inputs,
        attempt: work
            .attempt
            .ok_or(Error::InvariantViolation("an unclaimed queue check ran"))?,
        attempt_count: lease.attempt_count,
        lease_owner: lease.owner,
        generation: work.generation,
        run: None,
        hold: None,
        need: None,
        reused_from: None,
        tests_passed: None,
        verdict_ref: None,
    })
}

pub(super) fn held(reason: QueueCheckHoldReason, detail: String) -> QueueCheckStatus {
    QueueCheckStatus::Held(QueueCheckHold::new(reason, detail))
}

/// A completed run's phase result and contract observations. Phase
/// commands pass when every one exited zero; a nonzero exit is red. A
/// contract-output command's status is observed data, whatever it is. A run
/// that ended without a terminal status, or whose inputs changed, is held.
pub(super) fn judge_run(
    inputs: &QueueCheckInputs,
    run: &QueueCheckRun,
) -> std::result::Result<(bool, BTreeMap<String, CommandOutput>), QueueCheckHold> {
    if run.input_before != run.input_after {
        return Err(QueueCheckHold::new(
            QueueCheckHoldReason::UnstableInputs,
            "the input files changed while the commands ran",
        ));
    }
    let red = run.commands.iter().any(|command| !command.exited_zero());
    if !red && run.commands.len() != inputs.commands.len() {
        return Err(QueueCheckHold::new(
            QueueCheckHoldReason::Interrupted,
            "the executor ended before every phase command ran",
        ));
    }
    if run
        .commands
        .iter()
        .any(|command| command.status.is_none() && command.signal.is_none())
    {
        return Err(QueueCheckHold::new(
            QueueCheckHoldReason::Interrupted,
            "a phase command ended without a terminal status",
        ));
    }
    if !run
        .contract_outputs
        .keys()
        .eq(inputs.contract_outputs.keys())
    {
        return Err(QueueCheckHold::new(
            QueueCheckHoldReason::Interrupted,
            "the executor did not observe every contract output",
        ));
    }
    let mut outputs = BTreeMap::new();
    for (name, command) in &run.contract_outputs {
        let Some(status) = command.status else {
            return Err(QueueCheckHold::new(
                QueueCheckHoldReason::Interrupted,
                format!("contract output {name} ended without an exit status"),
            ));
        };
        outputs.insert(
            name.clone(),
            CommandOutput {
                status,
                stdout: command.stdout.clone(),
                stderr: command.stderr.clone(),
            },
        );
    }
    Ok((!red, outputs))
}

impl Vault {
    /// Runs claimed checker `work` through `host` to its next status: a
    /// checked init, a bound check or a diagnosis. An engine refusal of the
    /// work in its queue's current state holds the work with its reason;
    /// nothing goes green.
    ///
    /// # Errors
    /// A store failure or a stale completion.
    pub fn run_queue_check(
        &self,
        work: &QueueCheckWork,
        host: &mut dyn QueueCheckHost,
        stop: &dyn Fn() -> bool,
    ) -> Result<QueueCheckWork> {
        let ran = RepoRef::parse(&work.repo_ref)
            .and_then(|repo_ref| MergeQueue::open(self, repo_ref))
            .and_then(|queue| match &work.request {
                QueueCheckRequest::Initialize { .. } => queue.initialize_checked(work, host, stop),
                QueueCheckRequest::Check { .. } => queue.check_with_inputs(work, host, stop),
                QueueCheckRequest::Diagnose { .. } => queue.diagnose_checked(work, host, stop),
            });
        match ran {
            Ok(done) => Ok(done),
            Err(error) => self.finish_queue_check(
                work,
                WorkUpdate {
                    status: Some(held(QueueCheckHoldReason::Refused, error.to_string())),
                    ..WorkUpdate::default()
                },
            ),
        }
    }
}
