//! Checked queue initialization on an owner-approved baseline (FIX 6868).
//!
//! Both baseline phases run the frozen plan on the pinned baseline tree.
//! Only passing phase commands, stable inputs and complete matching
//! contract observations let the queue initialize. The checked stage is
//! durable before the existing `initialize` runs, so a crash between the
//! queue's save and the configuration's attachment only reconciles that
//! exact baseline on retry: it never initializes at another HEAD or resets
//! green. An unrelated existing queue is never adopted.
use std::collections::BTreeMap;

use super::check_execute::{held, judge_run, new_receipt};
use super::check_inputs::{
    QueueCheckExecution, QueueCheckHoldReason, QueueCheckHost, QueueCheckInputs,
    QueueCheckInvocation, QueueCheckNeed, QueueCheckReceipt, QueueCheckTarget,
};
use super::check_store::{
    QueueCheckConfiguration, QueueCheckInitStage, QueueCheckRequest, QueueCheckStatus,
    QueueCheckWork, WorkUpdate,
};
use super::plan::RepoCheckPlan;
use super::{CheckPhase, MergeQueue, REPO_CHECK_PLAN_PATH};
use crate::contract_oracle::{CommandOutput, ContractOracle, WorkspaceGraph, invalid};
use crate::error::Result;
use crate::git_wire::lock_repository;

impl MergeQueue<'_> {
    /// Runs claimed init `work`: both baseline phases of the frozen plan
    /// through `host`, the contract baseline, then the existing `initialize`
    /// at the approved baseline.
    ///
    /// # Errors
    /// A store failure or a stale completion.
    pub fn initialize_checked(
        &self,
        work: &QueueCheckWork,
        host: &mut dyn QueueCheckHost,
        stop: &dyn Fn() -> bool,
    ) -> Result<QueueCheckWork> {
        let QueueCheckRequest::Initialize {
            baseline_commit, ..
        } = &work.request
        else {
            return Err(invalid("work is not a queue initialization"));
        };
        let Some(config) = self
            .checker_configuration()?
            .filter(|config| config.baseline_commit == *baseline_commit)
        else {
            let need = QueueCheckNeed::new(&[], "no checked configuration names this baseline");
            return self.finish_status(work, QueueCheckStatus::NeedsConfiguration(need));
        };
        let plan = match config.plan.plan() {
            Ok(plan) => plan,
            Err(reason) => {
                let need = QueueCheckNeed::new(&[REPO_CHECK_PLAN_PATH], reason);
                return self.finish_status(work, QueueCheckStatus::NeedsConfiguration(need));
            }
        };
        match config.stage.clone() {
            QueueCheckInitStage::Requested => self.check_baseline(work, config, &plan, host, stop),
            QueueCheckInitStage::Checked { baseline_id }
            | QueueCheckInitStage::Initialized { baseline_id } => {
                self.attach_initialized(work, config, baseline_id)
            }
        }
    }

    fn check_baseline(
        &self,
        work: &QueueCheckWork,
        mut config: QueueCheckConfiguration,
        plan: &RepoCheckPlan,
        host: &mut dyn QueueCheckHost,
        stop: &dyn Fn() -> bool,
    ) -> Result<QueueCheckWork> {
        let environment = match host.environment() {
            Ok(environment) => environment,
            Err(need) => {
                return self.finish_status(work, QueueCheckStatus::NeedsConfiguration(need));
            }
        };
        let mut receipts = Vec::new();
        let mut observed: Option<BTreeMap<String, CommandOutput>> = None;
        for phase in [CheckPhase::Fast, CheckPhase::Slow] {
            if let Some(status) = self.baseline_moved(&config)? {
                return self.finish_baseline(work, status, receipts);
            }
            let inputs = QueueCheckInputs {
                store: self.repo.identity().as_hex(),
                repo: config.repo,
                target: QueueCheckTarget::Baseline {
                    commit: config.baseline_commit.clone(),
                    tree: config.baseline_tree.clone(),
                    phase,
                },
                baseline_id: None,
                plan_digest: config.plan.digest.clone(),
                commands: plan.phase(phase).to_vec(),
                contract_outputs: plan.contract_outputs.clone(),
                environment: environment.clone(),
            };
            let mut receipt = new_receipt(work, inputs)?;
            let tree = self.pinned_tree(&config.baseline_tree)?;
            let invocation = QueueCheckInvocation {
                target: &receipt.inputs.target,
                tree: &tree,
            };
            let execution = host.execute(&invocation, &receipt.inputs, stop)?;
            let run = match execution {
                QueueCheckExecution::Completed(run) => run,
                QueueCheckExecution::Held(hold) => {
                    receipt.hold = Some(hold.clone());
                    receipts.push(receipt);
                    return self.finish_baseline(work, QueueCheckStatus::Held(hold), receipts);
                }
                QueueCheckExecution::NeedsConfiguration(need) => {
                    receipt.need = Some(need.clone());
                    receipts.push(receipt);
                    let status = QueueCheckStatus::NeedsConfiguration(need);
                    return self.finish_baseline(work, status, receipts);
                }
            };
            let judged = judge_run(&receipt.inputs, &run);
            receipt.run = Some(run);
            let (passed, outputs) = match judged {
                Ok(judged) => judged,
                Err(hold) => {
                    receipt.hold = Some(hold.clone());
                    receipts.push(receipt);
                    return self.finish_baseline(work, QueueCheckStatus::Held(hold), receipts);
                }
            };
            receipt.tests_passed = Some(passed);
            receipts.push(receipt);
            if !passed {
                let status = QueueCheckStatus::Completed { passed: false };
                return self.finish_baseline(work, status, receipts);
            }
            if observed.as_ref().is_some_and(|earlier| *earlier != outputs) {
                let status = held(
                    QueueCheckHoldReason::UnstableInputs,
                    "the contract outputs differ between the fast and slow phases".to_owned(),
                );
                return self.finish_baseline(work, status, receipts);
            }
            observed = Some(outputs);
        }
        if let Some(status) = self.baseline_moved(&config)? {
            return self.finish_baseline(work, status, receipts);
        }
        let oracle = ContractOracle::new(self.vault);
        let snapshot = ContractOracle::capture(
            &plan.contracts,
            self.repo.repo_root(),
            observed.unwrap_or_default(),
        )?;
        let baseline_id = match &config.contract_baseline_ref {
            None => oracle.record_baseline(plan.contracts.clone(), snapshot)?.id,
            Some(reference) => {
                let Some(existing) = oracle.baseline(reference)? else {
                    let need = QueueCheckNeed::new(
                        &[],
                        "contract_baseline_ref names no recorded contract baseline",
                    );
                    let status = QueueCheckStatus::NeedsConfiguration(need);
                    return self.finish_baseline(work, status, receipts);
                };
                if existing.spec != plan.contracts {
                    let need = QueueCheckNeed::new(
                        &[REPO_CHECK_PLAN_PATH],
                        "the plan's contracts are not the named contract baseline's; none is dropped",
                    );
                    let status = QueueCheckStatus::NeedsConfiguration(need);
                    return self.finish_baseline(work, status, receipts);
                }
                let candidate = format!(
                    "queue-check-baseline:v1:{}:{}",
                    config.plan.digest, config.baseline_commit
                );
                let verdict = oracle.compare_and_record(reference, &candidate, &snapshot, true)?;
                if !verdict.passes() {
                    let mut update =
                        WorkUpdate::ending(QueueCheckStatus::Completed { passed: false }, receipts);
                    update.verdict_ref = Some(verdict.id);
                    return self.vault.finish_queue_check(work, update);
                }
                reference.clone()
            }
        };
        config.stage = QueueCheckInitStage::Checked {
            baseline_id: baseline_id.clone(),
        };
        let update = WorkUpdate {
            receipts,
            config: Some(&config),
            ..WorkUpdate::default()
        };
        let work = self.vault.finish_queue_check(work, update)?;
        if work.status != QueueCheckStatus::Running {
            return Ok(work);
        }
        self.attach_initialized(&work, config, baseline_id)
    }

    /// Initializes the queue at the checked baseline, or reconciles the one
    /// a crash left between the queue's save and this attachment.
    fn attach_initialized(
        &self,
        work: &QueueCheckWork,
        mut config: QueueCheckConfiguration,
        baseline_id: String,
    ) -> Result<QueueCheckWork> {
        let _guard = lock_repository(self.repo.common_dir())?;
        if let Some(status) = self.baseline_moved(&config)? {
            return self.finish_status(work, status);
        }
        if !self.claimed_work_holds(work)? {
            return self.finish_status(
                work,
                held(
                    QueueCheckHoldReason::Authority,
                    "the owner's queued approval or this run's lease no longer holds".to_owned(),
                ),
            );
        }
        let pointers = match self.read_queue()? {
            Some(queue)
                if queue.baseline_id == baseline_id
                    && queue.pointers.green == config.baseline_commit =>
            {
                queue.pointers
            }
            Some(_) => {
                let need = QueueCheckNeed::new(
                    &[],
                    "this repository already has a queue the checked init does not adopt",
                );
                return self.finish_status(work, QueueCheckStatus::NeedsConfiguration(need));
            }
            None => self.initialize(&baseline_id, WorkspaceGraph::unfiltered())?,
        };
        config.stage = QueueCheckInitStage::Initialized { baseline_id };
        self.vault.finish_queue_check(
            work,
            WorkUpdate {
                status: Some(QueueCheckStatus::Completed { passed: true }),
                pointers: Some(pointers),
                config: Some(&config),
                ..WorkUpdate::default()
            },
        )
    }

    /// The hold a baseline check takes when the repository is no longer at
    /// the approved baseline, clean.
    fn baseline_moved(&self, config: &QueueCheckConfiguration) -> Result<Option<QueueCheckStatus>> {
        let moved = self.head()? != config.baseline_commit
            || self.tree()? != config.baseline_tree
            || self.require_clean(self.repo.repo_root()).is_err();
        Ok(moved.then(|| {
            held(
                QueueCheckHoldReason::UnstableInputs,
                "the repository is no longer at the approved baseline, clean".to_owned(),
            )
        }))
    }

    fn finish_baseline(
        &self,
        work: &QueueCheckWork,
        status: QueueCheckStatus,
        receipts: Vec<QueueCheckReceipt>,
    ) -> Result<QueueCheckWork> {
        self.vault
            .finish_queue_check(work, WorkUpdate::ending(status, receipts))
    }
}
