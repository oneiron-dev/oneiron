//! The owner's checker requests and the bound diagnosis (FIX 6868).
//!
//! A request writes durable work before anything runs; the standalone
//! checker drain runs it. A request names no argv, plan body, output, pass
//! or receipt: the plan is the one frozen from the approved baseline.
use super::check_execute::{BoundCheck, held};
use super::check_inputs::{QueueCheckHoldReason, QueueCheckHost, QueueCheckNeed};
use super::check_store::{
    ConfigWrite, QueueCheckConfigDraft, QueueCheckRequest, QueueCheckStatus, QueueCheckWork,
    WorkUpdate,
};
use super::plan::FrozenCheckPlan;
use super::{CheckPhase, MergeQueue, REPO_CHECK_PLAN_PATH};
use crate::EntityId;
use crate::consent::QueuedCheckApproval;
use crate::contract_oracle::invalid;
use crate::error::Result;
use crate::git_wire::{GitOid, lock_repository};

impl MergeQueue<'_> {
    /// Requests checked initialization at `baseline_commit`, the clean
    /// HEAD the owner approved: the plan is read from that commit and
    /// frozen with the owner's queued approval. A missing or invalid plan
    /// keeps the work with its need. The same baseline asked again renews
    /// the approval; another baseline is no reinitialization, and an
    /// existing unchecked queue is never adopted.
    ///
    /// # Errors
    /// A malformed request or a store failure.
    pub(crate) fn request_initialization(
        &self,
        repo: EntityId,
        baseline_commit: &str,
        contract_baseline_ref: Option<String>,
        approve: impl FnOnce(&heed::RoTxn<'_>, &str) -> Result<QueuedCheckApproval>,
    ) -> Result<QueueCheckWork> {
        let baseline_commit = GitOid::parse_hex(baseline_commit)?.as_str().to_owned();
        if let Some(reference) = &contract_baseline_ref
            && (reference.len() != 64 || !reference.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(invalid(
                "contract_baseline_ref must be a contract baseline digest",
            ));
        }
        let request = QueueCheckRequest::Initialize {
            baseline_commit: baseline_commit.clone(),
            contract_baseline_ref: contract_baseline_ref.clone(),
        };
        let _guard = lock_repository(self.repo.common_dir())?;
        if let Some(config) = self.checker_configuration()? {
            if config.baseline_commit != baseline_commit
                || config.contract_baseline_ref != contract_baseline_ref
            {
                return Err(invalid(
                    "this repository has a checked configuration at another baseline",
                ));
            }
            return self.submit_check_work(repo, request, ConfigWrite::Renew, None, approve);
        }
        if self.read_queue()?.is_some() {
            let need = QueueCheckNeed::new(
                &[],
                "this queue was initialized without a checked configuration; its pointers and doors are unchanged",
            );
            return self.submit_check_work(repo, request, ConfigWrite::None, Some(need), approve);
        }
        if self.head()? != baseline_commit {
            return Err(invalid(
                "baseline_commit must be the repository's current HEAD",
            ));
        }
        let baseline_tree = self.commit_tree(&baseline_commit)?;
        let Some(bytes) = self.tree_file(&baseline_tree, REPO_CHECK_PLAN_PATH)? else {
            let need = QueueCheckNeed::new(
                &[REPO_CHECK_PLAN_PATH],
                format!("{REPO_CHECK_PLAN_PATH} is absent at the baseline commit"),
            );
            return self.submit_check_work(repo, request, ConfigWrite::None, Some(need), approve);
        };
        let plan = FrozenCheckPlan::freeze(bytes);
        if let Err(reason) = plan.plan() {
            let need = QueueCheckNeed::new(&[REPO_CHECK_PLAN_PATH], reason);
            return self.submit_check_work(repo, request, ConfigWrite::None, Some(need), approve);
        }
        let draft = QueueCheckConfigDraft {
            baseline_commit,
            baseline_tree,
            plan,
            contract_baseline_ref,
        };
        self.submit_check_work(
            repo,
            request,
            ConfigWrite::Create(Box::new(draft)),
            None,
            approve,
        )
    }

    /// Requests one fast or slow check of a staged path on the frozen plan.
    /// A matching passing receipt may stand unless `force_refresh`. A queue
    /// with no checked configuration keeps the work with that need.
    ///
    /// # Errors
    /// A malformed request or a store failure.
    pub(crate) fn request_check(
        &self,
        repo: EntityId,
        batch: &str,
        mask: u64,
        phase: CheckPhase,
        force_refresh: bool,
        approve: impl FnOnce(&heed::RoTxn<'_>, &str) -> Result<QueuedCheckApproval>,
    ) -> Result<QueueCheckWork> {
        let staged = self.batch(batch)?;
        if !staged.paths.iter().any(|path| path.mask == mask) {
            return Err(invalid("speculative path not staged"));
        }
        let request = QueueCheckRequest::Check {
            batch: batch.to_owned(),
            mask,
            phase,
            force_refresh,
        };
        self.request_configured(repo, request, approve)
    }

    /// Requests the diagnosis of a red batch: its missing fast checks run
    /// bound to the frozen plan, then the existing minimal quarantine
    /// reads only stored results.
    ///
    /// # Errors
    /// A malformed request or a store failure.
    pub(crate) fn request_diagnosis(
        &self,
        repo: EntityId,
        batch: &str,
        approve: impl FnOnce(&heed::RoTxn<'_>, &str) -> Result<QueuedCheckApproval>,
    ) -> Result<QueueCheckWork> {
        self.batch(batch)?;
        let request = QueueCheckRequest::Diagnose {
            batch: batch.to_owned(),
        };
        self.request_configured(repo, request, approve)
    }

    fn request_configured(
        &self,
        repo: EntityId,
        request: QueueCheckRequest,
        approve: impl FnOnce(&heed::RoTxn<'_>, &str) -> Result<QueuedCheckApproval>,
    ) -> Result<QueueCheckWork> {
        match self.initialized_configuration()? {
            Ok(_) => self.submit_check_work(repo, request, ConfigWrite::Renew, None, approve),
            Err(need) => {
                self.submit_check_work(repo, request, ConfigWrite::None, Some(need), approve)
            }
        }
    }

    /// Runs claimed diagnosis `work`: every missing fast check of its batch
    /// bound to the frozen plan, then the existing `diagnose_red` over the
    /// stored results alone. Its callback never runs an unbound check.
    ///
    /// # Errors
    /// A store failure or a stale completion.
    pub fn diagnose_checked(
        &self,
        work: &QueueCheckWork,
        host: &mut dyn QueueCheckHost,
        stop: &dyn Fn() -> bool,
    ) -> Result<QueueCheckWork> {
        let QueueCheckRequest::Diagnose { batch: id } = &work.request else {
            return Err(invalid("work is not a queue diagnosis"));
        };
        let (config, plan) = match self.checked_plan()? {
            Ok(found) => found,
            Err(need) => {
                return self.finish_status(work, QueueCheckStatus::NeedsConfiguration(need));
            }
        };
        let batch = self.batch(id)?;
        let mut work = work.clone();
        if batch.quarantine.is_none() {
            for path in batch.paths.iter().filter(|path| path.verdict.is_none()) {
                if stop() {
                    let status = held(
                        QueueCheckHoldReason::Interrupted,
                        "the host stopped during diagnosis".to_owned(),
                    );
                    return self.finish_status(&work, status);
                }
                let step = BoundCheck {
                    batch: id.clone(),
                    mask: path.mask,
                    phase: CheckPhase::Fast,
                    force_refresh: false,
                    inline: true,
                };
                work = self.bound_step(&work, &config, &plan, &step, host, stop)?;
                if work.status != QueueCheckStatus::Running {
                    return Ok(work);
                }
            }
            if self.all_paths_green(&self.batch(id)?)? {
                return self.finish_status(&work, QueueCheckStatus::Completed { passed: true });
            }
        }
        let quarantine = self.diagnose_red(
            id,
            &mut |_: &super::CheckInvocation| -> Result<super::CheckReport> {
                Err(invalid("a checked diagnosis runs no unbound check"))
            },
        )?;
        let verdict = quarantine.verdict.clone();
        self.vault.finish_queue_check(
            &work,
            WorkUpdate {
                status: Some(QueueCheckStatus::Completed { passed: false }),
                verdict_ref: Some(verdict),
                quarantine: Some(quarantine),
                ..WorkUpdate::default()
            },
        )
    }
}
