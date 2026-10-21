//! The owner's checker doors (FIX 6868): request checked initialization, a
//! bound fast or slow check and a bound diagnosis, and read their work.
//! Each one writes durable work and returns it at once; the standalone
//! server drain runs it. Authority is the owner's live proof, checked
//! before any id resolves; the queued approval a request writes is minted
//! from that proof in the writing transaction. No agent and no run holds it.
use super::*;
use crate::merge_queue::{
    QUEUE_CHECK_CANDIDATE_PREFIX, QueueCheckConfiguration, QueueCheckRequest, QueueCheckStatus,
    QueueCheckWork,
};

impl Memory<'_> {
    /// `vault.code.merge_queue.init`: requests owner-approved baseline
    /// checks and checked initialization from the plan pinned at
    /// `baseline_commit`. A missing plan keeps the work with its need; an
    /// existing queue is never reset.
    pub fn merge_queue_init_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueInitializeRequest,
    ) -> MemoryResult<MergeQueueCheckWorkView> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        // A served anchor's import becomes its queue source here (FIX 6869).
        let prepared = self.vault.prepare_queue_initialization(
            owner,
            repo.repo,
            &repo.repo_ref,
            &input.baseline_commit,
            input.contract_baseline_ref.as_deref(),
        )?;
        let queue = prepared.queue;
        let work = queue.request_initialization(
            repo.repo,
            &input.baseline_commit,
            input.contract_baseline_ref,
            prepared.source,
            |txn, digest| owner.queue_check_approval_in_txn(self.vault, txn, repo.repo, digest),
        )?;
        Ok(check_work_view(queue.checker_configuration()?, work))
    }

    /// `vault.code.merge_queue.check`: queues one fast or slow check on the
    /// exact staged inputs. A check past the repository's active one waits.
    pub fn merge_queue_check_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueCheckRequest,
    ) -> MemoryResult<MergeQueueCheckWorkView> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        let queue = self.merge_queue_of(&repo)?;
        let work = queue.request_check(
            repo.repo,
            &input.batch_ref,
            input.mask,
            input.phase.into(),
            input.force_refresh,
            |txn, digest| owner.queue_check_approval_in_txn(self.vault, txn, repo.repo, digest),
        )?;
        Ok(check_work_view(queue.checker_configuration()?, work))
    }

    /// `vault.code.merge_queue.diagnose`: queues the bound fast checks a
    /// red batch's diagnosis needs, then the existing minimal quarantine.
    pub fn merge_queue_diagnose_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueDiagnoseRequest,
    ) -> MemoryResult<MergeQueueCheckWorkView> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        let queue = self.merge_queue_of(&repo)?;
        let work = queue.request_diagnosis(repo.repo, &input.batch_ref, |txn, digest| {
            owner.queue_check_approval_in_txn(self.vault, txn, repo.repo, digest)
        })?;
        Ok(check_work_view(queue.checker_configuration()?, work))
    }

    /// `vault.code.merge_queue.check_status`: reads one checker work row,
    /// an init's before its queue exists included.
    pub fn merge_queue_check_status_as(
        &self,
        owner: &AuthenticatedOwner,
        input: MergeQueueCheckStatusRequest,
    ) -> MemoryResult<MergeQueueCheckWorkView> {
        self.merge_queue_owner(owner)?;
        let repo = self.merge_queue_repo(input.repo)?;
        // Read by the admitted store, so no materialized tree is needed.
        let store = repo.identity.as_hex();
        let work = self
            .vault
            .queue_check_work_of(&store, &input.work_ref)?
            .ok_or_else(|| MemoryError::not_found("merge queue checker work not found"))?;
        Ok(check_work_view(
            self.vault.queue_check_configuration_of(&store)?,
            work,
        ))
    }
}

/// A work row as the wire carries it: statuses, keys and references, never
/// host paths, plan command bodies or command exhaust.
pub(crate) fn check_work_view(
    config: Option<QueueCheckConfiguration>,
    work: QueueCheckWork,
) -> MergeQueueCheckWorkView {
    let work_ref = work.work_ref().to_owned();
    let (kind, requested_baseline) = match &work.request {
        QueueCheckRequest::Initialize {
            baseline_commit, ..
        } => (MergeQueueCheckWorkKind::Init, Some(baseline_commit.clone())),
        QueueCheckRequest::Check { .. } => (MergeQueueCheckWorkKind::Check, None),
        QueueCheckRequest::Diagnose { .. } => (MergeQueueCheckWorkKind::Diagnose, None),
    };
    let (status, configuration_keys, reason, hold) = match work.status {
        QueueCheckStatus::Queued => (MergeQueueCheckState::Queued, Vec::new(), None, None),
        QueueCheckStatus::Running => (MergeQueueCheckState::Running, Vec::new(), None, None),
        QueueCheckStatus::NeedsConfiguration(need) => (
            MergeQueueCheckState::NeedsConfiguration,
            need.keys,
            Some(need.reason),
            None,
        ),
        QueueCheckStatus::Held(held) => (
            MergeQueueCheckState::Held,
            Vec::new(),
            Some(held.detail),
            Some(held.reason),
        ),
        QueueCheckStatus::Completed { passed: true } => {
            (MergeQueueCheckState::Passed, Vec::new(), None, None)
        }
        QueueCheckStatus::Completed { passed: false } => {
            (MergeQueueCheckState::Failed, Vec::new(), None, None)
        }
        QueueCheckStatus::Settled { .. } => (MergeQueueCheckState::Settled, Vec::new(), None, None),
    };
    MergeQueueCheckWorkView {
        repo: work.repo,
        work_ref,
        kind,
        status,
        configuration_keys,
        reason,
        hold,
        generation: work.generation,
        baseline_commit: config
            .map(|config| config.baseline_commit)
            .or(requested_baseline),
        plan_digest: work.plan_digest,
        receipt_refs: work
            .receipts
            .iter()
            .map(|receipt| format!("{QUEUE_CHECK_CANDIDATE_PREFIX}{}", receipt.inputs_digest))
            .collect(),
        verdict_refs: work.verdict_refs,
        pointers: work
            .pointers
            .map(|pointers| pointers_view(work.repo, pointers)),
        quarantine: work.quarantine,
    }
}
