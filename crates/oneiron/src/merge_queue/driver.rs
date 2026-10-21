//! The merge queue's restart driver (FIX 6868, G2 PR2): one reducer over a
//! checked queue's durable rows, run by the checker's one server drain.
//!
//! [`MergeQueue::pending_work`] reads a snapshot of the queue, its batches
//! and the checker's work rows and answers what to do next, in the order
//! [`QueueWork::priority`] gives. [`MergeQueue::drive_one`] reads the queue
//! again under its writer and takes one step through the shipped bodies
//! alone: `recover`, the one staging body, the checker's bound requests,
//! the bound diagnosis, `land_reviewed` and `settle_slow`. It runs no
//! command, moves no ref by hand, approves nothing and rebases nothing: a
//! moved base holds for a fresh reviewed proposal, and overlapping accepted
//! work is handed to a reconciliation, never merged here. The owner's doors
//! keep today's behavior; a new hold is only ever this driver's.
use super::check_inputs::QueueCheckHoldReason;
use super::check_store::{QueueCheckConfiguration, QueueCheckRequest, QueueCheckStatus};
use super::driver_materialize::QueueOverlapFinding;
use super::types::EffectIntent;
use super::{
    BatchState, CheckPhase, MergeBatch, MergeQueue, QUEUE_CHECK_CANDIDATE_PREFIX, QueueDriveHold,
    QueueDriveHoldReason, QueueDriveOutcome, QueueDrivePass, QueueStageOverlap, QueueWork,
};
use crate::contract_oracle::{ContractOracle, invalid};
use crate::error::Result;
use crate::federation::QueueReconciliationAdmission;
use crate::git_wire::{GitWire, lock_repository};

impl MergeQueue<'_> {
    /// What the driver does next on this queue, in priority order. A queue
    /// with an effect intent answers its recovery alone; a HEAD that moved
    /// without a receipt answers nothing (HeldDiverged is read, never
    /// reset). A held check is asked again only on a tick, and one that
    /// needed host configuration only on the first pass after a start.
    ///
    /// # Errors
    /// A store failure.
    pub fn pending_work(&self, pass: QueueDrivePass) -> Result<Vec<QueueWork>> {
        let Some(queue) = self.read_queue()? else {
            return Ok(Vec::new());
        };
        if queue.intent.is_some() {
            return Ok(vec![QueueWork::Recover]);
        }
        if self.head()? != queue.pointers.head {
            return Ok(Vec::new());
        }
        let batches = {
            let txn = self.vault.store.env.read_txn()?;
            self.repo_batches_in_txn(&txn)?
        };
        let oracle = ContractOracle::new(self.vault);
        let mut works = Vec::new();
        let (mut red, mut first_settled) = (false, false);
        for (position, id) in queue.pointers.pending_slow.iter().enumerate() {
            let Some(batch) = batches.iter().find(|batch| &batch.id == id) else {
                continue;
            };
            let order = position as u64;
            if let Some(verdict) = &batch.slow_verdict {
                red |= !oracle
                    .verdict(verdict)?
                    .is_some_and(|verdict| verdict.passes());
                first_settled |= position == 0;
                continue;
            }
            let mask = self.landed_path(batch)?.mask;
            let worktree = self.worktree_path(&batch.id, u64::MAX);
            if worktree.symlink_metadata().is_err()
                && GitWire::new(self.vault)?.worktree_registered(&self.repo, &worktree)?
            {
                works.push(QueueWork::RepairPath {
                    batch: id.clone(),
                    mask,
                    phase: CheckPhase::Slow,
                    order,
                });
            } else {
                self.check_work_for(&mut works, batch, mask, CheckPhase::Slow, order, pass)?;
            }
        }
        if let Some(first) = queue.pointers.pending_slow.first()
            && (red || first_settled)
        {
            works.push(QueueWork::SettleSlow {
                batch: first.clone(),
                red,
                order: 0,
            });
        }
        for (index, batch) in batches.iter().enumerate() {
            let order = index as u64;
            let drive = batch.drive.as_ref();
            let unlanded = matches!(
                batch.state,
                BatchState::Queued | BatchState::Staged | BatchState::Ready
            );
            if let Some(link) = drive.and_then(|drive| drive.overlap.as_ref())
                && unlanded
            {
                if !link.superseded {
                    works.push(QueueWork::HandoffOverlap {
                        batch: batch.id.clone(),
                        order,
                    });
                }
                continue;
            }
            match batch.state {
                BatchState::Queued => works.push(QueueWork::Stage {
                    batch: batch.id.clone(),
                    order,
                }),
                BatchState::Staged | BatchState::Ready => {
                    self.fast_work(&mut works, batch, order, pass)?;
                }
                BatchState::Quarantined if drive.is_none_or(|drive| drive.survivor.is_none()) => {
                    works.push(QueueWork::RequeueSurvivors {
                        batch: batch.id.clone(),
                        order,
                    });
                }
                _ => {}
            }
        }
        works.sort_by_key(QueueWork::priority);
        Ok(works)
    }

    /// One driven step of `work` on this queue, enrolled by `config`. It
    /// reads the queue again under its writer before it acts.
    ///
    /// # Errors
    /// A store failure, or a configuration of another object store.
    pub fn drive_one(
        &self,
        config: &QueueCheckConfiguration,
        work: &QueueWork,
        pass: QueueDrivePass,
    ) -> Result<QueueDriveOutcome> {
        if config.store != self.repo.identity().as_hex() {
            return Err(invalid("the configuration names another object store"));
        }
        if !config.drives_queue() {
            return Ok(QueueDriveOutcome::Done);
        }
        match work {
            QueueWork::Recover => self.drive_recover(),
            QueueWork::SettleSlow { .. } => Ok(match self.settle_slow() {
                Ok(_) => QueueDriveOutcome::Changed,
                Err(error) => QueueDriveOutcome::Waiting(QueueDriveHold::new(
                    QueueDriveHoldReason::HeldRecovery,
                    format!("the slow settlement holds: {error}"),
                )),
            }),
            QueueWork::RepairPath {
                batch, mask, phase, ..
            } => self.drive_repair(batch, *mask, *phase),
            QueueWork::RequestCheck {
                batch, mask, phase, ..
            } => {
                if !self
                    .batch(batch)?
                    .paths
                    .iter()
                    .any(|path| path.mask == *mask)
                {
                    return Ok(QueueDriveOutcome::Done);
                }
                let request = QueueCheckRequest::Check {
                    batch: batch.clone(),
                    mask: *mask,
                    phase: *phase,
                    force_refresh: false,
                };
                self.request_driver_check(config, request)
            }
            QueueWork::Stage { batch, .. } => self.drive_stage(config, batch, pass),
            QueueWork::Diagnose { batch, .. } => {
                let request = QueueCheckRequest::Diagnose {
                    batch: batch.clone(),
                };
                self.request_driver_check(config, request)
            }
            QueueWork::RequeueSurvivors { batch, .. } => self.requeue_survivors_driven(batch),
            QueueWork::LandReviewed { batch, .. } => self.drive_land(batch, pass),
            QueueWork::HandoffOverlap { batch, .. } => self.drive_handoff(config, batch, pass),
        }
    }

    /// A staged batch's next fast work: custody and missing paths first,
    /// then each missing bound check; with every subset checked, the
    /// reviewed landing of a ready batch or the bound diagnosis of a red one.
    fn fast_work(
        &self,
        works: &mut Vec<QueueWork>,
        batch: &MergeBatch,
        order: u64,
        pass: QueueDrivePass,
    ) -> Result<()> {
        let pinned = batch.drive.as_ref().is_some_and(|drive| drive.pinned);
        let mut unchecked = false;
        for path in batch.paths.iter().filter(|path| path.verdict.is_none()) {
            unchecked = true;
            if !pinned || path.worktree.symlink_metadata().is_err() {
                works.push(QueueWork::RepairPath {
                    batch: batch.id.clone(),
                    mask: path.mask,
                    phase: CheckPhase::Fast,
                    order,
                });
                return Ok(());
            }
            self.check_work_for(works, batch, path.mask, CheckPhase::Fast, order, pass)?;
        }
        if unchecked {
            return Ok(());
        }
        if batch.state == BatchState::Ready {
            works.push(QueueWork::LandReviewed {
                batch: batch.id.clone(),
                order,
            });
        } else {
            let request = QueueCheckRequest::Diagnose {
                batch: batch.id.clone(),
            };
            if self.needs_request(&request, pass)? {
                works.push(QueueWork::Diagnose {
                    batch: batch.id.clone(),
                    order,
                });
            }
        }
        Ok(())
    }

    fn check_work_for(
        &self,
        works: &mut Vec<QueueWork>,
        batch: &MergeBatch,
        mask: u64,
        phase: CheckPhase,
        order: u64,
        pass: QueueDrivePass,
    ) -> Result<()> {
        let request = QueueCheckRequest::Check {
            batch: batch.id.clone(),
            mask,
            phase,
            force_refresh: false,
        };
        if self.needs_request(&request, pass)? {
            works.push(QueueWork::RequestCheck {
                batch: batch.id.clone(),
                mask,
                phase,
                order,
            });
        }
        Ok(())
    }

    /// Whether `request` is asked for now: never asked, or held for a reason
    /// the host may clear (on a tick), or needing host configuration (on the
    /// first pass after a start). Queued, running and finished work waits.
    fn needs_request(&self, request: &QueueCheckRequest, pass: QueueDrivePass) -> Result<bool> {
        Ok(match self.driver_work(request)? {
            None => true,
            Some(work) => match work.status {
                QueueCheckStatus::Held(hold) => {
                    (pass.tick || pass.first)
                        && matches!(
                            hold.reason,
                            QueueCheckHoldReason::Interrupted
                                | QueueCheckHoldReason::ExecutorUnavailable
                                | QueueCheckHoldReason::TreeUnavailable
                        )
                }
                QueueCheckStatus::NeedsConfiguration(_) => pass.first,
                QueueCheckStatus::Queued
                | QueueCheckStatus::Running
                | QueueCheckStatus::Completed { .. }
                | QueueCheckStatus::Settled { .. } => false,
            },
        })
    }

    /// Recovery first: the saved path a reviewed resume verifies is put back,
    /// then the existing `recover` reconciles the intent. A failure holds.
    fn drive_recover(&self) -> Result<QueueDriveOutcome> {
        let queue = self.queue()?;
        let restored = match &queue.intent {
            None => return Ok(QueueDriveOutcome::Done),
            Some(EffectIntent::Landing { batch, .. }) => {
                let batch = self.batch(batch)?;
                let mask = self.landed_path(&batch)?.mask;
                Some(self.rematerialize(&batch, mask, CheckPhase::Fast)?)
            }
            Some(EffectIntent::Rollback { .. }) => None,
        };
        Ok(match self.recover() {
            Ok(_) => QueueDriveOutcome::Changed,
            Err(error) => QueueDriveOutcome::Waiting(match restored {
                Some(Err(hold)) => hold,
                _ => QueueDriveHold::new(
                    QueueDriveHoldReason::HeldRecovery,
                    format!("recovery holds: {error}"),
                ),
            }),
        })
    }

    /// Pins a batch's staged objects once, then puts one saved path back.
    fn drive_repair(&self, id: &str, mask: u64, phase: CheckPhase) -> Result<QueueDriveOutcome> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let queue = self.queue()?;
        if queue.intent.is_some() {
            return Ok(recovery_first());
        }
        let mut batch = self.batch(id)?;
        let live = match phase {
            CheckPhase::Fast => matches!(batch.state, BatchState::Staged | BatchState::Ready),
            CheckPhase::Slow => batch.state == BatchState::HeadAdvanced,
        };
        if !live {
            return Ok(QueueDriveOutcome::Done);
        }
        let mut changed = false;
        if !batch.drive.as_ref().is_some_and(|drive| drive.pinned) {
            let wire = GitWire::new(self.vault)?;
            if let Err(error) = self.pin_batch(&wire, &mut batch) {
                return self.hold(
                    id,
                    QueueDriveHoldReason::HeldMaterialization,
                    format!("the staged objects cannot be pinned: {error}"),
                );
            }
            self.save(&queue, &[&batch])?;
            changed = true;
        }
        match self.rematerialize(&batch, mask, phase)? {
            Ok(restored) if changed || restored => Ok(QueueDriveOutcome::Changed),
            Ok(_) => Ok(QueueDriveOutcome::Done),
            Err(hold) => self.record_hold(id, Some(hold)),
        }
    }

    /// Queued → Staged: predecessors first (WaitingSymbols), then the
    /// overlap preflight against retained same-base work, then the base
    /// (HeldNeedsNewBase, no rebase), then the one staging body with its
    /// pins. A held handoff is tried again on a tick only.
    fn drive_stage(
        &self,
        config: &QueueCheckConfiguration,
        id: &str,
        pass: QueueDrivePass,
    ) -> Result<QueueDriveOutcome> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let queue = self.queue()?;
        if queue.intent.is_some() {
            return Ok(recovery_first());
        }
        if self.head()? != queue.pointers.head {
            return Ok(diverged());
        }
        let batch = self.batch(id)?;
        if batch.state != BatchState::Queued {
            return Ok(QueueDriveOutcome::Done);
        }
        let blockers = self.run_batch_blockers(&batch, self.vault.now_recorded_at())?;
        if !blockers.is_empty() {
            let tasks: Vec<String> = blockers.iter().map(crate::EntityId::to_hex).collect();
            return self.hold(
                id,
                QueueDriveHoldReason::WaitingSymbols,
                format!(
                    "waits behind the live declarations of TASK {}",
                    tasks.join(", ")
                ),
            );
        }
        if let Some(hold) = batch.drive.as_ref().and_then(|drive| drive.hold.as_ref())
            && hold.reason == QueueDriveHoldReason::HeldOverlap
            && !pass.tick
        {
            return Ok(QueueDriveOutcome::Waiting(hold.clone()));
        }
        let retained = {
            let txn = self.vault.store.env.read_txn()?;
            self.repo_batches_in_txn(&txn)?
        };
        match QueueStageOverlap::from_sources(self, config, &batch, &retained)? {
            QueueOverlapFinding::Overlap(overlap) => return self.hand_off(id, &overlap),
            QueueOverlapFinding::Hold(hold) => return self.record_hold(id, Some(hold)),
            QueueOverlapFinding::None => {}
        }
        if batch.expected_head != queue.pointers.head {
            return self.hold(
                id,
                QueueDriveHoldReason::HeldNeedsNewBase,
                "the queue head moved past this batch's base; no automatic rebase: a fresh \
                 reviewed proposal on the current green is needed",
            );
        }
        match self.stage_driven(id) {
            Ok(staged) if staged.state == BatchState::Staged => Ok(QueueDriveOutcome::Changed),
            Ok(_) => Ok(QueueDriveOutcome::Waiting(QueueDriveHold::new(
                QueueDriveHoldReason::WaitingSymbols,
                "the batch still waits behind a predecessor",
            ))),
            Err(error) => self.hold(
                id,
                QueueDriveHoldReason::HeldMaterialization,
                format!("staging holds: {error}"),
            ),
        }
    }

    /// Hands a proven overlap to the shared conflict writer under its sealed
    /// admission. A failure holds the batch; its work is kept.
    fn hand_off(&self, id: &str, overlap: &QueueStageOverlap) -> Result<QueueDriveOutcome> {
        let handed =
            QueueReconciliationAdmission::admit(self.vault, overlap).and_then(|admission| {
                self.vault
                    .record_queue_proposal_conflict(&self.repo, overlap, &admission)
            });
        match handed {
            Ok(_) => Ok(QueueDriveOutcome::Changed),
            Err(error) => self.hold(
                id,
                QueueDriveHoldReason::HeldOverlap,
                format!("the overlap handoff holds: {error}"),
            ),
        }
    }

    /// Ready → Landing → HeadAdvanced through the existing reviewed landing
    /// only, at the exact current head. A verdict without a bound receipt,
    /// a member without its review, or a refused admission holds; a refused
    /// admission is recovered at once and asked again on a tick only.
    fn drive_land(&self, id: &str, pass: QueueDrivePass) -> Result<QueueDriveOutcome> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let queue = self.queue()?;
        if queue.intent.is_some() {
            return Ok(recovery_first());
        }
        if self.head()? != queue.pointers.head {
            return Ok(diverged());
        }
        let mut batch = self.batch(id)?;
        if batch.state != BatchState::Ready {
            return Ok(QueueDriveOutcome::Done);
        }
        if batch.expected_head != queue.pointers.head {
            return self.hold(
                id,
                QueueDriveHoldReason::HeldNeedsNewBase,
                "the queue head moved past this tested batch; no automatic rebase: a fresh \
                 reviewed proposal on the current green is needed",
            );
        }
        let oracle = ContractOracle::new(self.vault);
        for path in &batch.paths {
            let bound = match &path.verdict {
                Some(verdict) => oracle.verdict(verdict)?.is_some_and(|verdict| {
                    verdict.candidate.starts_with(QUEUE_CHECK_CANDIDATE_PREFIX)
                }),
                None => false,
            };
            if !bound {
                return self.hold(
                    id,
                    QueueDriveHoldReason::HeldBinding,
                    "a fast verdict has no bound checker receipt; the owner's reviewed landing \
                     door still lands it",
                );
            }
        }
        if let Err(reason) = self.vault.reviewed_stack_members_ready(&batch)? {
            return self.hold(id, QueueDriveHoldReason::WaitingReview, reason);
        }
        if let Some(hold) = batch.drive.as_ref().and_then(|drive| drive.hold.as_ref())
            && hold.reason == QueueDriveHoldReason::WaitingAdmission
            && !pass.tick
        {
            return Ok(QueueDriveOutcome::Waiting(hold.clone()));
        }
        if !batch.drive.as_ref().is_some_and(|drive| drive.pinned) {
            self.pin_batch(&GitWire::new(self.vault)?, &mut batch)?;
            self.save(&queue, &[&batch])?;
        }
        let full = batch
            .paths
            .last()
            .ok_or_else(|| invalid("batch has no full path"))?
            .mask;
        if let Err(hold) = self.rematerialize(&batch, full, CheckPhase::Fast)? {
            return self.record_hold(id, Some(hold));
        }
        match self.land_reviewed(id) {
            Ok(_) => {
                self.record_hold(id, None)?;
                Ok(QueueDriveOutcome::Changed)
            }
            Err(error) => {
                if self.queue()?.intent.is_some()
                    && let Err(recovery) = self.recover()
                {
                    return Ok(QueueDriveOutcome::Waiting(QueueDriveHold::new(
                        QueueDriveHoldReason::HeldRecovery,
                        format!("the refused landing needs recovery: {recovery}"),
                    )));
                }
                self.hold(
                    id,
                    QueueDriveHoldReason::WaitingAdmission,
                    format!("the reviewed landing refused: {error}"),
                )
            }
        }
    }

    /// A handed-off batch: link the fresh entry its reconciliation TASK
    /// submitted, mark the source superseded once that entry is green, and
    /// on a tick ask again for a held TASK. Task completion alone clears
    /// nothing.
    fn drive_handoff(
        &self,
        config: &QueueCheckConfiguration,
        id: &str,
        pass: QueueDrivePass,
    ) -> Result<QueueDriveOutcome> {
        let batch = self.batch(id)?;
        let Some(mut link) = batch.drive.as_ref().and_then(|drive| drive.overlap.clone()) else {
            return Ok(QueueDriveOutcome::Done);
        };
        if link.superseded {
            return Ok(QueueDriveOutcome::Done);
        }
        let retained = {
            let txn = self.vault.store.env.read_txn()?;
            self.repo_batches_in_txn(&txn)?
        };
        if link.resolution_batch.is_none()
            && let Some(task) = link.task
            && let Some(successor) = retained.iter().find(|other| {
                !link.batches.contains(&other.id)
                    && other
                        .run_order
                        .as_ref()
                        .is_some_and(|order| order.task == task)
            })
        {
            link.resolution_batch = Some(successor.id.clone());
            self.update_overlap_links(&link)?;
            return Ok(QueueDriveOutcome::Changed);
        }
        if let Some(resolution) = &link.resolution_batch
            && retained
                .iter()
                .any(|other| &other.id == resolution && other.state == BatchState::GreenAdvanced)
        {
            link.superseded = true;
            self.update_overlap_links(&link)?;
            return Ok(QueueDriveOutcome::Changed);
        }
        if link.task.is_none()
            && (pass.tick || pass.first)
            && let QueueOverlapFinding::Overlap(overlap) =
                QueueStageOverlap::from_sources(self, config, &batch, &retained)?
            && overlap.sources == link.sources
        {
            let admission = QueueReconciliationAdmission::admit(self.vault, &overlap)?;
            let retried = self.vault.retry_queue_reconciliation_task(
                &overlap,
                &admission,
                &link,
                |txn, retried| self.attach_queue_conflict_in_txn(txn, retried),
            )?;
            if retried.task.is_some() {
                return Ok(QueueDriveOutcome::Changed);
            }
        }
        Ok(QueueDriveOutcome::Waiting(
            batch.drive.and_then(|drive| drive.hold).unwrap_or_else(|| {
                QueueDriveHold::new(
                    QueueDriveHoldReason::HeldOverlap,
                    "handed to a reconciliation",
                )
            }),
        ))
    }
}

fn recovery_first() -> QueueDriveOutcome {
    QueueDriveOutcome::Waiting(QueueDriveHold::new(
        QueueDriveHoldReason::HeldRecovery,
        "a merge effect needs recovery first",
    ))
}

fn diverged() -> QueueDriveOutcome {
    QueueDriveOutcome::Waiting(QueueDriveHold::new(
        QueueDriveHoldReason::HeldDiverged,
        "the repository HEAD moved without a queue receipt; nothing resets or rebases it",
    ))
}
