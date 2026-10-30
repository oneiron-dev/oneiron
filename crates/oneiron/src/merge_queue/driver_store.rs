//! The queue driver's reads of the checker's rows and its own durable
//! writes (FIX 6868, G2 PR2).
//!
//! Enrollment is the checked configuration, found by its typed scan; its
//! repository is resolved again from its stored CODE_ARTIFACT to the proven
//! object store. Requests ride the checker's own work rows under the
//! owner's stored approval, never renewed and never rebuilt. The driver's
//! own writes are its holds, its survivor formation and its conflict links,
//! each read and checked again in its writer; an unchanged hold writes
//! nothing.
use super::check_store::{
    CHECK_CONFIGS, ConfigWrite, QueueCheckConfiguration, QueueCheckInitStage, QueueCheckRequest,
    QueueCheckStatus, QueueCheckWork,
};
use super::storage::{BATCHES, check_row_size};
use super::{
    BatchState, CheckPhase, MergeBatch, MergeProposal, MergeQueue, QUEUE_CHECK_CANDIDATE_PREFIX,
    QueueBatchDrive, QueueConflictLink, QueueConflictView, QueueDriveHold, QueueDriveHoldReason,
    QueueDriveOutcome, QueueDriveStatus, QueueDriveView, QueueRevisionLink, QueueSurvivorLink,
};
use crate::Vault;
use crate::codebase::RepoRef;
use crate::contract_oracle::invalid;
use crate::error::{Error, Result};
use crate::git_wire::{GitWireRepo, lock_repository};

impl QueueCheckConfiguration {
    /// Whether this configuration enrolls its queue for automatic driving
    /// (CALL C "driver enrollment"): a checked initialization that completed
    /// and proved an attached target. A queue initialized without one, or a
    /// raw low-level queue, is never enrolled; its doors work as before.
    #[must_use]
    pub fn drives_queue(&self) -> bool {
        matches!(self.stage, QueueCheckInitStage::Initialized { .. })
            && self.driver_target.is_some()
    }
}

impl Vault {
    /// Every checked configuration that enrolls its queue, in store order.
    ///
    /// # Errors
    /// A store failure.
    pub fn queue_driver_configurations(&self) -> Result<Vec<QueueCheckConfiguration>> {
        let txn = self.store.env.read_txn()?;
        Ok(CHECK_CONFIGS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, config)| config)
            .filter(QueueCheckConfiguration::drives_queue)
            .collect())
    }

    /// The queue an enrolled configuration names: its CODE_ARTIFACT's stored
    /// pointer resolved again, which must still name that object store. A
    /// served import's queue opens its exact init source, a missing
    /// projection put back first under the store's writer (FIX 6869).
    ///
    /// # Errors
    /// A missing artifact, another object store, a held source by name or
    /// a store failure.
    pub fn queue_driver_open(&self, config: &QueueCheckConfiguration) -> Result<MergeQueue<'_>> {
        let artifact = self
            .get_code_artifact(&config.repo)?
            .ok_or(Error::EntityNotFound)?;
        let queue = match self.store_queue_source(&config.store)? {
            Some(bound)
                if bound.anchor == config.repo && bound.repo_ref.canonical() == config.repo_ref =>
            {
                self.ensure_served_queue_source(&bound)?
                    .map_err(|held| Error::Refused(format!("held_materialization: {held}")))?
            }
            Some(_) => {
                return Err(Error::ConcurrentWrite(
                    "the checked configuration names another queue source",
                ));
            }
            None => MergeQueue::open(self, RepoRef::parse(&artifact.repo_ref)?)?,
        };
        if queue.repo.identity().as_hex() != config.store {
            return Err(Error::ConcurrentWrite(
                "the code artifact no longer names the checked object store",
            ));
        }
        Ok(queue)
    }
}

impl<'a> MergeQueue<'a> {
    /// This object store's queue, for a writer that already holds it.
    pub(crate) fn of_repo(vault: &'a Vault, repo: GitWireRepo) -> Self {
        Self { vault, repo }
    }
}

impl MergeQueue<'_> {
    /// The checker work row `request` maps to, if one was ever asked for.
    pub(super) fn driver_work(
        &self,
        request: &QueueCheckRequest,
    ) -> Result<Option<QueueCheckWork>> {
        let key = self.work_key(request)?;
        let digest = key
            .rsplit_once(':')
            .map_or(key.as_str(), |(_, digest)| digest);
        self.check_work(digest)
    }

    /// Asks the checker for `request` under the stored configuration and
    /// its stored approval; the claim judges that approval again.
    pub(super) fn request_driver_check(
        &self,
        config: &QueueCheckConfiguration,
        request: QueueCheckRequest,
    ) -> Result<QueueDriveOutcome> {
        let work = self.submit_check_work(
            config.repo,
            request,
            None,
            ConfigWrite::Keep,
            None,
            |_, _| Err(invalid("the queue driver mints no approval")),
        )?;
        Ok(match work.status {
            QueueCheckStatus::Queued | QueueCheckStatus::Running => {
                QueueDriveOutcome::RequestedCheck {
                    work_ref: work.work_ref().to_owned(),
                }
            }
            _ => QueueDriveOutcome::Done,
        })
    }

    /// Keeps `hold` (or none) as batch `id`'s last typed hold and answers
    /// the step's outcome. An unchanged hold, or any while an effect needs
    /// recovery, writes nothing.
    pub(super) fn record_hold(
        &self,
        id: &str,
        hold: Option<QueueDriveHold>,
    ) -> Result<QueueDriveOutcome> {
        let outcome = hold
            .clone()
            .map_or(QueueDriveOutcome::Done, QueueDriveOutcome::Waiting);
        let _guard = lock_repository(self.repo.common_dir())?;
        let queue = self.queue()?;
        if queue.intent.is_some() {
            return Ok(outcome);
        }
        let mut batch = self.batch(id)?;
        if batch.drive.as_ref().and_then(|drive| drive.hold.as_ref()) == hold.as_ref() {
            return Ok(outcome);
        }
        batch
            .drive
            .get_or_insert_with(QueueBatchDrive::default)
            .hold = hold;
        self.save(&queue, &[&batch])?;
        Ok(outcome)
    }

    /// [`Self::record_hold`] of a new hold.
    pub(super) fn hold(
        &self,
        id: &str,
        reason: QueueDriveHoldReason,
        detail: impl Into<String>,
    ) -> Result<QueueDriveOutcome> {
        self.record_hold(id, Some(QueueDriveHold::new(reason, detail)))
    }

    /// Decides a quarantined batch's survivors once. The survivors' batch
    /// keeps the source's accepted run order, its symbols, predecessors and
    /// sequence, and is formed in the writer that links the source to it;
    /// after a crash the link is the answer. A moved head or green holds:
    /// survivors then need a newly reviewed base. The shipped owner requeue
    /// is unchanged.
    pub(super) fn requeue_survivors_driven(&self, id: &str) -> Result<QueueDriveOutcome> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let mut queue = self.queue()?;
        if queue.intent.is_some() {
            return Ok(QueueDriveOutcome::Waiting(QueueDriveHold::new(
                QueueDriveHoldReason::HeldRecovery,
                "a merge effect needs recovery first",
            )));
        }
        let mut source = self.batch(id)?;
        if source.state != BatchState::Quarantined
            || source
                .drive
                .as_ref()
                .is_some_and(|drive| drive.survivor.is_some())
        {
            return Ok(QueueDriveOutcome::Done);
        }
        let quarantine = source
            .quarantine
            .clone()
            .ok_or(Error::CorruptedIndex("quarantined batch has no quarantine"))?;
        let survivors: Vec<MergeProposal> = source
            .proposals
            .iter()
            .filter(|proposal| !quarantine.proposal_ids.contains(&proposal.id))
            .cloned()
            .collect();
        if survivors.is_empty() {
            source
                .drive
                .get_or_insert_with(QueueBatchDrive::default)
                .survivor = Some(QueueSurvivorLink::Empty);
            self.save(&queue, &[&source])?;
            return Ok(QueueDriveOutcome::Changed);
        }
        if queue.pointers.head != source.expected_head
            || survivors
                .iter()
                .any(|proposal| proposal.base_green != queue.pointers.green)
        {
            return self.hold(
                id,
                QueueDriveHoldReason::HeldNeedsNewBase,
                "the queue moved past the quarantined batch's base: its survivors need a newly \
                 reviewed proposal",
            );
        }
        super::staging::validate_proposals(&survivors, &queue.pointers.green)?;
        let child_id = self.next_batch_id(&mut queue, &survivors)?;
        let selected_tests = queue.graph.affected_tests(
            survivors
                .iter()
                .flat_map(|proposal| proposal.files.iter().map(|file| file.path.as_str())),
        )?;
        let run_order = super::staging::survivor_run_order(source.run_order.clone(), &survivors);
        let child = MergeBatch {
            schema_version: 1,
            id: child_id.clone(),
            expected_head: queue.pointers.head.clone(),
            base_green: queue.pointers.green.clone(),
            baseline_id: queue.baseline_id.clone(),
            proposals: survivors,
            state: BatchState::Queued,
            paths: Vec::new(),
            pre_snapshot: None,
            landed_head: None,
            slow_verdict: None,
            quarantine: None,
            selected_tests,
            run_order,
            drive: Some(QueueBatchDrive {
                survivor_of: Some(source.id.clone()),
                ..QueueBatchDrive::default()
            }),
        };
        let drive = source.drive.get_or_insert_with(QueueBatchDrive::default);
        drive.survivor = Some(QueueSurvivorLink::Batch(child_id));
        drive.hold = None;
        self.save(&queue, &[&source, &child])?;
        Ok(QueueDriveOutcome::Changed)
    }

    /// Links every batch `link` names to its overlap handoff, in the
    /// shared conflict writer's transaction. Each must still be retained
    /// and hold one of the link's sources. An unlanded batch is held; a
    /// landed one only keeps the link. An existing link's successor and
    /// supersession are kept.
    ///
    /// # Errors
    /// A batch that is gone, released or no longer holds a source.
    pub(crate) fn attach_queue_conflict_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        link: &QueueConflictLink,
    ) -> Result<()> {
        let sources: Vec<String> = link.sources.iter().map(crate::EntityId::to_hex).collect();
        for id in &link.batches {
            let key = self.batch_key(id);
            let mut batch = BATCHES
                .get(&self.vault.store, txn, &key)?
                .ok_or_else(|| invalid("an overlap batch is gone"))?;
            if matches!(
                batch.state,
                BatchState::Cancelled | BatchState::RolledBack | BatchState::Quarantined
            ) || !batch
                .proposals
                .iter()
                .any(|proposal| sources.contains(&proposal.id))
            {
                return Err(Error::ConcurrentWrite(
                    "an overlap batch no longer holds its source",
                ));
            }
            let unlanded = matches!(
                batch.state,
                BatchState::Queued | BatchState::Staged | BatchState::Ready
            );
            let drive = batch.drive.get_or_insert_with(QueueBatchDrive::default);
            let mut linked = link.clone();
            if let Some(existing) = &drive.overlap
                && existing.conflict == link.conflict
            {
                linked.resolution_batch = linked
                    .resolution_batch
                    .or_else(|| existing.resolution_batch.clone());
                linked.superseded |= existing.superseded;
            }
            if unlanded {
                drive.hold = Some(match &linked.held {
                    Some(reason) => {
                        QueueDriveHold::new(QueueDriveHoldReason::HeldTaskAuthority, reason.clone())
                    }
                    None => QueueDriveHold::new(
                        QueueDriveHoldReason::HeldOverlap,
                        "overlapping accepted proposals were handed to a reconciliation; a fresh \
                         combined reviewed proposal resolves them",
                    ),
                });
            }
            drive.overlap = Some(linked);
            check_row_size(&BATCHES.encode_value(&batch)?)?;
            BATCHES.put(&self.vault.store, txn, &key, &batch)?;
        }
        Ok(())
    }

    /// Writes `link`'s successor and supersession on every batch it names,
    /// under the repository writer.
    pub(super) fn update_overlap_links(&self, link: &QueueConflictLink) -> Result<()> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let queue = self.queue()?;
        let mut batches = Vec::new();
        for id in &link.batches {
            let mut batch = self.batch(id)?;
            let mut linked = false;
            if let Some(drive) = batch.drive.as_mut()
                && let Some(existing) = drive.overlap.as_mut()
                && existing.conflict == link.conflict
            {
                existing.resolution_batch.clone_from(&link.resolution_batch);
                existing.superseded = link.superseded;
                if link.superseded {
                    drive.hold = None;
                }
                linked = true;
            }
            if linked {
                batches.push(batch);
            }
        }
        self.save(&queue, &batches.iter().collect::<Vec<_>>())
    }

    /// The driver's view of `batch`, joined from its drive record and the
    /// checker's work rows. A read that fails is this batch's own
    /// Unavailable status, never an empty success.
    pub(crate) fn queue_driver_observation(&self, batch: &MergeBatch) -> QueueDriveView {
        match self.queue_driver_view(batch) {
            Ok(view) => view,
            Err(error) => QueueDriveView {
                batch_ref: batch.id.clone(),
                status: QueueDriveStatus::Unavailable,
                reason: Some(error.to_string()),
                check_work_refs: Vec::new(),
                receipt_refs: Vec::new(),
                conflicts: Vec::new(),
                survivor_batch: None,
                tested_revision: None,
                seal_hold: None,
            },
        }
    }

    fn queue_driver_view(&self, batch: &MergeBatch) -> Result<QueueDriveView> {
        let config = self.checker_configuration()?;
        let drive = batch.drive.clone().unwrap_or_default();
        let mut requests: Vec<QueueCheckRequest> = batch
            .paths
            .iter()
            .map(|path| QueueCheckRequest::Check {
                batch: batch.id.clone(),
                mask: path.mask,
                phase: CheckPhase::Fast,
                force_refresh: false,
            })
            .collect();
        if batch.landed_head.is_some() {
            requests.push(QueueCheckRequest::Check {
                batch: batch.id.clone(),
                mask: self.landed_path(batch)?.mask,
                phase: CheckPhase::Slow,
                force_refresh: false,
            });
        }
        requests.push(QueueCheckRequest::Diagnose {
            batch: batch.id.clone(),
        });
        let mut works = Vec::new();
        for request in &requests {
            if let Some(work) = self.driver_work(request)? {
                works.push(work);
            }
        }
        let (status, reason) = drive_status(
            config
                .as_ref()
                .is_some_and(QueueCheckConfiguration::drives_queue),
            batch,
            &drive,
            &works,
        );
        let (tested_revision, seal_hold) = match &drive.tested {
            Some(QueueRevisionLink::Sealed { revision }) => (Some(revision.to_hex()), None),
            Some(QueueRevisionLink::Pending { hold, .. }) => (None, hold.clone()),
            None => (None, None),
        };
        Ok(QueueDriveView {
            batch_ref: batch.id.clone(),
            status,
            reason,
            check_work_refs: works
                .iter()
                .map(|work| work.work_ref().to_owned())
                .collect(),
            receipt_refs: works
                .iter()
                .flat_map(|work| &work.receipts)
                .map(|receipt| format!("{QUEUE_CHECK_CANDIDATE_PREFIX}{}", receipt.inputs_digest))
                .collect(),
            conflicts: drive
                .overlap
                .iter()
                .map(|link| QueueConflictView {
                    source_proposals: link.sources.iter().map(crate::EntityId::to_hex).collect(),
                    conflict: link.conflict.to_hex(),
                    task: link.task.map(|task| task.to_hex()),
                    resolution_batch: link.resolution_batch.clone(),
                })
                .collect(),
            survivor_batch: match drive.survivor {
                Some(QueueSurvivorLink::Batch(child)) => Some(child),
                _ => None,
            },
            tested_revision,
            seal_hold,
        })
    }
}

/// Where the driver stands on `batch`: unenrolled, done, its kept hold, or
/// what its checker work says.
fn drive_status(
    enrolled: bool,
    batch: &MergeBatch,
    drive: &QueueBatchDrive,
    works: &[QueueCheckWork],
) -> (QueueDriveStatus, Option<String>) {
    if !enrolled {
        return (QueueDriveStatus::Unenrolled, None);
    }
    let decided =
        drive.survivor.is_some() || drive.overlap.as_ref().is_some_and(|link| link.superseded);
    if decided
        || matches!(
            batch.state,
            BatchState::GreenAdvanced | BatchState::RolledBack | BatchState::Cancelled
        )
    {
        return (QueueDriveStatus::Done, None);
    }
    if let Some(hold) = &drive.hold {
        return (hold.reason.into(), Some(hold.detail.clone()));
    }
    for work in works {
        match &work.status {
            QueueCheckStatus::Queued | QueueCheckStatus::Running => {
                return (QueueDriveStatus::WaitingCheck, None);
            }
            QueueCheckStatus::NeedsConfiguration(need) => {
                return (
                    QueueDriveStatus::NeedsConfiguration,
                    Some(need.reason.clone()),
                );
            }
            QueueCheckStatus::Held(held) => {
                return (QueueDriveStatus::HeldCheck, Some(held.detail.clone()));
            }
            QueueCheckStatus::Completed { .. } | QueueCheckStatus::Settled { .. } => {}
        }
    }
    (QueueDriveStatus::Driving, None)
}
