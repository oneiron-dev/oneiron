//! A quarantined batch's survivor formation (FIX 4362): one body for the
//! owner's `requeue_survivors` and the driver's step.
//!
//! A source keeps at most one survivor disposition: the survivors' batch,
//! or Empty when no member survived. The writer that forms the survivors'
//! batch links the source to it and it back to the source. A retry finds
//! that link and answers it; it never forms another batch.
use super::{
    BatchState, MergeBatch, MergeProposal, MergeQueue, QueueBatchDrive, QueueDriveHold,
    QueueDriveHoldReason, QueueDriveOutcome, QueueSurvivorLink,
};
use crate::error::{Error, Result};
use crate::git_wire::lock_repository;
use crate::store::contract_oracle::invalid;

/// Who asks for a quarantined batch's survivors (FIX 4362).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SurvivorCaller {
    /// The owner's `requeue_survivors`. It also needs the live checkout at
    /// the queue's HEAD and clean, as an enqueue does.
    Owner,
    /// The automatic driver.
    Driver,
}

/// Why a survivor formation wrote no disposition (FIX 4362).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SurvivorRefusal {
    /// The source is not quarantined.
    NotQuarantined,
    /// A landing or rollback intent needs recovery first.
    NeedsRecovery,
    /// HEAD or green moved past the source's base. Its survivors need a
    /// newly reviewed proposal; nothing rebases.
    NeedsNewBase,
}

impl SurvivorRefusal {
    /// The owner call's error for this refusal (FIX 4362).
    pub(super) fn owner_error(self) -> Error {
        match self {
            Self::NotQuarantined => invalid("batch has not been diagnosed"),
            Self::NeedsRecovery => Error::ConcurrentWrite("merge effect needs recovery"),
            Self::NeedsNewBase => Error::ConcurrentWrite("survivors need a newly reviewed base"),
        }
    }
}

/// What one survivor formation answers (FIX 4362).
pub(super) enum SurvivorFormation {
    /// The source's one disposition. `written` is false when an earlier
    /// call kept it.
    Decided {
        link: QueueSurvivorLink,
        written: bool,
    },
    /// No disposition was written.
    Refused(SurvivorRefusal),
}

impl MergeQueue<'_> {
    /// Decides a quarantined batch's survivors once, for the owner or the
    /// driver (FIX 4362). The survivors' batch keeps the source's
    /// proposals, its accepted run order, its symbols, predecessors and
    /// sequence. It is formed in the writer that links the source to it
    /// and it back to the source. A kept disposition answers a retry. No
    /// surviving member writes Empty. A moved head or green refuses:
    /// survivors then need a newly reviewed base.
    pub(super) fn form_survivors(
        &self,
        id: &str,
        caller: SurvivorCaller,
    ) -> Result<SurvivorFormation> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let mut queue = self.queue()?;
        let mut source = self.batch(id)?;
        if source.state != BatchState::Quarantined {
            return Ok(SurvivorFormation::Refused(SurvivorRefusal::NotQuarantined));
        }
        if let Some(link) = source
            .drive
            .as_ref()
            .and_then(|drive| drive.survivor.clone())
        {
            return Ok(SurvivorFormation::Decided {
                link,
                written: false,
            });
        }
        if queue.intent.is_some() {
            return Ok(SurvivorFormation::Refused(SurvivorRefusal::NeedsRecovery));
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
            return Ok(SurvivorFormation::Decided {
                link: QueueSurvivorLink::Empty,
                written: true,
            });
        }
        if queue.pointers.head != source.expected_head
            || survivors
                .iter()
                .any(|proposal| proposal.base_green != queue.pointers.green)
        {
            return Ok(SurvivorFormation::Refused(SurvivorRefusal::NeedsNewBase));
        }
        if caller == SurvivorCaller::Owner {
            self.require_current(&queue)?;
            self.require_clean(self.repo.repo_root())?;
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
        drive.survivor = Some(QueueSurvivorLink::Batch(child_id.clone()));
        drive.hold = None;
        self.save(&queue, &[&source, &child])?;
        Ok(SurvivorFormation::Decided {
            link: QueueSurvivorLink::Batch(child_id),
            written: true,
        })
    }

    /// The driver's survivor step: [`Self::form_survivors`] for the driver
    /// (FIX 4362). A written disposition is a change. A kept one, or a
    /// source not quarantined, is done. An effect intent waits for
    /// recovery. A moved base keeps its HeldNeedsNewBase hold in the same
    /// writer.
    pub(super) fn requeue_survivors_driven(&self, id: &str) -> Result<QueueDriveOutcome> {
        let _guard = lock_repository(self.repo.common_dir())?;
        match self.form_survivors(id, SurvivorCaller::Driver)? {
            SurvivorFormation::Decided { written: true, .. } => Ok(QueueDriveOutcome::Changed),
            SurvivorFormation::Decided { written: false, .. }
            | SurvivorFormation::Refused(SurvivorRefusal::NotQuarantined) => {
                Ok(QueueDriveOutcome::Done)
            }
            SurvivorFormation::Refused(SurvivorRefusal::NeedsRecovery) => {
                Ok(QueueDriveOutcome::Waiting(QueueDriveHold::new(
                    QueueDriveHoldReason::HeldRecovery,
                    "a merge effect needs recovery first",
                )))
            }
            SurvivorFormation::Refused(SurvivorRefusal::NeedsNewBase) => self.hold(
                id,
                QueueDriveHoldReason::HeldNeedsNewBase,
                "the queue moved past the quarantined batch's base: its survivors need a newly \
                 reviewed proposal",
            ),
        }
    }
}
