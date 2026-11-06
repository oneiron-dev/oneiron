//! A quarantined batch's survivor formation (FIX 4362).
use super::{
    BatchState, MergeBatch, MergeProposal, MergeQueue, QueueBatchDrive, QueueDriveHold,
    QueueDriveHoldReason, QueueDriveOutcome, QueueSurvivorLink,
};
use crate::error::{Error, Result};
use crate::git_wire::lock_repository;

impl MergeQueue<'_> {
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
}
