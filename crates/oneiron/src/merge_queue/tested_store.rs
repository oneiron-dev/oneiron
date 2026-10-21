//! Where a tested-revision seal is kept (FIX 6868, G2 PR3): one compact
//! link on the green batch's drive record, or on the checked-init work row
//! for the baseline. The inventory lives in the revision, never here.
//!
//! A link is pending from the moment its tree is green, with its
//! deterministic identities and persisted seal time, and sealed in the
//! same writer that finalizes its revision. A batch the owner's unchanged
//! settlement made green gets its intent here, on the driver's first look.
use super::check_store::{
    CHECK_WORK, QueueCheckConfiguration, QueueCheckInitStage, QueueCheckStatus, put_work,
};
use super::storage::{BATCHES, check_row_size};
use super::tested_types::QueueSealSource;
use super::{
    BatchState, MergeBatch, MergeQueue, QueueBatchDrive, QueueCheckReceipt, QueueExportHold,
    QueueExportHoldReason, QueueRevisionIntent, QueueRevisionLink, QueueRevisionSeal,
    QueueSealTarget,
};
use crate::code_revision::{queue_aggregation_session, queue_revision_id};
use crate::error::{Error, Result};
use crate::git_wire::lock_repository;
use crate::{EntityId, Vault};

/// Where one seal stands when the driver takes it up.
pub(super) enum SealState {
    Sealed(EntityId),
    Pending(QueueRevisionIntent),
    /// Not green yet, or its checked init not complete.
    Waiting(QueueExportHold),
}

impl MergeQueue<'_> {
    /// The checked baseline's pending link: its identities, the recorded
    /// checked-init approver and the seal time, decided now.
    pub(super) fn baseline_seal_link(
        &self,
        config: &QueueCheckConfiguration,
    ) -> Result<QueueRevisionLink> {
        let store = self.repo.identity().as_hex();
        Ok(QueueRevisionLink::Pending {
            intent: QueueRevisionIntent {
                revision: queue_revision_id(
                    &store,
                    &config.init_work,
                    "baseline",
                    &config.baseline_commit,
                    &config.baseline_tree,
                    &config.plan.digest,
                )?,
                session: queue_aggregation_session(&store, &config.init_work)?,
                target: QueueSealTarget::Baseline,
                parent_commit: None,
                commit: config.baseline_commit.clone(),
                tree: config.baseline_tree.clone(),
                plan_digest: config.plan.digest.clone(),
                approver: Some(config.approval.recorded_actor()),
                sealed_at: self.vault.now_recorded_at(),
            },
            hold: None,
        })
    }

    /// Keeps a pending intent on `batch`, which just went green: the
    /// landed commit and tree, the green it landed on and `sealed_at`. An
    /// existing link is kept.
    pub(super) fn attach_seal_intent(
        &self,
        config: &QueueCheckConfiguration,
        batch: &mut MergeBatch,
        sealed_at: u64,
    ) -> Result<()> {
        if batch
            .drive
            .as_ref()
            .is_some_and(|drive| drive.tested.is_some())
        {
            return Ok(());
        }
        let commit = batch
            .landed_head
            .clone()
            .ok_or(Error::CorruptedIndex("landed HEAD missing"))?;
        let tree = self.landed_path(batch)?.tree.clone();
        let store = self.repo.identity().as_hex();
        let intent = QueueRevisionIntent {
            revision: queue_revision_id(
                &store,
                &config.init_work,
                &format!("landed:{}", batch.id),
                &commit,
                &tree,
                &config.plan.digest,
            )?,
            session: queue_aggregation_session(&store, &config.init_work)?,
            target: QueueSealTarget::Landed {
                batch: batch.id.clone(),
            },
            parent_commit: Some(batch.expected_head.clone()),
            commit,
            tree,
            plan_digest: config.plan.digest.clone(),
            approver: None,
            sealed_at,
        };
        batch
            .drive
            .get_or_insert_with(QueueBatchDrive::default)
            .tested = Some(QueueRevisionLink::Pending { intent, hold: None });
        Ok(())
    }

    /// `target`'s link as stored.
    pub(super) fn seal_link(
        &self,
        config: &QueueCheckConfiguration,
        target: &QueueSealTarget,
    ) -> Result<Option<QueueRevisionLink>> {
        Ok(match target {
            QueueSealTarget::Baseline => {
                let txn = self.vault.store.env.read_txn()?;
                CHECK_WORK
                    .get(&self.vault.store, &txn, &config.init_work)?
                    .and_then(|work| work.baseline_seal)
            }
            QueueSealTarget::Landed { batch } => {
                self.batch(batch)?.drive.and_then(|drive| drive.tested)
            }
        })
    }

    /// The sealed revision of the green `commit`, once sealed: the
    /// baseline's, or the green batch's that landed it.
    pub(super) fn sealed_at_commit(
        &self,
        config: &QueueCheckConfiguration,
        commit: &str,
    ) -> Result<Option<EntityId>> {
        if commit == config.baseline_commit {
            return Ok(self
                .seal_link(config, &QueueSealTarget::Baseline)?
                .and_then(|link| link.sealed()));
        }
        let batches = {
            let txn = self.vault.store.env.read_txn()?;
            self.repo_batches_in_txn(&txn)?
        };
        Ok(batches
            .into_iter()
            .find(|batch| {
                batch.state == BatchState::GreenAdvanced
                    && batch.landed_head.as_deref() == Some(commit)
            })
            .and_then(|batch| batch.drive)
            .and_then(|drive| drive.tested)
            .and_then(|link| link.sealed()))
    }

    /// Where `target`'s seal stands, under the repository writer. A green
    /// target with no link yet gets its pending intent written first.
    pub(super) fn seal_state(
        &self,
        config: &QueueCheckConfiguration,
        target: &QueueSealTarget,
    ) -> Result<SealState> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let link = match target {
            QueueSealTarget::Baseline => {
                let store = &self.vault.store;
                let mut txn = store.env.write_txn()?;
                let mut work = CHECK_WORK
                    .get(store, &txn, &config.init_work)?
                    .ok_or(Error::EntityNotFound)?;
                if !matches!(config.stage, QueueCheckInitStage::Initialized { .. })
                    || work.status != (QueueCheckStatus::Completed { passed: true })
                {
                    return Ok(SealState::Waiting(QueueExportHold::new(
                        QueueExportHoldReason::SealPending,
                        "the checked initialization has not completed",
                    )));
                }
                if work.baseline_seal.is_none() {
                    work.baseline_seal = Some(self.baseline_seal_link(config)?);
                    put_work(store, &mut txn, &work)?;
                    txn.commit()?;
                }
                work.baseline_seal
            }
            QueueSealTarget::Landed { batch: id } => {
                let queue = self.queue()?;
                let mut batch = self.batch(id)?;
                if batch.state != BatchState::GreenAdvanced {
                    return Ok(SealState::Waiting(QueueExportHold::new(
                        QueueExportHoldReason::SealPending,
                        "the batch is not green",
                    )));
                }
                if batch
                    .drive
                    .as_ref()
                    .is_none_or(|drive| drive.tested.is_none())
                {
                    self.attach_seal_intent(config, &mut batch, self.vault.now_recorded_at())?;
                    self.save(&queue, &[&batch])?;
                }
                batch.drive.and_then(|drive| drive.tested)
            }
        };
        Ok(match link {
            Some(QueueRevisionLink::Sealed { revision }) => SealState::Sealed(revision),
            Some(QueueRevisionLink::Pending { intent, .. }) => SealState::Pending(intent),
            None => return Err(Error::CorruptedIndex("seal link missing after its write")),
        })
    }

    /// Keeps `hold` as `target`'s pending seal's last hold. An unchanged
    /// hold, or a sealed link, writes nothing.
    pub(super) fn record_seal_hold(
        &self,
        config: &QueueCheckConfiguration,
        target: &QueueSealTarget,
        hold: QueueExportHold,
    ) -> Result<()> {
        let _guard = lock_repository(self.repo.common_dir())?;
        match target {
            QueueSealTarget::Baseline => {
                let store = &self.vault.store;
                let mut txn = store.env.write_txn()?;
                let Some(mut work) = CHECK_WORK.get(store, &txn, &config.init_work)? else {
                    return Ok(());
                };
                if let Some(QueueRevisionLink::Pending { hold: kept, .. }) = &mut work.baseline_seal
                    && kept.as_ref() != Some(&hold)
                {
                    *kept = Some(hold);
                    put_work(store, &mut txn, &work)?;
                    txn.commit()?;
                }
            }
            QueueSealTarget::Landed { batch: id } => {
                let queue = self.queue()?;
                let mut batch = self.batch(id)?;
                if let Some(QueueRevisionLink::Pending { hold: kept, .. }) =
                    batch.drive.as_mut().and_then(|drive| drive.tested.as_mut())
                    && kept.as_ref() != Some(&hold)
                {
                    *kept = Some(hold);
                    self.save(&queue, &[&batch])?;
                }
            }
        }
        Ok(())
    }

    /// Where a seal of `target` attaches.
    pub(super) fn seal_source(
        &self,
        config: &QueueCheckConfiguration,
        target: &QueueSealTarget,
    ) -> QueueSealSource {
        match target {
            QueueSealTarget::Baseline => QueueSealSource::Init(config.init_work.clone()),
            QueueSealTarget::Landed { batch } => QueueSealSource::Batch(self.batch_key(batch)),
        }
    }
}

impl QueueRevisionSeal {
    /// The source link of this seal, read in `txn`: the green batch's or
    /// the checked-init work's.
    fn source_link(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<QueueRevisionLink>> {
        Ok(match &self.source {
            QueueSealSource::Batch(key) => BATCHES
                .get(&vault.store, txn, key)?
                .filter(|batch| batch.state == BatchState::GreenAdvanced)
                .and_then(|batch| batch.drive)
                .and_then(|drive| drive.tested),
            QueueSealSource::Init(key) => CHECK_WORK
                .get(&vault.store, txn, key)?
                .and_then(|work| work.baseline_seal),
        })
    }

    /// Whether the stored link still names this seal's revision: pending
    /// for it (`Some(false)`) or already sealed to it (`Some(true)`).
    fn names_revision(&self, link: Option<&QueueRevisionLink>) -> Option<bool> {
        let revision = self.revision.revision_id;
        match link {
            Some(QueueRevisionLink::Sealed { revision: sealed }) if *sealed == revision => {
                Some(true)
            }
            Some(QueueRevisionLink::Pending { intent, .. }) if intent.revision == revision => {
                Some(false)
            }
            _ => None,
        }
    }

    /// Checks again, in the finalizer's writer, that the source still
    /// names this revision and that every receipt the record stands on is
    /// still on the checker's rows, passing, with its verdict.
    ///
    /// # Errors
    /// A source that moved or a receipt that is gone.
    pub(crate) fn validate_sources_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        let tested = self
            .revision
            .tested_queue
            .as_ref()
            .ok_or(Error::InvalidClaimBody("not a tested queue revision"))?;
        if self
            .names_revision(self.source_link(vault, txn)?.as_ref())
            .is_none()
        {
            return Err(Error::ConcurrentWrite(
                "the seal's source no longer names this revision",
            ));
        }
        let prefix = format!("{}:", tested.store);
        let receipts: Vec<QueueCheckReceipt> = CHECK_WORK
            .scan_from(&vault.store, txn, prefix.as_bytes())?
            .into_iter()
            .flat_map(|(_, work)| work.receipts)
            .collect();
        for link in tested.fast.iter().chain(std::iter::once(&tested.slow)) {
            if !receipts.iter().any(|receipt| {
                receipt.inputs_digest == link.inputs_digest
                    && receipt.verdict_ref == link.verdict_ref
                    && receipt.tests_passed == Some(true)
            }) {
                return Err(Error::ConcurrentWrite(
                    "a receipt the seal stands on is gone",
                ));
            }
        }
        Ok(())
    }

    /// Seals the source link to this revision, in the finalizer's writer.
    ///
    /// # Errors
    /// A source that moved, or a store failure.
    pub(crate) fn attach_in_txn(&self, vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        let link = self.source_link(vault, txn)?;
        match self.names_revision(link.as_ref()) {
            Some(true) => return Ok(()),
            Some(false) => {}
            None => {
                return Err(Error::ConcurrentWrite(
                    "the seal's source no longer names this revision",
                ));
            }
        }
        let sealed = Some(QueueRevisionLink::Sealed {
            revision: self.revision.revision_id,
        });
        match &self.source {
            QueueSealSource::Batch(key) => {
                let mut batch = BATCHES
                    .get(&vault.store, txn, key)?
                    .ok_or(Error::ConcurrentWrite("the sealed batch is gone"))?;
                batch
                    .drive
                    .get_or_insert_with(QueueBatchDrive::default)
                    .tested = sealed;
                check_row_size(&BATCHES.encode_value(&batch)?)?;
                BATCHES.put(&vault.store, txn, key, &batch)?;
            }
            QueueSealSource::Init(key) => {
                let mut work = CHECK_WORK
                    .get(&vault.store, txn, key)?
                    .ok_or(Error::ConcurrentWrite("the checked-init work is gone"))?;
                work.baseline_seal = sealed;
                put_work(&vault.store, txn, &work)?;
            }
        }
        Ok(())
    }
}
