//! The current green's sealed revision and its export readiness (FIX 6868,
//! G2 PR3; CALLS D and E).
//!
//! `green_revision` is a read: it finds the sealed revision of the live
//! green pointer, checks the record against the queue and issues the read
//! capability the new export takes. `queue_export_readiness` names, in one
//! place, every reason that export holds and its way out. No hold is a red
//! verdict, and nothing here approves, rebases, rechecks or retries: the
//! owner's `vault.code.export` and the owner queue doors are unchanged.
use std::collections::BTreeMap;

use super::{
    GreenQueueRevision, MergeQueue, QueueExportHold, QueueExportHoldReason, QueueGreenExportView,
    QueueRevisionIntent, QueueSealTarget,
};
use crate::code_revision::{CodeCommitMetadata, MODE_GITLINK, QueuePromotionGap};
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWire, lock_repository};
use crate::repo_mutation::proposal::RepoProposal;

type Held<T> = std::result::Result<T, QueueExportHold>;

fn held<T>(reason: QueueExportHoldReason, detail: impl Into<String>) -> Result<Held<T>> {
    Ok(Err(QueueExportHold::new(reason, detail)))
}

/// How many object ids one presence read names.
const OBJECT_READ_CHUNK: usize = 1_000;

impl MergeQueue<'_> {
    /// Runs `act` holding this queue's repository writer, which re-enters
    /// on this thread: the green pointer cannot move while it runs.
    ///
    /// # Errors
    /// The writer cannot be taken.
    pub(crate) fn with_repository_writer<T>(&self, act: impl FnOnce() -> T) -> Result<T> {
        let _guard = lock_repository(self.repo.common_dir())?;
        Ok(act())
    }

    /// CALL D "queue aggregate commit metadata": the canonical author and
    /// message of a tested revision. A landed batch is authored by its last
    /// actually landed proposal's recorded live actor, `Queue batch <id>`;
    /// the baseline by the checked-init approver, `Checked baseline
    /// <commit>`; the timestamp is the seal intent's. An erased or
    /// unavailable author holds: no synthetic person or owner stands in.
    /// Every document's reviewed mode is recorded explicitly.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn queue_commit_metadata(
        &self,
        intent: &QueueRevisionIntent,
        sources: &[RepoProposal],
        modes: &BTreeMap<[u8; 32], u32>,
    ) -> Result<Held<CodeCommitMetadata>> {
        let (author, message) = match &intent.target {
            QueueSealTarget::Baseline => {
                let Some(author) = intent.approver else {
                    return held(
                        QueueExportHoldReason::AuthorUnavailable,
                        "no checked-init approver was recorded",
                    );
                };
                (author, format!("Checked baseline {}", intent.commit))
            }
            QueueSealTarget::Landed { batch } => {
                let Some(last) = sources.last() else {
                    return held(
                        QueueExportHoldReason::AuthorUnavailable,
                        "the batch landed no source",
                    );
                };
                let Some(author) = last.actor.id() else {
                    return held(
                        QueueExportHoldReason::AuthorErased,
                        "the last landed proposal's actor was erased",
                    );
                };
                (author, format!("Queue batch {batch}"))
            }
        };
        if self.vault.get_entity_type(&author)?.is_none() {
            return held(
                QueueExportHoldReason::AuthorUnavailable,
                format!("the canonical author {} cannot be read", author.to_hex()),
            );
        }
        Ok(Ok(modes.iter().fold(
            CodeCommitMetadata::new(author, message),
            |metadata, (document, mode)| metadata.with_file_mode(*document, *mode),
        )))
    }

    /// The live green pointer's sealed tested revision, checked against
    /// this queue: its object store, its checked init and its exact commit.
    ///
    /// # Errors
    /// A store failure, or a sealed record that differs from the queue.
    pub fn green_revision(&self) -> Result<Held<GreenQueueRevision>> {
        let config = match self.initialized_configuration()? {
            Ok(config) if config.drives_queue() => config,
            _ => {
                return held(
                    QueueExportHoldReason::Unenrolled,
                    "no checked configuration drives this queue",
                );
            }
        };
        let green = self.queue()?.pointers.green;
        let Some(id) = self.sealed_at_commit(&config, &green)? else {
            return held(
                QueueExportHoldReason::SealPending,
                format!("the green {green} has no sealed tested revision yet"),
            );
        };
        let revision = self
            .vault
            .get_code_revision(&id)?
            .ok_or(Error::EntityNotFound)?;
        let store = self.repo.identity().as_hex();
        if !revision.tested_queue.as_ref().is_some_and(|tested| {
            tested.commit == green && tested.store == store && tested.init_work == config.init_work
        }) {
            return Err(Error::CorruptedIndex(
                "the sealed green record differs from its queue",
            ));
        }
        Ok(Ok(GreenQueueRevision {
            revision,
            store,
            commit: green,
        }))
    }

    /// CALL E "export readiness": whether `export_green` can export the
    /// green now, or the one named hold it waits on. A retry runs the same
    /// frozen request again; nothing is approved, rebased, rechecked or
    /// pushed to make it pass, and there is no timeout or ceiling.
    ///
    /// # Errors
    /// A store or object store failure.
    pub fn queue_export_readiness(&self, green: &GreenQueueRevision) -> Result<Held<()>> {
        let revision = green.revision();
        let Some(metadata) = &revision.commit_metadata else {
            return held(
                QueueExportHoldReason::AuthorUnavailable,
                "the tested revision has no canonical author",
            );
        };
        if self.vault.get_entity_type(&metadata.author)?.is_none() {
            return held(
                QueueExportHoldReason::AuthorErased,
                format!(
                    "the canonical author {} was erased",
                    metadata.author.to_hex()
                ),
            );
        }
        if let Some(path) = revision
            .blob_frontiers
            .iter()
            .find_map(|(path, blob)| (blob.mode == MODE_GITLINK).then_some(path))
        {
            return held(
                QueueExportHoldReason::HeldUnsupportedTree,
                format!("{path} is a submodule link"),
            );
        }
        let oids = revision
            .blob_frontiers
            .values()
            .map(|blob| GitOid::parse_hex(blob.git_oid.clone()))
            .collect::<Result<Vec<_>>>()?;
        let wire = GitWire::new(self.vault)?;
        for chunk in oids.chunks(OBJECT_READ_CHUNK) {
            let present = wire.object_info(&self.repo, chunk)?;
            if let Some(missing) = chunk.iter().find(|oid| !present.contains_key(*oid)) {
                return held(
                    QueueExportHoldReason::HeldObject,
                    format!("object {} is not in the object store", missing.as_str()),
                );
            }
        }
        match self.vault.queue_promotion_gap(revision.revision_id)? {
            None => Ok(Ok(())),
            Some(QueuePromotionGap::UntouchedBytes(detail)) => {
                held(QueueExportHoldReason::HeldUntouchedPromotion, detail)
            }
            Some(QueuePromotionGap::Unreviewed(detail)) => {
                held(QueueExportHoldReason::HeldUnreviewedChange, detail)
            }
        }
    }

    /// The current green's export readiness for the queue's status. A read
    /// that fails is its own `unavailable` hold, never a ready answer.
    #[must_use]
    pub fn green_export_view(&self) -> QueueGreenExportView {
        let green_commit = self
            .read_queue()
            .ok()
            .flatten()
            .map(|queue| queue.pointers.green)
            .unwrap_or_default();
        let readiness = self.green_revision().and_then(|green| match green {
            Ok(green) => Ok((
                Some(green.revision_id().to_hex()),
                self.queue_export_readiness(&green)?.err(),
            )),
            Err(hold) => Ok((None, Some(hold))),
        });
        let (tested_revision, hold) = readiness.unwrap_or_else(|error| {
            (
                None,
                Some(QueueExportHold::new(
                    QueueExportHoldReason::Unavailable,
                    error.to_string(),
                )),
            )
        });
        QueueGreenExportView {
            green_commit,
            tested_revision,
            hold,
        }
    }
}
