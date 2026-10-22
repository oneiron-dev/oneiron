//! `vault.batch` (OF-181): an atomic core entity batch, the write `POST
//! /v1/core/batch` makes. Every put commits in one transaction or none
//! does. The grade it commits at is its host credential's, which no input
//! names: below owner grade, a put that turns an agent definition back on
//! is refused in the write transaction
//! ([`crate::BatchBuilder::commit_below_owner`]).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shape::{
    AnnouncementAuthority, CORE_MAX_BATCH_ENTITIES, CoreWriteTextField, core_write_times,
    entity_id, stage_core_put, text_pairs, write_id,
};
use crate::Vault;
use crate::batch::BatchBuilder;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// One entity put in a batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchEntityInput {
    /// The entity's id; a fresh one when omitted.
    #[serde(default)]
    pub id: Option<String>,
    /// The entity type byte.
    #[serde(alias = "entityType")]
    pub entity_type: u8,
    #[serde(default, alias = "occurredStart")]
    pub occurred_start: Option<u64>,
    #[serde(default, alias = "occurredEnd")]
    pub occurred_end: Option<u64>,
    #[serde(default, alias = "learnedAt")]
    pub learned_at: Option<u64>,
    pub body: Value,
    #[serde(default)]
    pub text: Option<Vec<CoreWriteTextField>>,
}

/// The puts to commit atomically, at most [`CORE_MAX_BATCH_ENTITIES`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchWriteInput {
    pub entities: Vec<CoreBatchEntityInput>,
}

/// One put a batch committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchEntityReceipt {
    pub id: String,
    pub entity_type: u8,
}

/// The puts a batch committed, in input order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchWriteReceipt {
    pub count: usize,
    pub entities: Vec<CoreBatchEntityReceipt>,
}

/// The grade a batch commits at, which its host selects from the
/// credential that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreBatchCommit {
    Owner,
    BelowOwner,
}

impl Vault {
    /// Stages every put of `input` and commits them once, at `commit`. A
    /// TURN is a platform announcement only at the owner's `announcement`.
    /// # Errors
    /// Too many entities, a bad id, interval or body, or the commit's
    /// refusal; nothing is written then.
    pub fn write_core_batch(
        &self,
        input: &CoreBatchWriteInput,
        commit: CoreBatchCommit,
        announcement: AnnouncementAuthority,
    ) -> MemoryResult<CoreBatchWriteReceipt> {
        let (batch, entities) = self.stage_core_batch(input, announcement)?;
        match commit {
            CoreBatchCommit::Owner => batch.commit(),
            CoreBatchCommit::BelowOwner => batch.commit_below_owner(),
        }?;
        Ok(CoreBatchWriteReceipt {
            count: entities.len(),
            entities,
        })
    }

    /// [`Self::write_core_batch`] for a caller its host bound to `reader`
    /// (OF-063, FIX 1223, 6068): each id a put names that a stored row holds
    /// must be a row `reader` reads, judged against that row in the batch's
    /// own writer before any put lands, and each CLAIM's typed record refs
    /// must resolve under `reader`. `None` is a caller whose credential
    /// grants no read: it puts only fresh rows, and no CLAIM.
    /// # Errors
    /// As [`Self::write_core_batch`]; a named stored row outside `reader` as
    /// missing; a CLAIM's unresolved ref as the claim gate's denial; a CLAIM
    /// or a stored row's id from a caller with no read as forbidden.
    pub fn write_core_batch_read_by(
        &self,
        input: &CoreBatchWriteInput,
        commit: CoreBatchCommit,
        announcement: AnnouncementAuthority,
        reader: Option<&ScopedRead<'_>>,
    ) -> MemoryResult<CoreBatchWriteReceipt> {
        let (batch, entities) = self.stage_core_batch(input, announcement)?;
        match (reader, commit) {
            (Some(reader), CoreBatchCommit::Owner) => batch.commit_read_by(reader),
            (Some(reader), CoreBatchCommit::BelowOwner) => {
                batch.commit_below_owner_read_by(reader, |_| Ok(()))
            }
            (None, commit) => return self.commit_core_batch_unread(batch, &entities, commit),
        }?;
        Ok(CoreBatchWriteReceipt {
            count: entities.len(),
            entities,
        })
    }

    /// Commits a staged core batch for a caller with no read: refused
    /// forbidden when it names a CLAIM, whose refs only a read resolves, or
    /// an id a stored row holds, judged in the batch's own writer (OF-063,
    /// FIX 1223, 6068).
    fn commit_core_batch_unread(
        &self,
        batch: BatchBuilder<'_>,
        entities: &[CoreBatchEntityReceipt],
        commit: CoreBatchCommit,
    ) -> MemoryResult<CoreBatchWriteReceipt> {
        let unread = || {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "this credential grants no read, and the batch names a CLAIM or a stored row",
                &["Write fresh rows that are no CLAIM, or use a credential that reads."],
            )
        };
        if entities
            .iter()
            .any(|entity| entity.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        {
            return Err(unread());
        }
        let ids = entities
            .iter()
            .map(|entity| entity_id(&entity.id, "id"))
            .collect::<MemoryResult<Vec<_>>>()?;
        let stored = std::cell::Cell::new(false);
        let guard = |txn: &heed::RoTxn<'_>| -> crate::Result<()> {
            for id in &ids {
                if crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, id)? {
                    stored.set(true);
                    return Err(crate::Error::EntityNotFound);
                }
            }
            Ok(())
        };
        let committed = match commit {
            CoreBatchCommit::Owner => batch.commit_with_target_guard(guard),
            CoreBatchCommit::BelowOwner => batch.commit_below_owner_with_guard(guard),
        };
        if stored.get() {
            return Err(unread());
        }
        committed?;
        Ok(CoreBatchWriteReceipt {
            count: entities.len(),
            entities: entities.to_vec(),
        })
    }

    /// Every put of `input` staged in one batch, and its receipt rows.
    fn stage_core_batch(
        &self,
        input: &CoreBatchWriteInput,
        announcement: AnnouncementAuthority,
    ) -> MemoryResult<(BatchBuilder<'_>, Vec<CoreBatchEntityReceipt>)> {
        if input.entities.len() > CORE_MAX_BATCH_ENTITIES {
            return Err(MemoryError::bad_request(format!(
                "entities must contain at most {CORE_MAX_BATCH_ENTITIES} entries"
            )));
        }
        let mut batch = self.batch();
        let mut entities = Vec::with_capacity(input.entities.len());
        for entity in &input.entities {
            // A thread binding is its room door's to stamp (FIX 2951), and
            // an audience edit its thread's audience door's (FIX 5545).
            if entity.entity_type == crate::registry::ENTITY_TYPE_TURN
                && [
                    crate::workspace_roster::ROOM_THREAD_KEY,
                    crate::workspace_roster::ROOM_THREAD_AUDIENCE_KEY,
                ]
                .iter()
                .any(|key| entity.body.get(*key).is_some())
            {
                return Err(MemoryError::bad_request(
                    "a TURN's room_thread and room_thread_audience are stamped by its room's thread doors",
                ));
            }
            let id = write_id(entity.id.as_deref())?;
            let times = core_write_times(
                entity.occurred_start,
                entity.occurred_end,
                entity.learned_at,
            )?;
            batch = stage_core_put(
                batch,
                &id,
                entity.entity_type,
                times,
                &entity.body,
                announcement,
                entity.text.as_deref().map(text_pairs),
            )?;
            entities.push(CoreBatchEntityReceipt {
                id: id.to_hex(),
                entity_type: entity.entity_type,
            });
        }
        Ok((batch, entities))
    }
}

impl Memory<'_> {
    /// `vault.batch` on an embedded handle, which carries no credential
    /// grade: it commits below owner grade, never above it. Its TURNs are
    /// platform announcements only while the bound actor is a live owner.
    /// It is held to this handle's own read lane (FIX 1223, 6068).
    /// # Errors
    /// As [`Vault::write_core_batch_read_by`].
    pub fn core_batch_write(
        &self,
        input: &CoreBatchWriteInput,
    ) -> MemoryResult<CoreBatchWriteReceipt> {
        let announcement = AnnouncementAuthority::of_actor(self.vault(), &self.actor())?;
        // A handle whose credential grants no read writes as one with none.
        let lane = self.read_lane(ClaimReadStatus::Recorded).ok();
        self.vault().write_core_batch_read_by(
            input,
            CoreBatchCommit::BelowOwner,
            announcement,
            lane.as_ref(),
        )
    }
}
