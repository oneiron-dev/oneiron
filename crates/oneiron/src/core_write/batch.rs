//! `vault.batch` (OF-181): an atomic core entity batch, the write `POST
//! /v1/core/batch` makes. Every put commits in one transaction or none
//! does. The grade it commits at is its host credential's, which no input
//! names: below owner grade, a put that turns an agent definition back on
//! is refused in the write transaction
//! ([`crate::BatchBuilder::commit_below_owner`]).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shape::{
    AnnouncementAuthority, CoreWriteTextField, core_write_times, entity_id, stage_core_put,
    text_pairs, write_id,
};
use crate::Vault;
use crate::batch::BatchBuilder;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::memory::{Memory, MemoryError, MemoryResult};

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

/// The puts to commit atomically, as many as the caller names (Rule 5).
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

/// The lane a core write's caller is held to (OF-063; FIX 1223, 6068,
/// 10781), which its host selects from the credential that sent it.
pub enum CoreWriteLane<'v> {
    /// The read the caller's credential reads under: each stored row a put
    /// names must be one it reads, and each CLAIM's typed record refs must
    /// resolve under it.
    Read(ScopedRead<'v>),
    /// For a credential that grants no read, the read its target key gives:
    /// each stored row a put names must lie inside the bounds of what the
    /// credential may write to. Its CLAIMs' refs are judged as an unbound
    /// writer's are.
    Target(ScopedRead<'v>),
    /// No bounds to judge (an owner-grade caller whose read is refused, or a
    /// caller with no read and no target key): it writes as before.
    Unbound,
}

impl CoreWriteLane<'_> {
    /// Whether this lane's caller may put at every id of `ids` in `txn`
    /// (FIX 6068, 10781): a fresh id always; a stored row only when the
    /// lane reads it, its original judged whatever it holds; the TURN doors'
    /// owner ([`Vault::turn_doors_owner`]) as before. An unbound lane puts
    /// anywhere, as before.
    pub(crate) fn admits_puts_in(
        &self,
        txn: &heed::RoTxn<'_>,
        ids: &[crate::EntityId],
    ) -> crate::Result<bool> {
        let (Self::Read(lane) | Self::Target(lane)) = self else {
            return Ok(true);
        };
        if ids.is_empty() || lane.vault().turn_doors_owner_in(lane, txn)? {
            return Ok(true);
        }
        for id in ids {
            if !crate::batch::put_target_admitted_in(lane, txn, id)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Vault {
    /// Stages every put of `input` and commits them once, at `commit`. A
    /// TURN is a platform announcement only at the owner's `announcement`.
    /// # Errors
    /// A bad id, interval or body, or the commit's
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

    /// [`Self::write_core_batch`] held to `lane` (OF-063; FIX 1223, 6068). A
    /// read lane takes a stored row a put names only when it reads that row,
    /// judged against the row in the batch's own writer before any put
    /// lands, and each CLAIM's typed record refs must resolve under it. A
    /// target lane takes a stored row only inside the bounds of what its
    /// credential may write to, judged the same way; its CLAIMs commit as an
    /// unbound writer's do. An unbound lane writes as
    /// [`Self::write_core_batch`] does.
    /// # Errors
    /// As [`Self::write_core_batch`]; a named stored row outside the lane as
    /// missing; under a read lane, a CLAIM's unresolved ref as the claim
    /// gate's denial.
    pub fn write_core_batch_in_lane(
        &self,
        input: &CoreBatchWriteInput,
        commit: CoreBatchCommit,
        announcement: AnnouncementAuthority,
        lane: &CoreWriteLane<'_>,
    ) -> MemoryResult<CoreBatchWriteReceipt> {
        let (batch, entities) = self.stage_core_batch(input, announcement)?;
        match (lane, commit) {
            (CoreWriteLane::Read(reader), CoreBatchCommit::Owner) => batch.commit_read_by(reader),
            (CoreWriteLane::Read(reader), CoreBatchCommit::BelowOwner) => {
                batch.commit_below_owner_read_by(reader, |_| Ok(()))
            }
            (CoreWriteLane::Target(_), commit) => {
                let ids = entities
                    .iter()
                    .map(|entity| entity_id(&entity.id, "id"))
                    .collect::<MemoryResult<Vec<_>>>()?;
                let guard = |txn: &heed::RoTxn<'_>| -> crate::Result<()> {
                    if lane.admits_puts_in(txn, &ids)? {
                        return Ok(());
                    }
                    // As missing: the row's kind, body and scope stay unsaid.
                    Err(crate::Error::EntityNotFound)
                };
                match commit {
                    CoreBatchCommit::Owner => batch.commit_with_target_guard(guard),
                    CoreBatchCommit::BelowOwner => batch.commit_below_owner_with_guard(guard),
                }
            }
            (CoreWriteLane::Unbound, CoreBatchCommit::Owner) => batch.commit(),
            (CoreWriteLane::Unbound, CoreBatchCommit::BelowOwner) => batch.commit_below_owner(),
        }?;
        Ok(CoreBatchWriteReceipt {
            count: entities.len(),
            entities,
        })
    }

    /// Every put of `input` staged in one batch, and its receipt rows.
    fn stage_core_batch(
        &self,
        input: &CoreBatchWriteInput,
        announcement: AnnouncementAuthority,
    ) -> MemoryResult<(BatchBuilder<'_>, Vec<CoreBatchEntityReceipt>)> {
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
    /// It is held to this handle's write lane ([`Self::core_write_lane`],
    /// FIX 1223, 6068).
    /// # Errors
    /// As [`Self::core_write_lane`] and [`Vault::write_core_batch_in_lane`].
    pub fn core_batch_write(
        &self,
        input: &CoreBatchWriteInput,
    ) -> MemoryResult<CoreBatchWriteReceipt> {
        let announcement = AnnouncementAuthority::of_actor(self.vault(), &self.actor())?;
        let lane = self.core_write_lane()?;
        self.vault().write_core_batch_in_lane(
            input,
            CoreBatchCommit::BelowOwner,
            announcement,
            &lane,
        )
    }

    /// The lane this handle's core writes are held to (OF-063; FIX 1223,
    /// 6068, 10781): its read lane; for a credential that grants no read,
    /// the lane of that credential's target key, which judges what it may
    /// write to without asking the read verb, built for the caller where it
    /// sits and inside a bound room turn as the read lane is. A credential
    /// with no target key leaves no bounds to judge: it writes unbound, as
    /// before.
    /// # Errors
    /// The read lane's refusal other than a credential that grants no read,
    /// or the target key's.
    pub(crate) fn core_write_lane(&self) -> MemoryResult<CoreWriteLane<'_>> {
        if let Some(read) = self.read_lane_if_granted(ClaimReadStatus::Recorded)? {
            return Ok(CoreWriteLane::Read(read));
        }
        let target = match self.presented_credential() {
            Some(proof) => self
                .vault()
                .credential_target_key(proof)
                .map_err(MemoryError::from)?,
            None => None,
        };
        let Some(key) = target else {
            return Ok(CoreWriteLane::Unbound);
        };
        let key = self.in_room_turn(key.for_destination(self.destination()))?;
        Ok(CoreWriteLane::Target(
            self.vault()
                .scoped_read(key)
                .with_claim_status(ClaimReadStatus::Recorded),
        ))
    }
}
