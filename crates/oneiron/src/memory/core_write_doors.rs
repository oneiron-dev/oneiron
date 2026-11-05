//! The core write doors on the `Memory` facade (OF-181): `vault.batch`,
//! `vault.conversations.create`, `vault.conversations.turns.create` and
//! `vault.conversations.records.append`, each held to the handle's write or
//! read lane and run through the core write doors on the vault.

use oneiron_contracts::memory::{MemoryError, MemoryResult};

use super::Memory;
#[cfg(doc)]
use crate::Vault;
use crate::core_write::shape::ActorAnnouncementAuthority;
use crate::core_write::{
    AnnouncementAuthority, ConversationCreateInput, ConversationTurnCreateInput, CoreBatchCommit,
    CoreBatchWriteInput, CoreBatchWriteReceipt, CoreEntityWriteReceipt, CoreWriteLane,
    DagRecordAppendInput, DagRecordAppendReceipt,
};
use crate::ports::ClaimReadStatus;

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

impl Memory<'_> {
    /// `vault.conversations.create`: a conversation, its membership
    /// authored as the bound actor, held to this handle's write lane (FIX
    /// 10781): its read, or the bounds of what a credential that grants no
    /// read may write to.
    /// # Errors
    /// As [`Vault::write_core_conversation`], and the write lane's refusal.
    pub fn conversations_create(
        &self,
        input: &ConversationCreateInput,
    ) -> MemoryResult<CoreEntityWriteReceipt> {
        let actor = self.write_actor();
        let lane = self.core_write_lane()?;
        self.vault()
            .write_core_conversation(input, Some(actor), &lane)
    }

    /// `vault.conversations.turns.create`: one TURN under a conversation,
    /// held to this handle's own read lane (FIX 5939), a platform
    /// announcement only while the bound actor is a live owner.
    /// # Errors
    /// As [`Vault::write_core_conversation_turn`].
    pub fn conversations_turns_create(
        &self,
        input: &ConversationTurnCreateInput,
    ) -> MemoryResult<CoreEntityWriteReceipt> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let announcement = AnnouncementAuthority::of_actor(self.vault(), &self.actor())?;
        self.vault()
            .write_core_conversation_turn(input, &lane, announcement)
    }
}

impl Memory<'_> {
    /// `vault.conversations.records.append`: one TURN on the DAG, or one
    /// MESSAGE of a TURN (FIX 9771), bylined
    /// the bound actor, through the append door that checks each named
    /// reference on this handle's read lane. It is a platform announcement
    /// only while the bound actor is a live owner.
    /// # Errors
    /// A bad input, or the append door's refusal.
    pub fn conversations_records_append(
        &self,
        input: &DagRecordAppendInput,
    ) -> MemoryResult<DagRecordAppendReceipt> {
        let announcement = AnnouncementAuthority::of_actor(self.vault(), &self.actor())?;
        self.conversations_records_append_at(input, announcement)
    }

    /// [`Self::conversations_records_append`] at the `announcement` a served
    /// door resolved from its credential (FIX 5968).
    /// # Errors
    /// As [`Self::conversations_records_append`].
    pub fn conversations_records_append_at(
        &self,
        input: &DagRecordAppendInput,
        announcement: AnnouncementAuthority,
    ) -> MemoryResult<DagRecordAppendReceipt> {
        let append = input.append_record(self.write_actor(), announcement)?;
        Ok(self.vault().append_dag_record(self, &append)?.into())
    }
}
