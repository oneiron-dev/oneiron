//! `vault.conversations.records.append` (OF-181): one DAG record and its
//! topology, the write `POST /v1/core/conversations/{c}/records` makes. The
//! byline is the writer's own: the row takes no actor, and the append door
//! checks every reference it names on the writer's read lane, in the
//! append's own transaction.

use super::shape::{ActorAnnouncementAuthority, AnnouncementAuthority};
use super::{DagRecordAppendInput, DagRecordAppendReceipt};
use crate::memory::Memory;
use oneiron_contracts::memory::MemoryResult;

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
