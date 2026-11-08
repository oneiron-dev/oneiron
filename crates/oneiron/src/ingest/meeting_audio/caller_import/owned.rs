//! Host-owned continuation over the same private meeting import state.

use std::sync::Arc;

use super::*;
use crate::Vault;
use crate::memory::TranscriptRetainedCaller;

/// A nonserialized host-owned import. It owns the original authorized input
/// and keeps the original reader, not a reader rebuilt from a later request's
/// wider credential. Dropping it drops this in-memory continuation.
pub struct OwnedMeetingTranscriptImportAttempt {
    vault: Arc<Vault>,
    actor: EntityId,
    caller: TranscriptRetainedCaller,
    state: MeetingTranscriptImportState,
}

impl Vault {
    /// Prepare the same owner import for a host that must retain it between
    /// requests. `memory` must belong to this vault. The bulk callback still
    /// approves this attempt's exact artifact outside any writer.
    pub fn prepare_owned_meeting_transcript_import_as_owner<A: BulkImportAuthorizer + ?Sized>(
        self: &Arc<Self>,
        memory: &Memory<'_>,
        owner: &AuthenticatedOwner,
        stored: &StoredMeetingTranscript,
        authorizer: &mut A,
    ) -> Result<OwnedMeetingTranscriptImportAttempt> {
        check_vault(self, memory)?;
        let state = MeetingTranscriptImportState::prepare(memory, owner, stored, authorizer)?;
        Ok(OwnedMeetingTranscriptImportAttempt {
            vault: Arc::clone(self),
            actor: memory.actor(),
            caller: memory.retain_transcript_caller()?,
            state,
        })
    }
}

impl OwnedMeetingTranscriptImportAttempt {
    /// Continue as the original owner through the original reader. The current
    /// operation supplies its live owner proof and task-work turn only; its
    /// read authority never replaces this attempt's saved read authority.
    pub fn resume(
        &mut self,
        current: &Memory<'_>,
        owner: &AuthenticatedOwner,
    ) -> Result<MeetingTranscriptCallerImportOutcome> {
        check_vault(&self.vault, current)?;
        {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            check_owner(current, owner, &txn)?;
        }
        let mut memory =
            self.caller
                .memory(&self.vault, self.actor, crate::EdgeActorClass::Human)?;
        if let Some(turn) = current.task_work_turn() {
            memory = memory.with_task_work_turn(turn);
        }
        let result = self.state.resume(&memory, owner);
        self.caller.keep_narrowed_room(&memory);
        result
    }
}

fn check_vault(vault: &Vault, memory: &Memory<'_>) -> Result<()> {
    if !std::ptr::eq(vault, memory.vault()) {
        return Err(
            MemoryError::bad_request("meeting import caller belongs to another vault").into(),
        );
    }
    Ok(())
}
