//! In-memory owner continuations; dropping the server drops pending imports.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::meeting_audio::{
    MeetingTranscriptCallerImportError, MeetingTranscriptCallerImportOutcome,
    OwnedMeetingTranscriptImportAttempt,
};
use oneiron::memory::Memory;

use crate::owner::{OwnerError, OwnerResult, memory_refusal};

#[derive(Default)]
pub(crate) struct MeetingImports {
    pending: Mutex<HashMap<EntityId, Arc<Mutex<OwnedMeetingTranscriptImportAttempt>>>>,
}

impl MeetingImports {
    pub(crate) fn retain(
        &self,
        session: EntityId,
        attempt: OwnedMeetingTranscriptImportAttempt,
    ) -> OwnerResult<()> {
        self.pending
            .lock()
            .map_err(|_| poisoned())?
            .insert(session, Arc::new(Mutex::new(attempt)));
        Ok(())
    }

    pub(crate) fn resume(
        &self,
        session: EntityId,
        current: &Memory<'_>,
        owner: &AuthenticatedOwner,
    ) -> OwnerResult<MeetingTranscriptCallerImportOutcome> {
        let attempt = self
            .pending
            .lock()
            .map_err(|_| poisoned())?
            .get(&session)
            .cloned()
            .ok_or_else(|| OwnerError::NotFound("pending meeting import", session.to_hex()))?;
        let result = attempt
            .lock()
            .map_err(|_| poisoned())?
            .resume(current, owner)
            .map_err(import_error)?;
        if matches!(result, MeetingTranscriptCallerImportOutcome::Imported(_)) {
            self.pending
                .lock()
                .map_err(|_| poisoned())?
                .remove(&session);
        }
        Ok(result)
    }

    pub(crate) fn discard(&self, session: EntityId) -> OwnerResult<bool> {
        Ok(self
            .pending
            .lock()
            .map_err(|_| poisoned())?
            .remove(&session)
            .is_some())
    }
}

pub(crate) fn import_error(error: MeetingTranscriptCallerImportError) -> OwnerError {
    match error {
        MeetingTranscriptCallerImportError::Storage(error) => error.into(),
        MeetingTranscriptCallerImportError::Caller(error) => memory_refusal(error),
        MeetingTranscriptCallerImportError::Audio(error) => OwnerError::Invalid(error.to_string()),
    }
}

fn poisoned() -> OwnerError {
    OwnerError::Host(anyhow::anyhow!("meeting import state lock poisoned"))
}
