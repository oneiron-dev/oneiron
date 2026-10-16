//! Pinned artifact publications on the owner lane: each owed one goes out once
//! the NOTE session binds, and again while the server answers `Staged`.
use std::time::{Duration, Instant};

use super::SyncClient;
use crate::EntityId;
use crate::artifact_hosting::ArtifactPublicationOutcome;

/// How long a sent publication waits for its receipt before it goes again.
/// A `Staged` one waits for window sync to deliver what it names.
const ARTIFACT_PUBLICATION_RESEND: Duration = Duration::from_secs(5);

impl SyncClient {
    /// The publication frames due on this connection now. The server applies
    /// one only from the vault owner's bound session, so none goes before it.
    pub(crate) fn due_artifact_publication_frames(&mut self) -> crate::Result<Vec<Vec<u8>>> {
        if !self.note_session_bound
            || self.config.note_session.is_none()
            || self.config.federation_peer.is_some()
        {
            return Ok(Vec::new());
        }
        let owed = self.vault.artifact_publication_frames()?;
        self.artifact_publication_resend
            .retain(|digest, _| owed.iter().any(|owed| owed.digest == *digest));
        let now = Instant::now();
        let mut due = Vec::new();
        for owed in owed {
            if self
                .artifact_publication_resend
                .get(&owed.digest)
                .is_some_and(|at| *at > now)
            {
                continue;
            }
            self.artifact_publication_resend
                .insert(owed.digest, now + ARTIFACT_PUBLICATION_RESEND);
            due.push(owed.frame);
        }
        Ok(due)
    }

    /// `Applied` and `Refused` clear the outbox row the receipt names; a
    /// `Staged` one keeps it, and its resend time stands.
    pub(super) fn accept_artifact_receipt(
        &self,
        entity: EntityId,
        payload: &[u8],
    ) -> crate::Result<()> {
        if self.vault.accept_artifact_publication_receipt(entity, payload)?
            == ArtifactPublicationOutcome::Refused
        {
            let _ = self.event_tx.send(super::SyncEvent::Error(
                "the sync server refused an artifact publication".to_owned(),
            ));
        }
        Ok(())
    }
}
