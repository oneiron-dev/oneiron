//! Pinned artifact publications on the owner lane: each owed one goes out in
//! bounded parts once the NOTE session binds, a part at a time and a turn
//! for each publication (FIX 9575), and again while the server answers
//! `Staged`.
use std::time::{Duration, Instant};

use super::SyncClient;
use crate::EntityId;
use crate::artifact_hosting::{
    ArtifactPublicationCursor, ArtifactPublicationOutcome, ArtifactPublicationPart,
    ArtifactPublicationStep,
};

/// How long a sent publication waits for its receipt before it goes again,
/// counted from its last part: a round waits, never each part. A `Staged`
/// one waits for window sync to deliver what it names.
const ARTIFACT_PUBLICATION_RESEND: Duration = Duration::from_secs(5);

impl SyncClient {
    /// Fills `slot`, when it is empty, with the next publication part due
    /// on this connection; `true` when it did. The server applies a
    /// publication only from the vault owner's bound session, so none goes
    /// before it. A publication that does not prepare is reported and stays
    /// owed; the next pull moves on to the next one.
    pub(crate) fn pull_artifact_publication(
        &mut self,
        cursor: &mut ArtifactPublicationCursor,
        slot: &mut Option<ArtifactPublicationPart>,
    ) -> crate::Result<bool> {
        if slot.is_some()
            || !self.note_session_bound
            || self.config.note_session.is_none()
            || self.config.federation_peer.is_some()
        {
            return Ok(false);
        }
        let now = Instant::now();
        self.artifact_publication_resend.retain(|_, at| *at > now);
        let waiting = &self.artifact_publication_resend;
        let due = |digest: &[u8; 32]| !waiting.contains_key(digest);
        match self.vault.next_artifact_publication_step(cursor, &due)? {
            ArtifactPublicationStep::Ready(part) => {
                *slot = Some(part);
                Ok(true)
            }
            ArtifactPublicationStep::ItemError { entity, error } => {
                let _ = self.event_tx.send(super::SyncEvent::Error(format!(
                    "Artifact publication {} did not prepare: {error}",
                    entity.to_hex()
                )));
                Ok(false)
            }
            ArtifactPublicationStep::Idle => Ok(false),
        }
    }

    /// Whether `part` may still go: its frame is not withheld, and its
    /// pointer still owes the change it carries.
    pub(crate) fn artifact_publication_part_current(&self, part: &ArtifactPublicationPart) -> bool {
        !self.frame_withheld(&part.frame)
            && self
                .vault
                .artifact_publication_part_current(part)
                .unwrap_or(false)
    }

    /// Moves `cursor` past `part`, which the socket took (`sent`) or which
    /// was dropped unsent. A round's last part sent starts its wait for the
    /// receipt.
    pub(crate) fn artifact_publication_released(
        &mut self,
        cursor: &mut ArtifactPublicationCursor,
        part: &ArtifactPublicationPart,
        sent: bool,
    ) {
        if cursor.released(part, sent) {
            self.artifact_publication_resend
                .insert(part.digest, Instant::now() + ARTIFACT_PUBLICATION_RESEND);
        }
    }

    /// `Applied` and `Refused` clear the outbox row the receipt names; a
    /// `Staged` one keeps it, and its resend time stands.
    pub(super) fn accept_artifact_receipt(
        &self,
        entity: EntityId,
        payload: &[u8],
    ) -> crate::Result<()> {
        if self
            .vault
            .accept_artifact_publication_receipt(entity, payload)?
            == ArtifactPublicationOutcome::Refused
        {
            let _ = self.event_tx.send(super::SyncEvent::Error(
                "the sync server refused an artifact publication".to_owned(),
            ));
        }
        Ok(())
    }
}
