//! The `ai.video` jobs a restart keeps (FIX-LIST 465). Each submitted job's
//! rung, provider handle and call sit in a vault side table under its
//! ticket, and so does its end once a poll sees one: a job a restart left
//! running is taken up again on its next poll, and an ended job answers
//! every poll from its row until its caller deletes it. A clip's bytes sit
//! beside the row, one key a part, so the row stays small.
use std::sync::Arc;

use oneiron::llm::media::{AiOperation, MediaJobState, MediaPart, MediaRequest};
use oneiron::{ModelId, Vault};
use serde::{Deserialize, Serialize};

/// The rows' prefix: the declared `MODEL_MEDIA_JOB` family.
const JOB: &str = "models:media-job:v1:";

/// One submitted job, as a restart finds it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct JobRow {
    /// The rung that took the job (its engine id).
    pub(super) model: ModelId,
    pub(super) operation: AiOperation,
    /// The provider's own id for the job; no caller sees it.
    pub(super) provider_job: String,
    /// The call as its caller sent it. A job taken up again is admitted
    /// on it, bound to its rung afresh.
    pub(super) request: MediaRequest,
    /// Where the job ended, once a poll saw it.
    #[serde(default)]
    pub(super) ended: Option<MediaJobState>,
}

/// The vault's job rows.
pub(super) struct JobStore {
    vault: Arc<Vault>,
}

impl JobStore {
    pub(super) fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }

    /// Keeps `row` as job `ticket`, its end's clip bytes beside it. A row
    /// the vault refuses is logged: the job still runs, held, until a
    /// restart.
    pub(super) fn put(&self, ticket: &str, mut row: JobRow) {
        if let Some(MediaJobState::Done { response }) = &mut row.ended {
            for (index, part) in response.parts.iter_mut().enumerate() {
                let Some(bytes) = part_bytes(part).filter(|bytes| !bytes.is_empty()) else {
                    continue;
                };
                let bytes = std::mem::take(bytes);
                if let Err(error) = self.vault.sync_state_put(&part_key(ticket, index), &bytes) {
                    tracing::error!(%error, ticket, "a media job's clip was not kept");
                    return;
                }
            }
        }
        let kept = rmp_serde::to_vec_named(&row)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                self.vault
                    .sync_state_put(&row_key(ticket), &bytes)
                    .map_err(|error| error.to_string())
            });
        if let Err(error) = kept {
            tracing::error!(%error, ticket, "a media job was not kept");
        }
    }

    /// Job `ticket`'s row, its clips' bytes back in place.
    pub(super) fn get(&self, ticket: &str) -> Option<JobRow> {
        let bytes = match self.vault.sync_state_get(&row_key(ticket)) {
            Ok(bytes) => bytes?,
            Err(error) => {
                tracing::error!(%error, ticket, "a media job could not be read");
                return None;
            }
        };
        let mut row: JobRow = match rmp_serde::from_slice(&bytes) {
            Ok(row) => row,
            Err(error) => {
                tracing::error!(%error, ticket, "a media job's row does not decode");
                return None;
            }
        };
        if let Some(MediaJobState::Done { response }) = &mut row.ended {
            for (index, part) in response.parts.iter_mut().enumerate() {
                let Some(bytes) = part_bytes(part).filter(|bytes| bytes.is_empty()) else {
                    continue;
                };
                if let Ok(Some(kept)) = self.vault.sync_state_get(&part_key(ticket, index)) {
                    *bytes = kept;
                }
            }
        }
        Some(row)
    }

    /// Drops job `ticket`'s row and its clips.
    pub(super) fn remove(&self, ticket: &str) {
        let row = row_key(ticket);
        let mut keys = self
            .vault
            .sync_state_keys_with_prefix(&format!("{row}:"))
            .unwrap_or_default();
        keys.push(row);
        for key in keys {
            if let Err(error) = self.vault.sync_state_delete(&key) {
                tracing::error!(%error, ticket, "a media job's row was not dropped");
            }
        }
    }
}

fn row_key(ticket: &str) -> String {
    format!("{JOB}{ticket}")
}

fn part_key(ticket: &str, index: usize) -> String {
    format!("{JOB}{ticket}:part:{index}")
}

/// The bytes a part carries, when it is one that carries bytes.
fn part_bytes(part: &mut MediaPart) -> Option<&mut Vec<u8>> {
    match part {
        MediaPart::Image { bytes, .. }
        | MediaPart::Audio { bytes, .. }
        | MediaPart::Video { bytes, .. } => Some(bytes),
        MediaPart::Text { .. } | MediaPart::Embedding { .. } => None,
    }
}
