//! The `ai.video` jobs a restart keeps (FIX-LIST 465). Each submitted job's
//! rung, provider handle and call sit in a vault side table under its
//! ticket, and so does its end once a poll sees one: a job a restart left
//! running is taken up again when the server starts (or on its next poll,
//! when that fails), and an ended job answers every poll from its row until
//! its caller deletes it. A clip's bytes sit beside the row, one key a part,
//! so the row stays small.
use std::sync::Arc;

use oneiron::llm::media::{AiOperation, MediaJobState, MediaPart, MediaRequest};
use oneiron::llm::run_admission::PayerPerson;
use oneiron::{ModelId, Vault};
use serde::{Deserialize, Serialize};

use crate::models::ladder::PendingReceipt;

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
    /// The served receipt its answer carries, when its ladder stamped one:
    /// a job taken up again still says which rung served it.
    #[serde(default)]
    pub(super) receipt: Option<PendingReceipt>,
    /// Who its submit billed when a room paid for it (FIX 805): a job taken
    /// up again bills the same payer, never its poller's. `None` is the
    /// vault owner's.
    pub(super) payer: Option<PayerPerson>,
}

/// The vault's job rows.
pub(super) struct JobStore {
    vault: Arc<Vault>,
}

impl JobStore {
    pub(super) fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }

    /// Keeps `row` as job `ticket`, its end's clip bytes beside it: the row
    /// and its clips in one write, so a refused write keeps none of them.
    pub(super) fn put(&self, ticket: &str, mut row: JobRow) -> Result<(), String> {
        let mut parts = Vec::new();
        if let Some(MediaJobState::Done { response }) = &mut row.ended {
            for (index, part) in response.parts.iter_mut().enumerate() {
                if let Some(bytes) = part_bytes(part).filter(|bytes| !bytes.is_empty()) {
                    parts.push((part_key(ticket, index), std::mem::take(bytes)));
                }
            }
        }
        let kept = rmp_serde::to_vec_named(&row).map_err(|error| error.to_string())?;
        self.vault
            .with_write_txn_grouped(|wtxn| {
                for (key, bytes) in &parts {
                    self.vault.sync_state_put_in_write_txn(wtxn, key, bytes)?;
                }
                self.vault
                    .sync_state_put_in_write_txn(wtxn, &row_key(ticket), &kept)
            })
            .map_err(|error| error.to_string())
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

    /// The ticket of every kept job, ended or not.
    pub(super) fn tickets(&self) -> Vec<String> {
        match self.vault.sync_state_keys_with_prefix(JOB) {
            Ok(keys) => keys
                .iter()
                .filter_map(|key| key.strip_prefix(JOB))
                .filter(|ticket| !ticket.contains(':'))
                .map(str::to_owned)
                .collect(),
            Err(error) => {
                tracing::error!(%error, "the kept media jobs could not be listed");
                Vec::new()
            }
        }
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
