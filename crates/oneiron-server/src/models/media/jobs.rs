//! The `ai.video` jobs a restart keeps (FIX-LIST 465). Each submitted job's
//! rung, provider handle and call sit in a vault side table under its
//! ticket, and so does its end once a poll sees one: a job a restart left
//! running is taken up again when the server starts (or on its next poll,
//! when that fails), and an ended job answers every poll from its row until
//! its caller deletes it. A clip's bytes sit beside the row, one key a part,
//! so the row stays small.
//!
//! Each row and its clips are one body instance each under the vault's body
//! custody (KS-2B2, FIX 5683 part B2), bound lazily when a checkpoint carries
//! them. The row keeps the stamps that name its owners from its submit
//! ([`custody`]), and an erase of an owner leaves its erased form: the job's
//! skeleton with its request scrubbed and its end terminal, and no clips.
//! An erased job is never written again ([`JobStore::put`]), taken up,
//! resumed or resubmitted; every poll answers its erased end. A deleted job
//! is gone with its clips in one write, and a late end never writes it back
//! ([`JobStore::update`], FIX 9511).
use std::sync::Arc;

use oneiron::llm::media::{AiOperation, MediaJobState, MediaPart, MediaRequest};
use oneiron::llm::run_admission::PayerPerson;
use oneiron::store::ResponseStamps;
use oneiron::{ModelId, Vault};
use serde::{Deserialize, Serialize};

use super::job_lifecycle::JobWrite;
use super::run_line::JobLine;
use crate::models::ladder::PendingReceipt;

mod custody;

pub(super) use custody::{erased_poll, submit_stamps};

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
    /// Who owns its content, stamped at its submit and kept at its end: the
    /// actor that asked, the subject, the source rows. Never its payer
    /// (KS-2B2).
    #[serde(default)]
    pub(super) stamps: ResponseStamps,
    /// An erase of an owner took its content: the row is its erased form
    /// (KS-2B2).
    #[serde(default)]
    pub(super) erased: bool,
    /// The run line its submit spent on when a program's run submitted it
    /// (FIX 780, 6083): a job taken up again settles on that run's line,
    /// never the media meter. `None` is the media meter's.
    #[serde(default)]
    pub(super) line: Option<JobLine>,
}

/// A kept job as its row reads (FIX 9390): the row, or the erased marker of
/// a retired job whose row never decoded, which answers as an erased job.
pub(super) enum KeptJob {
    Row(JobRow),
    Erased,
}

impl KeptJob {
    /// The row, unless an erase took the job: its erased form, or the
    /// marker. An erased job is never written again, taken up, resumed or
    /// resubmitted (KS-2B2).
    pub(super) fn live(self) -> Option<JobRow> {
        match self {
            Self::Row(row) if !row.erased => Some(row),
            Self::Row(_) | Self::Erased => None,
        }
    }

    /// Whether an erase took the job.
    pub(super) fn erased(&self) -> bool {
        match self {
            Self::Row(row) => row.erased,
            Self::Erased => true,
        }
    }
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
    /// `false` when an erase took the job first: nothing is written, so no
    /// end puts erased content back (KS-2B2).
    pub(super) fn put(&self, ticket: &str, row: JobRow) -> Result<bool, String> {
        let (kept, parts) = encoded(ticket, row)?;
        self.vault
            .media_job_put(&row_key(ticket), &kept, &parts)
            .map_err(|error| error.to_string())
    }

    /// Keeps `row` over job `ticket`'s kept row, as [`Self::put`] keeps
    /// one, and only while that row is there (FIX 9511): a job a delete
    /// dropped meanwhile is not written back, and neither are its clips.
    pub(super) fn update(&self, ticket: &str, row: JobRow) -> Result<JobWrite, String> {
        let (kept, parts) = encoded(ticket, row)?;
        let written = self
            .vault
            .media_job_update(&row_key(ticket), &kept, &parts)
            .map_err(|error| error.to_string())?;
        // Nothing was written: an erase took the job, or a delete dropped it.
        Ok(match written {
            true => JobWrite::Kept,
            false if self.get(ticket).is_some_and(|kept| kept.erased()) => JobWrite::Erased,
            false => JobWrite::Deleted,
        })
    }

    /// Job `ticket`'s row, its clips' bytes back in place; the erased
    /// marker of a retired job whose row never decoded reads as erased,
    /// before any decode (FIX 9390).
    pub(super) fn get(&self, ticket: &str) -> Option<KeptJob> {
        let key = row_key(ticket);
        let bytes = match self.vault.sync_state_get(&key) {
            Ok(bytes) => bytes?,
            Err(error) => {
                tracing::error!(%error, ticket, "a media job could not be read");
                return None;
            }
        };
        let Ok(bytes) = oneiron::store::media_response_read(key.as_bytes(), &bytes) else {
            return Some(KeptJob::Erased);
        };
        let mut row: JobRow = match rmp_serde::from_slice(bytes) {
            Ok(row) => row,
            Err(error) => {
                tracing::error!(%error, ticket, "a media job's row does not decode");
                return None;
            }
        };
        // An erased job's clips went with its content.
        if !row.erased
            && let Some(MediaJobState::Done { response }) = &mut row.ended
        {
            for (index, part) in response.parts.iter_mut().enumerate() {
                let Some(bytes) = part_bytes(part).filter(|bytes| bytes.is_empty()) else {
                    continue;
                };
                if let Ok(Some(kept)) = self.vault.sync_state_get(&part_key(ticket, index)) {
                    *bytes = kept;
                }
            }
        }
        Some(KeptJob::Row(row))
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

    /// Drops job `ticket`'s row and its clips in one write (FIX 9511): a
    /// delete, which keeps every custody key, never an erase (KS-2B2). A
    /// write the vault refuses drops nothing, and says so.
    pub(super) fn delete(&self, ticket: &str) -> Result<(), String> {
        let row = row_key(ticket);
        let clips = format!("{row}:");
        self.vault
            .try_with_write_txn_grouped(|txn| {
                let mut keys = Vec::new();
                self.vault
                    .sync_state_visit_prefix_in_write_txn(txn, &clips, |key, _| {
                        keys.push(key.to_owned());
                        Ok::<_, oneiron::Error>(())
                    })?;
                keys.push(row.clone());
                for key in &keys {
                    self.vault.sync_state_delete_in_write_txn(txn, key)?;
                }
                Ok::<_, oneiron::Error>(())
            })
            .map_err(|error| error.to_string())
    }
}

/// `row` as job `ticket`'s kept bytes, and its end's clips, each under its
/// own key, taken out of the row.
fn encoded(ticket: &str, mut row: JobRow) -> Result<(Vec<u8>, Vec<(String, Vec<u8>)>), String> {
    let mut parts = Vec::new();
    if let Some(MediaJobState::Done { response }) = &mut row.ended {
        for (index, part) in response.parts.iter_mut().enumerate() {
            if let Some(bytes) = part_bytes(part).filter(|bytes| !bytes.is_empty()) {
                parts.push((part_key(ticket, index), std::mem::take(bytes)));
            }
        }
    }
    let kept = rmp_serde::to_vec_named(&row).map_err(|error| error.to_string())?;
    Ok((kept, parts))
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
