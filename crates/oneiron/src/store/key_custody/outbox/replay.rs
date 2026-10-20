//! The outstanding batch's keyless record, and the intake of its ack (FIX
//! 5899).
//!
//! `<journal>/outbox/o.<target id hex>` (named MessagePack) records the one
//! batch a member's slot holds: its position, head object id, set revision
//! and whether its head is wrapped to the vault data key, and, once the
//! control plane acknowledged it, that ack. It is written before a byte of
//! the batch is staged and removed only once the journal accepted the ack,
//! or once the batch left the outbox unacknowledged. A restart therefore
//! takes the original batch's ack in without sealing it again, and never
//! takes an ack against another batch. It holds no key.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::super::files::{open_dir, read_whole, replace_file};
use super::super::log::Journal;
use super::super::platform;
use super::super::protocol::{
    AckPosition, AckRecord, BatchFacts, Lineage, PendingCode, TargetId, TargetPending, TargetSpec,
    hex,
};
use super::{OutboxTarget, files};

const OUTBOX: &str = "outbox";
const RECORD_VERSION: u8 = 1;

/// An answer in the outbox the vault's user does not own, owner-only.
const NOT_OWNED: &str =
    "the CP's custody answer in the outbox is not a 0600 file of the vault's user";
const NOT_PARSED: &str = "the CP's custody acknowledgement is not an exact AckRecord";
const NOT_MATCHED: &str = "the CP's custody acknowledgement does not match its batch";

fn record_corrupt() -> Error {
    Error::CorruptedIndex("key custody outbox record")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordWire {
    version: u8,
    position: AckPosition,
    head_object_id: [u8; 32],
    set_revision: u64,
    data_key: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ack: Option<AckRecord>,
}

/// A member's outstanding batch, as its record keeps it.
pub(super) struct Retained {
    pub(super) facts: BatchFacts,
    /// The control plane's ack, once it was checked and kept.
    pub(super) ack: Option<AckRecord>,
}

fn record(journal: &Journal, id: &TargetId) -> (PathBuf, String) {
    (
        journal.dir().join(OUTBOX),
        format!("o.{}", hex(id.as_str().as_bytes())),
    )
}

/// The member `id`'s outstanding batch, if one is recorded.
pub(super) fn load(journal: &Journal, id: &TargetId) -> Result<Option<Retained>> {
    let (dir, name) = record(journal, id);
    let Some(bytes) = read_whole(&dir.join(name))? else {
        return Ok(None);
    };
    let wire: RecordWire = rmp_serde::from_slice(&bytes).map_err(|_| record_corrupt())?;
    if wire.version != RECORD_VERSION {
        return Err(record_corrupt());
    }
    Ok(Some(Retained {
        facts: BatchFacts {
            position: wire.position.position().ok_or_else(record_corrupt)?,
            head_object_id: wire.head_object_id,
            set_revision: wire.set_revision,
            data_key: wire.data_key,
        },
        ack: wire.ack,
    }))
}

/// Records the member `id`'s outstanding batch `facts`, with the ack the
/// control plane gave for it once there is one; synced.
pub(super) fn keep(
    journal: &Journal,
    id: &TargetId,
    facts: &BatchFacts,
    ack: Option<&AckRecord>,
) -> Result<()> {
    let (dir, name) = record(journal, id);
    open_dir(journal.dir(), true, None)?;
    open_dir(&dir, true, None)?;
    let wire = RecordWire {
        version: RECORD_VERSION,
        position: AckPosition::of(&facts.position),
        head_object_id: facts.head_object_id,
        set_revision: facts.set_revision,
        data_key: facts.data_key,
        ack: ack.cloned(),
    };
    let bytes = rmp_serde::to_vec_named(&wire).map_err(|_| record_corrupt())?;
    replace_file(&dir, &name, &bytes)
}

/// Removes the member `id`'s record, durably.
pub(super) fn release(journal: &Journal, id: &TargetId) -> Result<()> {
    let (dir, name) = record(journal, id);
    match fs::remove_file(dir.join(name)) {
        Ok(()) => platform::sync_dir(&dir),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// What the outstanding batch's directory shows.
pub(super) enum Found {
    /// No directory: never exposed, or dropped before an ack.
    Gone,
    /// Complete, its READY marker not written yet: a crash came first.
    Unmarked,
    /// READY, no ack yet; Hypnos's pending note when it wrote one.
    Waiting(Option<TargetPending>),
    /// An ack naming exactly this batch.
    Acked(Box<AckRecord>),
    /// An ack that is not the vault user's file, not an exact AckRecord,
    /// or not this batch's.
    Refused(&'static str),
}

enum Answer {
    None,
    NotOwned,
    Bytes(Vec<u8>),
}

/// The file Hypnos wrote at `path`: a regular 0600 file of the vault's
/// user, opened without following a link.
fn answer(path: &Path) -> Result<Answer> {
    match read_whole(path) {
        Ok(Some(bytes)) => Ok(Answer::Bytes(bytes)),
        Ok(None) => Ok(Answer::None),
        Err(Error::CorruptedIndex(_)) => Ok(Answer::NotOwned),
        Err(error) => Err(error),
    }
}

fn failed(detail: &str) -> TargetPending {
    TargetPending {
        code: PendingCode::Failed,
        detail: detail.to_owned(),
    }
}

/// Reads the outstanding batch `facts` names in `slot` for `spec`. An ack
/// must parse strictly as the exact [`AckRecord`] (no wrapper, no unknown
/// field) and name this member and this batch: its set revision, position,
/// head object id and operation id, with evidence its scope admits.
pub(super) fn examine(
    journal: &Journal,
    slot: &Path,
    spec: &TargetSpec,
    facts: &BatchFacts,
) -> Result<Found> {
    let dir = slot.join(files::batch_name(facts));
    match fs::symlink_metadata(&dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Ok(Found::Refused(
                "the outstanding custody batch in the outbox is not a directory",
            ));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Found::Gone),
        Err(err) => return Err(err.into()),
    }
    if !files::exists(&dir.join(files::READY))? {
        return Ok(Found::Unmarked);
    }
    match answer(&dir.join(files::ACK))? {
        Answer::None => {}
        Answer::NotOwned => return Ok(Found::Refused(NOT_OWNED)),
        Answer::Bytes(bytes) => {
            let Ok(ack) = serde_json::from_slice::<AckRecord>(&bytes) else {
                return Ok(Found::Refused(NOT_PARSED));
            };
            if ack.target_id != spec.id().as_str() {
                return Ok(Found::Refused(NOT_MATCHED));
            }
            return match journal.check_ack(facts, &ack) {
                Ok(_) => Ok(Found::Acked(Box::new(ack))),
                Err(Error::InvalidConfig(_)) => Ok(Found::Refused(NOT_MATCHED)),
                Err(error) => Err(error),
            };
        }
    }
    Ok(Found::Waiting(match answer(&dir.join(files::PENDING))? {
        Answer::None => None,
        Answer::NotOwned => Some(failed(NOT_OWNED)),
        Answer::Bytes(bytes) => {
            Some(serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                failed("the outbox's pending note is not an exact TargetPending")
            }))
        }
    }))
}

impl OutboxTarget {
    /// Takes in the control plane's ack of this member's outstanding batch,
    /// before a pass reads the acks: checked against the batch's record, kept
    /// in it, every local copy of the batch removed and synced, and only then
    /// accepted by the journal, against that same batch; the record goes
    /// last. A batch that left the outbox unacknowledged is released for the
    /// next one, and one a crash left without READY is marked. Never an
    /// error: what does not go through, the member's publication names.
    pub(in crate::store::key_custody) fn take_in(&self, journal: &Journal) {
        if let Err(error) = self.try_take_in(journal) {
            tracing::debug!(
                target_id = %self.id(),
                %error,
                "the custody outbox's acknowledgement was not taken in; the next pass retries"
            );
        }
    }

    fn try_take_in(&self, journal: &Journal) -> Result<()> {
        let Some(outstanding) = load(journal, self.id())? else {
            return Ok(());
        };
        let slot = self.open_slot(Lineage::of(&outstanding.facts.position))?;
        let _lock = files::lock(&slot)?;
        // Read again under the slot's lock: another process may have settled
        // it.
        let Some(Retained { facts, ack }) = load(journal, self.id())? else {
            return Ok(());
        };
        let ack = match ack {
            Some(ack) => ack,
            None => match examine(journal, &slot, &self.spec, &facts)? {
                Found::Acked(ack) => {
                    let ack = *ack;
                    keep(journal, self.id(), &facts, Some(&ack))?;
                    ack
                }
                Found::Unmarked => return files::mark_ready(&slot, &files::batch_name(&facts)),
                Found::Gone => {
                    files::sweep(&slot)?;
                    return release(journal, self.id());
                }
                Found::Waiting(_) | Found::Refused(_) => return Ok(()),
            },
        };
        // Every local copy goes, durably, before the journal takes the ack.
        files::remove_batch(&slot, &files::batch_name(&facts))?;
        journal.accept_facts(&facts, &ack)?;
        release(journal, self.id())
    }
}
