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

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::key_custody::files::open_dir;
use crate::key_custody::files::read_whole;
use crate::key_custody::files::replace_file;
use crate::key_custody::platform;
use crate::key_custody::protocol::PendingCode;
use crate::key_custody::protocol::TargetId;
use crate::key_custody::protocol::TargetPending;
use crate::key_custody::protocol::TargetSpec;
use crate::key_custody::protocol::hex;

pub const OUTBOX: &str = "outbox";
pub const RECORD_VERSION: u8 = 1;

/// An answer in the outbox the vault's user does not own, owner-only.
pub const NOT_OWNED: &str =
    "the CP's custody answer in the outbox is not a 0600 file of the vault's user";
pub const NOT_PARSED: &str = "the CP's custody acknowledgement is not an exact AckRecord";
pub const NOT_MATCHED: &str = "the CP's custody acknowledgement does not match its batch";

pub fn record_corrupt() -> Error {
    Error::CorruptedIndex("key custody outbox record")
}

pub enum Answer {
    None,
    NotOwned,
    Bytes(Vec<u8>),
}

/// The file Hypnos wrote at `path`: a regular 0600 file of the vault's
/// user, opened without following a link.
pub fn answer(path: &Path) -> Result<Answer> {
    match read_whole(path) {
        Ok(Some(bytes)) => Ok(Answer::Bytes(bytes)),
        Ok(None) => Ok(Answer::None),
        Err(Error::CorruptedIndex(_)) => Ok(Answer::NotOwned),
        Err(error) => Err(error),
    }
}

pub fn failed(detail: &str) -> TargetPending {
    TargetPending {
        code: PendingCode::Failed,
        detail: detail.to_owned(),
    }
}

