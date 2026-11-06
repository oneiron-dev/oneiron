//! One member's slot in the Hypnos outbox (FIX 5899): the batch directory
//! Hypnos ships, written in the order its scanner relies on.
//!
//! A batch is built in `.b.<operation id>.r<set revision>.<nonce>.pending/`
//! beside it: `meta.json`, the exact sealed `head` (none for a log-only
//! member), `log/f<seq hex16>` for each local frame after the position the
//! member last acknowledged and `frames.jsonl` listing them, each file a
//! synced temporary renamed into place with its directory synced. The stage
//! is synced and renamed to `b.<operation id>.r<set revision>/`, the slot
//! synced, and `READY` written last, the batch directory synced after it.
//! Hypnos never touches a directory without `READY`; the engine removes
//! every directory and stage it does not record. Every directory is
//! owner-only (0700) and every file 0600, opened without following a link.
//! Neither a head nor the frames are capped in size or count.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use rand::RngCore;
use serde::Serialize;

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::key_custody::protocol::TargetScope;
use crate::key_custody::protocol::TargetSpec;
use crate::key_custody::protocol::hex;

/// The empty marker Hypnos ships a batch on, written last.
pub const READY: &str = "READY";
/// The control plane's [`AckRecord`](super::super::protocol::AckRecord), as
/// Hypnos writes it.
pub const ACK: &str = "ack.json";
/// An optional [`TargetPending`](super::super::protocol::TargetPending)
/// Hypnos writes while the control plane does not acknowledge.
pub const PENDING: &str = "pending.json";
pub const META: &str = "meta.json";
pub const HEAD: &str = "head";
pub const FRAMES: &str = "frames.jsonl";
pub const LOG: &str = "log";
pub const LOCK: &str = ".lock";
pub const META_VERSION: u8 = 1;

#[derive(Serialize)]
pub struct TargetWire<'a> {
    pub id: &'a str,
    pub kind: &'static str,
    pub scope: TargetScope,
}

/// Whether anything is at `path`, never following a link.
pub fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}
