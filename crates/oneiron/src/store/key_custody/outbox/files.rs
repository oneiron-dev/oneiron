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

use crate::error::{Error, Result};

use super::super::files::{make_new_dir, replace_file, safe_open};
use super::super::log::frame_name;
use super::super::platform;
use super::super::protocol::{AckPosition, BatchFacts, CustodyBatch, TargetScope, TargetSpec, hex};

/// The empty marker Hypnos ships a batch on, written last.
pub(super) const READY: &str = "READY";
/// The control plane's [`AckRecord`](super::super::protocol::AckRecord), as
/// Hypnos writes it.
pub(super) const ACK: &str = "ack.json";
/// An optional [`TargetPending`](super::super::protocol::TargetPending)
/// Hypnos writes while the control plane does not acknowledge.
pub(super) const PENDING: &str = "pending.json";
const META: &str = "meta.json";
const HEAD: &str = "head";
const FRAMES: &str = "frames.jsonl";
const LOG: &str = "log";
const LOCK: &str = ".lock";
const META_VERSION: u8 = 1;

/// `b.<operation id hex>.r<set revision>`.
pub(super) fn batch_name(facts: &BatchFacts) -> String {
    format!("b.{}.r{}", hex(&facts.operation_id()), facts.set_revision)
}

/// Holds the slot's lock for the life of the returned file: one engine
/// process at a time stages or takes in there. Hypnos does not take it.
pub(super) fn lock(slot: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    let lock = platform::secure(&mut options).open(slot.join(LOCK))?;
    platform::lock_exclusive(&lock)?;
    Ok(lock)
}

#[derive(Serialize)]
struct MetaWire<'a> {
    version: u8,
    vault_name: &'a str,
    target: TargetWire<'a>,
    set_revision: u64,
    position: AckPosition,
    head_object_id: String,
    operation_id: String,
    data_key_wrapped: bool,
}

#[derive(Serialize)]
struct TargetWire<'a> {
    id: &'a str,
    kind: &'static str,
    scope: TargetScope,
}

/// A batch's `meta.json`: what Hypnos ships it as. Ids, positions and
/// digests only.
pub(super) fn meta(vault_name: &str, spec: &TargetSpec, facts: &BatchFacts) -> Result<Vec<u8>> {
    serde_json::to_vec(&MetaWire {
        version: META_VERSION,
        vault_name,
        target: TargetWire {
            id: spec.id().as_str(),
            kind: spec.kind().name(),
            scope: spec.scope(),
        },
        set_revision: facts.set_revision,
        position: AckPosition::of(&facts.position),
        head_object_id: hex(&facts.head_object_id),
        operation_id: hex(&facts.operation_id()),
        data_key_wrapped: facts.data_key,
    })
    .map_err(|_| Error::CorruptedIndex("key custody outbox metadata"))
}

/// Writes `name` in `dir` through `write`, streamed into a synced temporary
/// renamed into place, the directory synced after.
fn write_streamed(
    dir: &Path,
    name: &str,
    write: impl FnOnce(&mut BufWriter<File>) -> Result<()>,
) -> Result<()> {
    let temp = dir.join(format!(".t{:016x}.pending", rand::rngs::OsRng.next_u64()));
    let written = (|| -> Result<()> {
        let mut out = BufWriter::new(safe_open(&temp, true, false, None)?);
        write(&mut out)?;
        out.into_inner()
            .map_err(std::io::IntoInnerError::into_error)?
            .sync_all()?;
        fs::rename(&temp, dir.join(name))?;
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written?;
    platform::sync_dir(dir)
}

/// Stages `batch` for `spec` in `slot`, the frames after `after`, `meta` as
/// its metadata, and marks it READY last.
pub(super) fn write_batch(
    slot: &Path,
    spec: &TargetSpec,
    batch: &CustodyBatch,
    after: u64,
    meta: &[u8],
) -> Result<()> {
    let name = batch_name(&batch.facts());
    let stage = slot.join(format!(
        ".{name}.{:016x}.pending",
        rand::rngs::OsRng.next_u64()
    ));
    make_new_dir(&stage, None)?;
    replace_file(&stage, META, meta)?;
    if spec.scope() == TargetScope::HeadAndLog {
        replace_file(&stage, HEAD, batch.head())?;
    }
    let log = stage.join(LOG);
    make_new_dir(&log, None)?;
    // One frame at a time, its inventory line streamed beside it.
    write_streamed(&stage, FRAMES, |out| {
        for seq in after.saturating_add(1)..=batch.position().seq {
            let Some(frame) = batch.frame(seq)? else {
                continue;
            };
            replace_file(&log, &frame_name(seq), &frame)?;
            writeln!(out, "{{\"seq\":{seq},\"length\":{}}}", frame.len())?;
        }
        Ok(())
    })?;
    platform::sync_dir(&stage)?;
    let dir = slot.join(&name);
    fs::rename(&stage, &dir)?;
    platform::sync_dir(slot)?;
    mark_ready(slot, &name)
}

/// Writes the batch `name`'s READY marker, its directory synced after.
pub(super) fn mark_ready(slot: &Path, name: &str) -> Result<()> {
    replace_file(&slot.join(name), READY, &[])
}

/// Whether anything is at `path`, never following a link.
pub(super) fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Removes what is at `path`: a batch directory's marker first, so nothing
/// half-removed reads as READY, then its key-bearing head, then the rest.
fn remove_tree(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            for name in [READY, HEAD] {
                match fs::remove_file(path.join(name)) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.into()),
                }
            }
            fs::remove_dir_all(path)?;
        }
        Ok(_) => fs::remove_file(path)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

/// Removes the batch directory `name` from `slot`, durably.
pub(super) fn remove_batch(slot: &Path, name: &str) -> Result<()> {
    remove_tree(&slot.join(name))?;
    platform::sync_dir(slot)
}

/// Removes every batch directory and stage in `slot`, durably: called when
/// the journal records none outstanding there.
pub(super) fn sweep(slot: &Path) -> Result<()> {
    let mut removed = false;
    for entry in fs::read_dir(slot)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_str().is_some_and(|name| {
            name.starts_with("b.") || (name.starts_with(".b.") && name.ends_with(".pending"))
        }) {
            remove_tree(&entry.path())?;
            removed = true;
        }
    }
    if removed {
        platform::sync_dir(slot)?;
    }
    Ok(())
}
