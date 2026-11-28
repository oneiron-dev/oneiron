//! The checkpoint protocol of a resumable template (pass 34 row C1). The
//! workload writes each checkpoint under `out/<checkpoint_output>/<label>/`.
//! When the checkpoint is complete, the workload publishes `LATEST` in
//! `out/<checkpoint_output>/` by rename. `LATEST` is a regular file of at
//! most 256 bytes. It holds the label on one line, with an optional trailing
//! LF. The node reads only the directory `LATEST` names. The workload does
//! not change a checkpoint after `LATEST` names it.
//!
//! The label is one nonempty UTF-8 path component of at most 128 bytes,
//! with no slash or NUL. `.`, `..`, `LATEST` and names ending in `.partial`
//! or `.manifest` are reserved. Every directory and file opened under
//! `out/` is opened by its parent's descriptor without following links.
//! The tree contains only directories and regular files, with UTF-8 names
//! and no LF in a path.
//!
//! The node builds one manifest line per regular file:
//! `<sha256 lower hex> <bytes> <relative path>\n`. Paths use `/` and the
//! lines are sorted by the path's bytes. The checkpoint digest is the
//! lower-hex SHA-256 of the manifest text. The label is not hashed. The scan
//! fails if `LATEST` changes, a file's length or mtime changes while it is
//! read, or the key's disk request, file, depth or hash-time bound is exceeded.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, Stat};
use sha2::{Digest as _, Sha256};

use super::admission::log_write_error;
use super::journal::JournalEvent;
use super::node_parts::NodeJobSettings;
use super::{NodeBook, NodeGate, NodeJobs};
use crate::gpu_execution_node::node_settings::valid_checkpoint_output;
use crate::gpu_execution_node::wire::{CheckpointRecord, JobState, OutputsState, WorkloadPin};

const LATEST: &str = "LATEST";
const LATEST_MAX_BYTES: u64 = 256;
const FILES_MAX: usize = 100_000;
const DEPTH_MAX: usize = 32;

pub(crate) fn valid_label(label: &str) -> bool {
    (1..=128).contains(&label.len())
        && !label.contains(['/', '\0', '\n'])
        && !matches!(label, "." | ".." | LATEST)
        && !label.ends_with(".partial")
        && !label.ends_with(".manifest")
}

pub(crate) fn manifest_line(sha256: &[u8; 32], bytes: u64, path: &str) -> String {
    format!("{} {bytes} {path}\n", oneiron_hex::encode(sha256))
}

pub(crate) fn manifest_digest(
    lines: impl IntoIterator<Item = Result<String, String>>,
) -> Result<String, String> {
    let mut digest = Sha256::new();
    for line in lines {
        digest.update(line?.as_bytes());
    }
    Ok(oneiron_hex::encode(&digest.finalize()))
}

/// Reads and hashes the checkpoint named by `LATEST`. The journal stamps
/// `saved_at_ms` when it accepts the record.
pub(super) fn scan(
    payload_dir: &Path,
    checkpoint_output: &str,
    disk_mib: u64,
    limit: Duration,
    cancelled: impl Fn() -> bool,
) -> Result<CheckpointRecord, String> {
    let mut walk = Walk {
        started: Instant::now(),
        limit,
        cancelled: &cancelled,
        size_bound: disk_mib.saturating_mul(1 << 20),
        bytes: 0,
        files: Vec::new(),
        buffer: vec![0; 1 << 16],
    };
    walk.check_time()?;
    if !valid_checkpoint_output(checkpoint_output) {
        return Err("checkpoint_output is not a normal path component".to_owned());
    }
    let payload = fs::open(payload_dir, directory_flags(), Mode::empty())
        .map_err(|error| format!("payload_dir: {error}"))?;
    let out = open_directory(&payload, "out")?;
    let checkpoints = open_directory(&out, checkpoint_output)?;
    let (marker, marker_stat) = read_latest(&checkpoints)?;
    let text = std::str::from_utf8(&marker).map_err(|_| "LATEST is not UTF-8".to_owned())?;
    let label = text.strip_suffix('\n').unwrap_or(text);
    if !valid_label(label) {
        return Err(format!(
            "LATEST names an invalid checkpoint label: {label:?}"
        ));
    }
    let checkpoint = open_directory(&checkpoints, label)?;
    walk.directory(&checkpoint, "", 0)?;
    walk.check_time()?;
    walk.files
        .sort_unstable_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let sha256 = manifest_digest(walk.files.iter().map(|file| {
        walk.check_time()?;
        Ok(manifest_line(&file.sha256, file.bytes, &file.path))
    }))?;
    let (after, after_stat) = read_latest(&checkpoints)
        .map_err(|why| format!("LATEST changed or cannot be read again: {why}"))?;
    if after != marker || !same_file(&marker_stat, &after_stat) {
        return Err("LATEST changed under the checkpoint scan".to_owned());
    }
    walk.check_time()?;
    Ok(CheckpointRecord {
        label: label.to_owned(),
        sha256,
        bytes: walk.bytes,
        files: walk.files.len() as u64,
        saved_at_ms: 0,
    })
}

impl NodeBook {
    /// Whether a checkpoint worker runs for `key` now.
    pub(super) fn checkpoint_in_flight(&self, key: &str) -> bool {
        self.checkpoint_scans
            .get(key)
            .is_some_and(|scan| scan.in_flight)
    }
}

impl NodeJobs {
    /// The tick's follow-up for a launched key: a scan while it runs
    /// (`Running`), or the end's scan and then the outputs (`Ended`). At most
    /// one checkpoint worker runs per key, and the tick waits for none: a
    /// tick that finds one running leaves the key to a later tick. A key of
    /// any other template does no checkpoint work, and its end hashes its
    /// outputs on the tick as before.
    pub(super) fn follow_checkpoint(&self, key: &str, pin: Box<WorkloadPin>, state: JobState) {
        if self.service_closed() || self.lock().checkpoint_in_flight(key) {
            return;
        }
        let admission = &self.parts().admission;
        let Some(output) = admission.template_checkpoint_output(&pin) else {
            if state == JobState::Ended {
                self.hash_and_seal(key, &pin);
                self.lock().checkpoint_scans.remove(key);
            }
            return;
        };
        let settings = admission.job_settings();
        let now = self.parts().clock.boot_ns();
        let interval = settings.checkpoint_scan_secs.saturating_mul(1_000_000_000);
        {
            let mut book = self.lock();
            if book.gate != NodeGate::Open || !Self::checkpoint_key_pending(&book, key, state) {
                return;
            }
            let scan = book.checkpoint_scans.entry(key.to_owned()).or_default();
            if scan.in_flight
                || (state == JobState::Running
                    && scan
                        .last_started_boot_ns
                        .is_some_and(|last| now.saturating_sub(last) < interval))
            {
                return;
            }
            scan.in_flight = true;
            scan.last_started_boot_ns = Some(now);
        }
        let jobs = self.clone();
        let worker_key = key.to_owned();
        let spawned = std::thread::Builder::new()
            .name("oneiron-job-checkpoint".to_owned())
            .spawn(move || {
                let go_on =
                    jobs.scan_and_record_checkpoint(&worker_key, &pin, &output, &settings, state);
                if state == JobState::Ended && go_on && !jobs.service_closed() {
                    jobs.hash_and_seal(&worker_key, &pin);
                }
                jobs.finish_checkpoint_work(&worker_key, state);
            });
        if let Err(error) = spawned {
            tracing::warn!(key, %error, "job checkpoint worker not started");
            self.finish_checkpoint_work(key, state);
        }
    }

    /// Whether `key` is in `state` with its outputs not yet sealed.
    fn checkpoint_key_pending(book: &NodeBook, key: &str, state: JobState) -> bool {
        book.journal
            .as_ref()
            .and_then(|journal| journal.table().get(key))
            .is_some_and(|known| known.state == state && known.outputs == OutputsState::Pending)
    }

    fn finish_checkpoint_work(&self, key: &str, state: JobState) {
        let mut book = self.lock();
        if state == JobState::Ended {
            book.checkpoint_scans.remove(key);
        } else if let Some(scan) = book.checkpoint_scans.get_mut(key) {
            scan.in_flight = false;
        }
    }

    /// Scans the key's checkpoint directory and journals a changed latest
    /// checkpoint. `false` when the outputs must wait for a later tick: the
    /// key moved, the service closed, or the journal refused the record. A
    /// failed scan keeps the last checkpoint and returns `true`.
    fn scan_and_record_checkpoint(
        &self,
        key: &str,
        pin: &WorkloadPin,
        output: &str,
        settings: &NodeJobSettings,
        state: JobState,
    ) -> bool {
        let payload_dir = super::JobKeyId::for_key(key).payload_dir(&self.paths().work_dir);
        let mut checkpoint = match scan(
            &payload_dir,
            output,
            pin.request.disk_mib,
            Duration::from_secs(settings.checkpoint_hash_limit_secs),
            || self.service_closed(),
        ) {
            Ok(checkpoint) => checkpoint,
            Err(why) => {
                tracing::debug!(key, %why, "job checkpoint not recorded");
                return true;
            }
        };
        if self
            .parts()
            .admission
            .template_checkpoint_output(pin)
            .as_deref()
            != Some(output)
        {
            return true;
        }
        let now = self.now();
        let mut book = self.lock();
        if self.service_closed() || book.gate != NodeGate::Open {
            return false;
        }
        let Some(journal) = book.journal.as_mut() else {
            return false;
        };
        let Some(known) = journal.table().get(key) else {
            return false;
        };
        if known.state != state || known.outputs != OutputsState::Pending {
            return false;
        }
        if known
            .checkpoint
            .as_ref()
            .is_some_and(|last| last.label == checkpoint.label && last.sha256 == checkpoint.sha256)
        {
            return true;
        }
        checkpoint.saved_at_ms = now.wall_ms;
        let issuer = known.issuer;
        let event = JournalEvent::CheckpointSaved { checkpoint };
        match journal.record(key, issuer, &now.boot_id, now.wall_ms, event) {
            Ok(_) => true,
            Err(error) => {
                log_write_error(key, &error);
                false
            }
        }
    }
}

struct ManifestFile {
    path: String,
    sha256: [u8; 32],
    bytes: u64,
}

struct Walk<'a> {
    started: Instant,
    limit: Duration,
    cancelled: &'a dyn Fn() -> bool,
    size_bound: u64,
    bytes: u64,
    files: Vec<ManifestFile>,
    buffer: Vec<u8>,
}

impl Walk<'_> {
    fn check_time(&self) -> Result<(), String> {
        if (self.cancelled)() {
            Err("checkpoint scan cancelled".to_owned())
        } else if self.started.elapsed() > self.limit {
            Err("checkpoint hash time limit exceeded".to_owned())
        } else {
            Ok(())
        }
    }

    fn directory(&mut self, dir: &OwnedFd, prefix: &str, depth: usize) -> Result<(), String> {
        self.check_time()?;
        let entries = Dir::read_from(dir).map_err(|error| format!("{prefix:?}: {error}"))?;
        for entry in entries {
            self.check_time()?;
            let entry = entry.map_err(|error| format!("{prefix:?}: {error}"))?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| format!("{prefix:?}: non-UTF-8 checkpoint name"))?;
            if matches!(name, "." | "..") {
                continue;
            }
            if name.contains('\n') {
                return Err(format!(
                    "{name:?}: LF cannot be written on one manifest line"
                ));
            }
            if depth == DEPTH_MAX {
                return Err("checkpoint depth limit exceeded".to_owned());
            }
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            let seen = fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| format!("{path:?}: {error}"))?;
            match FileType::from_raw_mode(seen.st_mode) {
                FileType::Directory => {
                    let child = open_directory(dir, name)?;
                    self.directory(&child, &path, depth + 1)?;
                }
                FileType::RegularFile => self.file(dir, name, path, &seen)?,
                _ => return Err(format!("{path:?}: not a regular file or directory")),
            }
        }
        Ok(())
    }

    fn file(&mut self, dir: &OwnedFd, name: &str, path: String, seen: &Stat) -> Result<(), String> {
        if self.files.len() == FILES_MAX {
            return Err("checkpoint file limit exceeded".to_owned());
        }
        let (mut file, before) = open_regular(dir, name, seen)?;
        let remaining = self.size_bound - self.bytes;
        let size = u64::try_from(before.st_size).map_err(|_| format!("{path:?}: invalid size"))?;
        if size > remaining {
            return Err("checkpoint exceeds the key's disk request".to_owned());
        }
        let mut digest = Sha256::new();
        let mut bytes = 0_u64;
        loop {
            self.check_time()?;
            match file.read(&mut self.buffer) {
                Ok(0) => break,
                Ok(read) => {
                    bytes = bytes
                        .checked_add(read as u64)
                        .filter(|&bytes| bytes <= remaining)
                        .ok_or_else(|| "checkpoint exceeds the key's disk request".to_owned())?;
                    digest.update(&self.buffer[..read]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(format!("{path:?}: {error}")),
            }
        }
        check_read(&file, &before, bytes, &path)?;
        self.bytes += bytes;
        self.files.push(ManifestFile {
            path,
            sha256: digest.finalize().into(),
            bytes,
        });
        Ok(())
    }
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_directory(parent: &OwnedFd, name: &str) -> Result<OwnedFd, String> {
    fs::openat(parent, name, directory_flags(), Mode::empty())
        .map_err(|error| format!("{name:?}: {error}"))
}

fn open_regular(parent: &OwnedFd, name: &str, seen: &Stat) -> Result<(File, Stat), String> {
    if FileType::from_raw_mode(seen.st_mode) != FileType::RegularFile {
        return Err(format!("{name:?}: not a regular file"));
    }
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = fs::openat(parent, name, flags, Mode::empty())
        .map_err(|error| format!("{name:?}: {error}"))?;
    let opened = fs::fstat(&fd).map_err(|error| format!("{name:?}: {error}"))?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile || !same_file(seen, &opened)
    {
        return Err(format!("{name:?}: changed before reading"));
    }
    Ok((File::from(fd), opened))
}

fn same_file(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
}

fn check_read(file: &File, before: &Stat, bytes: u64, path: &str) -> Result<(), String> {
    let after = fs::fstat(file).map_err(|error| format!("{path:?}: {error}"))?;
    if !same_file(before, &after) || u64::try_from(after.st_size).ok() != Some(bytes) {
        return Err(format!("{path:?}: changed while reading"));
    }
    Ok(())
}

fn read_latest(dir: &OwnedFd) -> Result<(Vec<u8>, Stat), String> {
    let seen = fs::statat(dir, LATEST, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| format!("LATEST: {error}"))?;
    let (mut file, before) = open_regular(dir, LATEST, &seen)?;
    let mut marker = Vec::new();
    file.by_ref()
        .take(LATEST_MAX_BYTES + 1)
        .read_to_end(&mut marker)
        .map_err(|error| format!("LATEST: {error}"))?;
    let bytes = marker.len() as u64;
    if bytes > LATEST_MAX_BYTES {
        return Err("LATEST is over 256 bytes".to_owned());
    }
    check_read(&file, &before, bytes, LATEST)?;
    Ok((marker, before))
}
