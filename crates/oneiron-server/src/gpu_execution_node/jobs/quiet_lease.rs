//! The quiet lease (row GPU-QUIET-LEASE, ANSWER GPU-QUIET-LEASE-FLEET = A):
//! a run of a template with `quiet = true` has the host to itself, so its
//! timings measure the job and nothing else.
//!
//! - A quiet key is reserved only when every other key of the node is idle:
//!   ended, its release check not leaving its device out (a process may
//!   still hold the card, whether or not the workload started), and either
//!   never started or with its outputs hashed.
//! - From its reserve until its own outputs are hashed (or its release check
//!   leaves the device out), the key holds the lease: every other reserve
//!   answers `Busy` and writes nothing, not even a refusal, and the tick
//!   cleans no payload. No other key can launch, so no other output is
//!   hashed during the lease. The reserve's record says the key took the
//!   lease, so a template edited afterwards does not end it.
//! - With `execution_node.quiet_tag` set, the lease is also the host's quiet
//!   marker, the fleet's existing convention (Orchestrator NOTE
//!   KEL-WINDOW-ON-BUILD-LINE, 14:21 Sat 28 Nov): the file
//!   `<fleet-home>/agent-traces/quiet-hosts/<host>` on the fleet, which the
//!   fleet's placement reads as a full host. The node writes it in the
//!   format the referee's booker writes (`book_series_mel.sh`): one line
//!   naming the holder and, last, `(<host>)`, created only where no file is
//!   ([`std::fs::OpenOptions::create_new`], the booker's `noclobber`), never
//!   taken over, its time refreshed at each tick while the lease is held (a
//!   marker counts for 3 hours from its last touch), and removed by a rename
//!   that checks the bytes it moved, so another holder's file is never
//!   deleted. A stale marker of this node is removed that way and then
//!   written again where no file is. The node's line is
//!   `oneiron execution-node <machine> template <template> key <key id> (<host>)`.
//! - A marker another holder wrote (a booker's, or a lane's `touch` before a
//!   measurement) keeps every reserve of this node `Busy`: the host is quiet
//!   for someone else.
//! - The tick brings the file in line with the journal, also at the first
//!   tick after a start: a marker of this node whose key no longer holds the
//!   lease (the key ended while the engine was down, or the engine stopped
//!   between the marker and the reserve's record) is removed, and a lease
//!   whose marker is gone (a sweep removed it) writes it again. It does so
//!   under the admission lock, as the reserve does, so a reserve's new
//!   marker is never read as one with no holder.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::journal::{JournalEvent, KeyTable, NodeKey};
use super::{BUSY_RETRY_AFTER_MS, JobKeyId, NodeJobs};
use crate::gpu_execution_node::node::ExecutionNode;
use crate::gpu_execution_node::node_settings::ExecutionNodeSettings;
use crate::gpu_execution_node::wire::{DeviceRelease, JobAnswer, JobEnd, OutputsState};

/// The first two words of every marker this engine writes.
const TAG_PREFIX: &str = "oneiron execution-node";

/// The quiet lease as the node's file sets it now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuietLease {
    /// `execution_node.quiet_tag`: the host's quiet marker. `None`: the node
    /// keeps the lease to itself and writes no file.
    pub tag: Option<PathBuf>,
    /// The templates whose runs take the lease (`quiet = true`).
    pub templates: BTreeSet<String>,
}

impl QuietLease {
    /// The lease the node's file sets.
    #[must_use]
    pub fn of(settings: &ExecutionNodeSettings) -> Self {
        Self {
            tag: settings.quiet_tag.clone(),
            templates: settings
                .templates
                .iter()
                .filter(|(_, template)| template.quiet)
                .map(|(name, _)| name.clone())
                .collect(),
        }
    }

    /// The lease `node`'s file sets now; none while the file does not read.
    #[must_use]
    pub fn read(node: &ExecutionNode) -> Self {
        let file = node.settings().ok().flatten();
        file.as_ref().map_or_else(Self::default, Self::of)
    }
}

/// The key that holds the lease now, if one does: a key that took it at its
/// reserve (its `Reserved` record), whatever its template says now.
#[must_use]
pub(super) fn holder<'t>(table: &'t KeyTable, templates: &BTreeSet<String>) -> Option<&'t NodeKey> {
    table.iter().find(|key| {
        key.reserve
            .as_ref()
            .is_some_and(|reserve| templates.contains(&reserve.pin.template))
            && holds_lease(key)
    })
}

/// Whether `key` is done with the host: ended, its release check not leaving
/// the device out, and either its workload never started or its outputs are
/// hashed (or failed to hash). A key whose prepare step refused after the
/// launch commit never started, yet its card may still be held.
#[must_use]
pub fn idle(key: &NodeKey) -> bool {
    key.is_ended()
        && !matches!(key.release, DeviceRelease::Unconfirmed { .. })
        && (!key.started() || key.outputs != OutputsState::Pending)
}

/// Whether a quiet `key` still holds the lease: it is not idle, unless its
/// release check left the device out, after which no hashing follows until
/// a clean probe.
fn holds_lease(key: &NodeKey) -> bool {
    !idle(key) && !matches!(key.release, DeviceRelease::Unconfirmed { .. })
}

/// The marker's line for `key` of `template` on `machine`.
fn tag_line(machine: &str, template: &str, key: &JobKeyId) -> String {
    format!(
        "{TAG_PREFIX} {machine} template {template} key {} ({})\n",
        key.as_str(),
        host_name()
    )
}

/// Whether `text` is a marker this node (`machine`) wrote.
fn written_by(text: &str, machine: &str) -> bool {
    text.strip_prefix(TAG_PREFIX)
        .and_then(|rest| rest.split_whitespace().next())
        .is_some_and(|word| word == machine)
}

/// The host's name, as the marker's last word names it.
fn host_name() -> String {
    let mut buffer = [0_u8; 256];
    // SAFETY: the buffer is valid for writes of its whole length, and
    // gethostname writes at most that many bytes.
    let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if result != 0 {
        return "unknown".to_owned();
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

/// The marker's text, or `None` when there is no file.
///
/// # Errors
///
/// The file exists and does not read.
pub fn read_tag(path: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Writes `line` where no file is: an existing file is never replaced.
fn take_tag(path: &Path, line: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(line.as_bytes())?;
    file.sync_all()
}

/// Takes the place of this node's own stale marker `path`: removes it only
/// while it is still this node's ([`release_tag`] checks the bytes it moved),
/// then writes `line` where no file is. A holder that wrote the path in
/// between keeps it, and the take answers `AlreadyExists`.
fn retake_own_tag(path: &Path, machine: &str, line: &str) -> std::io::Result<()> {
    release_tag(path, machine)?;
    take_tag(path, line)
}

/// Moves the marker its time on: a marker counts for 3 hours from its last
/// touch.
fn refresh_tag(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .set_modified(std::time::SystemTime::now())
}

/// Removes the marker only while it is this node's (`machine`): the rename
/// takes the file whole, and a file that turns out to be another holder's is
/// linked back where no new file is.
fn release_tag(path: &Path, machine: &str) -> std::io::Result<()> {
    let moved = side_path(path, "release");
    match std::fs::rename(path, &moved) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let text = std::fs::read_to_string(&moved).unwrap_or_default();
    if written_by(&text, machine) {
        return std::fs::remove_file(&moved);
    }
    match std::fs::hard_link(&moved, path) {
        Ok(()) => std::fs::remove_file(&moved),
        Err(error) => {
            tracing::warn!(path = %path.display(), moved = %moved.display(), %error, "another holder's quiet marker was moved and could not be put back");
            Err(error)
        }
    }
}

/// `<path>.<what>.<pid>`, beside the marker.
fn side_path(path: &Path, what: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{what}.{}", std::process::id()));
    path.with_file_name(name)
}

fn busy() -> JobAnswer {
    JobAnswer::Busy {
        retry_after_ms: BUSY_RETRY_AFTER_MS,
    }
}

impl NodeJobs {
    /// The reserve's quiet-lease step, under the admission lock, before any
    /// record (`event` is the reserve's `Reserved` record or its refusal).
    /// While another key holds the lease, or another holder's marker is on
    /// the host, every reserve answers `Busy` and writes nothing, a refusal
    /// too. A quiet key is then `Busy` while another key is not idle; once
    /// admitted, its record says it holds the lease, and it writes the marker
    /// before that record. A marker that cannot be written ends the key
    /// `quiet_tag_unwritable`. Any other event passes.
    pub(super) fn quiet_lease_admit(
        &self,
        table: &KeyTable,
        event: &mut JournalEvent,
    ) -> Option<JobAnswer> {
        let lease = self.parts().admission.quiet_lease();
        if holder(table, &lease.templates).is_some() {
            return Some(busy());
        }
        let machine = self.parts().machine.to_ulid();
        let found = lease.tag.as_deref().map(read_tag);
        if let Some(Ok(Some(text))) = &found
            && !written_by(text, &machine)
        {
            return Some(busy());
        }
        let JournalEvent::Reserved { reserve, quiet, .. } = &mut *event else {
            return None;
        };
        if !lease.templates.contains(&reserve.pin.template) {
            return None;
        }
        if !table.iter().all(idle) {
            return Some(busy());
        }
        *quiet = true;
        let (Some(path), Some(found)) = (lease.tag.as_deref(), found) else {
            return None;
        };
        let line = tag_line(
            &machine,
            &reserve.pin.template,
            &JobKeyId::for_key(&reserve.key),
        );
        let taken = match found {
            Ok(None) => take_tag(path, &line),
            // A marker of this node with no holder is one a stopped engine left.
            Ok(Some(_)) => retake_own_tag(path, &machine, &line),
            Err(error) => {
                *event = refused(format!("quiet_tag_unreadable: {error}"));
                return None;
            }
        };
        match taken {
            Ok(()) => None,
            // Another holder wrote it since the read.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Some(busy()),
            Err(error) => {
                *event = refused(format!("quiet_tag_unwritable: {error}"));
                None
            }
        }
    }

    /// The tick's quiet-marker step: the marker follows the journal. The
    /// holder's marker is written when it is gone and refreshed when it is
    /// there; a marker of this node with no holder, or naming another key,
    /// goes. Another holder's marker is left alone. The step holds the
    /// admission lock from its read of the journal to its change of the
    /// file, as the reserve's step does.
    pub(super) fn keep_quiet_tag(&self) {
        let lease = self.parts().admission.quiet_lease();
        let Some(path) = lease.tag.as_deref() else {
            return;
        };
        let machine = self.parts().machine.to_ulid();
        let book = self.lock();
        let line = book
            .journal
            .as_ref()
            .and_then(|journal| holder(journal.table(), &lease.templates))
            .and_then(|key| {
                let template = &key.reserve.as_ref()?.pin.template;
                Some(tag_line(&machine, template, &key.id))
            });
        let found = match read_tag(path) {
            Ok(found) => found,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "quiet marker not read; the next tick reads it again");
                return;
            }
        };
        let kept = match (line, found) {
            (Some(line), None) => take_tag(path, &line),
            (Some(line), Some(text)) if text == line => refresh_tag(path),
            (Some(line), Some(text)) if written_by(&text, &machine) => {
                retake_own_tag(path, &machine, &line)
            }
            (Some(_), Some(text)) => {
                tracing::warn!(path = %path.display(), holder = %text.trim(), "a quiet run holds the lease while another holder's marker is on the host");
                Ok(())
            }
            (None, Some(text)) if written_by(&text, &machine) => release_tag(path, &machine),
            (None, _) => Ok(()),
        };
        drop(book);
        if let Err(error) = kept {
            tracing::warn!(path = %path.display(), %error, "quiet marker not kept; the next tick tries again");
        }
    }
}

fn refused(reason: String) -> JournalEvent {
    JournalEvent::Ended {
        end: JobEnd::Refused { reason },
        end_boot_ns: None,
    }
}
