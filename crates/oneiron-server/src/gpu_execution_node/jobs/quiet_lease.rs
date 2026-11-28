//! The quiet lease (row GPU-QUIET-LEASE, ANSWER GPU-QUIET-LEASE-FLEET = A):
//! a run of a template with `quiet = true` has the host to itself, so its
//! timings measure the job and nothing else.
//!
//! - A quiet key is reserved only when every other key of the node is idle:
//!   ended, and either never started or with its outputs hashed. A key whose
//!   release check left its device out is not idle, as a process may still
//!   hold the card.
//! - From its reserve until its own outputs are hashed (or its release check
//!   leaves the device out), the key holds the lease: every other reserve
//!   answers `Busy` and writes nothing, and the tick cleans no payload. No
//!   other key can launch, so no other output is hashed during the lease.
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
//!   deleted. The node's line is
//!   `oneiron execution-node <machine> template <template> key <key id> (<host>)`.
//! - A marker another holder wrote (a booker's, or a lane's `touch` before a
//!   measurement) keeps every reserve of this node `Busy`: the host is quiet
//!   for someone else.
//! - The tick brings the file in line with the journal, also at the first
//!   tick after a start: a marker of this node whose key no longer holds the
//!   lease (the key ended while the engine was down, or the engine stopped
//!   between the marker and the reserve's record) is removed, and a lease
//!   whose marker is gone (a sweep removed it) writes it again.

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

    fn is_quiet(&self, key: &NodeKey) -> bool {
        key.reserve
            .as_ref()
            .is_some_and(|reserve| self.templates.contains(&reserve.pin.template))
    }

    /// The key that holds the lease now, if one does.
    #[must_use]
    pub fn holder<'table>(&self, table: &'table KeyTable) -> Option<&'table NodeKey> {
        table
            .iter()
            .find(|key| self.is_quiet(key) && holds_lease(key))
    }
}

/// Whether `key` is done with the host: ended, and either its workload never
/// started or its outputs are hashed (or failed to hash).
#[must_use]
pub fn idle(key: &NodeKey) -> bool {
    key.is_ended() && (!key.started() || key.outputs != OutputsState::Pending)
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

/// Replaces this node's own marker `path` with `line` in one rename.
fn replace_own_tag(path: &Path, line: &str) -> std::io::Result<()> {
    let staged = side_path(path, "take");
    let _ = std::fs::remove_file(&staged);
    take_tag(&staged, line)?;
    std::fs::rename(&staged, path)
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
    /// The reserve's quiet-lease step, under the admission lock, once the
    /// reserve is admitted (`event` is its `Reserved` record): `Busy` while
    /// another key holds the lease, while another holder's marker is on the
    /// host, and, for a quiet key, while another key is not idle. A quiet
    /// key then writes the marker before its record; a marker that cannot be
    /// written ends the key `quiet_tag_unwritable`. Any other event passes.
    pub(super) fn quiet_lease_admit(
        &self,
        table: &KeyTable,
        event: &mut JournalEvent,
    ) -> Option<JobAnswer> {
        let JournalEvent::Reserved { reserve, .. } = &*event else {
            return None;
        };
        let template = reserve.pin.template.clone();
        let key = JobKeyId::for_key(&reserve.key);
        let lease = self.parts().admission.quiet_lease();
        let quiet = lease.templates.contains(&template);
        if lease.holder(table).is_some() || (quiet && !table.iter().all(idle)) {
            return Some(busy());
        }
        let path = lease.tag.as_deref()?;
        let machine = self.parts().machine.to_ulid();
        let found = match read_tag(path) {
            Ok(found) => found,
            Err(_) if !quiet => return None,
            Err(error) => {
                *event = refused(format!("quiet_tag_unreadable: {error}"));
                return None;
            }
        };
        if found
            .as_deref()
            .is_some_and(|text| !written_by(text, &machine))
        {
            return Some(busy());
        }
        if !quiet {
            return None;
        }
        let line = tag_line(&machine, &template, &key);
        // A marker of this node with no holder is one a stopped engine left.
        let taken = if found.is_some() {
            replace_own_tag(path, &line)
        } else {
            take_tag(path, &line)
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

    /// Whether a key holds the quiet lease now: the tick then cleans no
    /// payload.
    pub(super) fn quiet_lease_held(&self) -> bool {
        let lease = self.parts().admission.quiet_lease();
        let book = self.lock();
        book.journal
            .as_ref()
            .is_some_and(|journal| lease.holder(journal.table()).is_some())
    }

    /// The tick's quiet-marker step: the marker follows the journal. The
    /// holder's marker is written when it is gone and refreshed when it is
    /// there; a marker of this node with no holder, or naming another key,
    /// goes. Another holder's marker is left alone.
    pub(super) fn keep_quiet_tag(&self) {
        let lease = self.parts().admission.quiet_lease();
        let Some(path) = lease.tag.as_deref() else {
            return;
        };
        let machine = self.parts().machine.to_ulid();
        let line = {
            let book = self.lock();
            book.journal
                .as_ref()
                .and_then(|journal| lease.holder(journal.table()))
                .and_then(|holder| {
                    let template = &holder.reserve.as_ref()?.pin.template;
                    Some(tag_line(&machine, template, &holder.id))
                })
        };
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
            (Some(line), Some(text)) if written_by(&text, &machine) => replace_own_tag(path, &line),
            (Some(_), Some(text)) => {
                tracing::warn!(path = %path.display(), holder = %text.trim(), "a quiet run holds the lease while another holder's marker is on the host");
                Ok(())
            }
            (None, Some(text)) if written_by(&text, &machine) => release_tag(path, &machine),
            (None, _) => Ok(()),
        };
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
