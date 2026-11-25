//! The node's incidents (pass 34, `34-compute-general/DESIGN.md` sections
//! 5 and 7.3, row Q4): typed records of what happened to the machine
//! itself, not to one key. Each is a notice, never a question (16, practice
//! 6): a failed and a passed readiness check, a drain and its clear, a
//! quarantined device, a host reset, a lost history.
//!
//! They live in `incidents.jsonl` beside the journal, one JSON line each,
//! each append synced, and the file keeps the newest `jobs.incidents.keep`.
//! They stay out of the per-key journal: a record with no key would break
//! its replay, and an older engine reads an unknown journal tag as a lost
//! history. Row Q2's `vault.machines.status` reads them.

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::job_unit::write_file_synced;
use crate::gpu_execution_node::wire::ReadinessCheck;

/// The node's incidents, beside the journal in `state_dir`.
pub const INCIDENTS_FILE_NAME: &str = "incidents.jsonl";

/// What happened to the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentKind {
    /// A readiness check failed after a pass, or failed another way than
    /// the last.
    ReadinessFailed {
        check: ReadinessCheck,
        why: String,
        failed_in_a_row: u32,
    },
    /// A readiness check passed after `after_failures` failed ones.
    ReadinessPassed { after_failures: u32 },
    /// The machine was drained. `rule` names the DRAIN rule when it drained
    /// after a failed readiness check; `None` when the node saw a drain
    /// another path set (the count of failed jobs, a job unit outside the
    /// journal).
    Drained { why: String, rule: Option<String> },
    /// The drain was cleared. `rule` names the DRAIN rule when a passed
    /// readiness check cleared it; `None` when it was cleared at the box.
    DrainCleared { rule: Option<String> },
    /// A device was put out of every reserve and launch after a key's end.
    DeviceQuarantined { device: String, why: String },
    /// The node started in another boot than it last ran in.
    HostReset { previous_boot: String },
    /// The journal that could have held a key is lost.
    HistoryLost { why: String },
}

/// One incident, as the node keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIncident {
    /// The incident's place: a later incident has a higher one.
    pub seq: u64,
    /// When, on the node's wall clock.
    pub at_ms: u64,
    pub boot_id: String,
    pub kind: IncidentKind,
}

/// The kept incidents and their file.
#[derive(Debug)]
pub(super) struct IncidentLog {
    path: PathBuf,
    kept: VecDeque<NodeIncident>,
    next_seq: u64,
}

impl IncidentLog {
    /// Reads the node's incidents. A missing file holds none; a line that
    /// does not read (a write torn by a reset) is skipped.
    pub(super) fn open(state_dir: &Path) -> Self {
        let path = state_dir.join(INCIDENTS_FILE_NAME);
        let kept: VecDeque<NodeIncident> = std::fs::read_to_string(&path)
            .map(|text| {
                text.lines()
                    .filter(|line| !line.trim().is_empty())
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect()
            })
            .unwrap_or_default();
        let next_seq = kept.back().map_or(1, |last| last.seq.saturating_add(1));
        Self {
            path,
            kept,
            next_seq,
        }
    }

    /// Records `kind` at `at_ms` in `boot_id`, synced, and keeps the newest
    /// `keep`. A write that fails is logged; the incident is still kept in
    /// memory, so `Node`'s readers see it until the engine stops.
    pub(super) fn record(&mut self, boot_id: &str, at_ms: u64, kind: IncidentKind, keep: u64) {
        let incident = NodeIncident {
            seq: self.next_seq,
            at_ms,
            boot_id: boot_id.to_owned(),
            kind,
        };
        self.next_seq = self.next_seq.saturating_add(1);
        tracing::info!(seq = incident.seq, kind = ?incident.kind, "execution node incident");
        self.kept.push_back(incident.clone());
        let keep = usize::try_from(keep).unwrap_or(usize::MAX);
        let written = if self.kept.len() > keep {
            while self.kept.len() > keep {
                self.kept.pop_front();
            }
            self.rewrite()
        } else {
            self.append(&incident)
        };
        if let Err(error) = written {
            tracing::warn!(%error, "execution node incident not written to its file");
        }
    }

    /// The kept incidents after `after` (all with `None`), oldest first, at
    /// most `limit`.
    pub(super) fn page(&self, after: Option<u64>, limit: usize) -> Vec<NodeIncident> {
        self.kept
            .iter()
            .filter(|incident| after.is_none_or(|after| incident.seq > after))
            .take(limit)
            .cloned()
            .collect()
    }

    fn append(&self, incident: &NodeIncident) -> std::io::Result<()> {
        let mut line = encode(incident)?;
        line.push('\n');
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.sync_data()
    }

    fn rewrite(&self) -> std::io::Result<()> {
        let mut text = String::new();
        for incident in &self.kept {
            text.push_str(&encode(incident)?);
            text.push('\n');
        }
        write_file_synced(&self.path, text.as_bytes())
    }
}

impl super::NodeJobs {
    /// A fresh quarantine of the key's devices: puts each out of every
    /// reserve and launch, then records one incident for each. Recovery's
    /// replay of a quarantine calls `quarantine_device` alone and writes
    /// none.
    pub(super) fn quarantine_with_incident(&self, known: &super::NodeKey, why: &str) {
        self.quarantine_device(known, why);
        for lease in known.launch.iter().flat_map(|launch| &launch.devices) {
            self.record_incident(IncidentKind::DeviceQuarantined {
                device: lease.device_id.clone(),
                why: why.to_owned(),
            });
        }
    }
}

fn encode(incident: &NodeIncident) -> std::io::Result<String> {
    serde_json::to_string(incident)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}
