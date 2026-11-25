//! Breadcrumb lines (pass 34, `34-compute-general/DESIGN.md` section 7.3,
//! row Q4): while a key runs, every tick writes one line to
//! `breadcrumbs.jsonl` in the key's control directory: the boot clock, the
//! wall clock, and the temperature, power draw and memory in use of the
//! key's devices where the probe gives them. Each write is synced, so after
//! a hard reset the last lines are still there, and the key's `Lost`
//! receipt carries them as evidence ("is it possible to also log more",
//! the owner on nelly, 00:06).
//!
//! The file keeps the newest `jobs.breadcrumbs.keep` lines. The tick file
//! beside it is unchanged: it stays the one figure a reset is dated by.

use std::collections::BTreeSet;
use std::path::Path;

use super::NodeJobs;
use super::job_unit::write_file_synced;
use super::journal::NodeKey;
use crate::gpu_execution_node::wire::{Breadcrumb, JobState};

/// A running key's breadcrumb lines, in its control directory.
pub const BREADCRUMB_FILE_NAME: &str = "breadcrumbs.jsonl";

/// Appends `line` to the key's breadcrumb file and keeps the newest `keep`
/// lines, synced. A line of the file that does not read is dropped.
///
/// # Errors
///
/// The write's error: the file then keeps its earlier lines.
pub(super) fn append_breadcrumb(
    control_dir: &Path,
    line: &Breadcrumb,
    keep: u64,
) -> std::io::Result<()> {
    let mut lines = read_breadcrumbs(control_dir);
    lines.push(line.clone());
    let keep = usize::try_from(keep).unwrap_or(usize::MAX);
    let first = lines.len().saturating_sub(keep);
    let mut text = String::new();
    for kept in &lines[first..] {
        let encoded = serde_json::to_string(kept)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        text.push_str(&encoded);
        text.push('\n');
    }
    write_file_synced(&control_dir.join(BREADCRUMB_FILE_NAME), text.as_bytes())
}

/// Every breadcrumb line the key's file holds, oldest first; none when the
/// file is missing or unreadable. A line that does not read is skipped.
#[must_use]
pub(super) fn read_breadcrumbs(control_dir: &Path) -> Vec<Breadcrumb> {
    let Ok(text) = std::fs::read_to_string(control_dir.join(BREADCRUMB_FILE_NAME)) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

impl NodeJobs {
    /// The breadcrumb step of the tick: one line for each key launching or
    /// running in this boot, from one sample of their devices. It runs
    /// outside the admission lock: the probe may take its full query time.
    pub(super) fn write_breadcrumbs(&self) {
        let now = self.now();
        let running: Vec<NodeKey> = self
            .keys()
            .into_iter()
            .filter(|key| matches!(key.state, JobState::Launching | JobState::Running))
            .filter(|key| {
                key.launch
                    .as_ref()
                    .is_some_and(|launch| launch.boot_id == now.boot_id)
            })
            .collect();
        if running.is_empty() {
            return;
        }
        let device_ids: Vec<String> = running
            .iter()
            .flat_map(|key| key.launch.iter().flat_map(|launch| &launch.devices))
            .map(|lease| lease.device_id.clone())
            .collect();
        let samples = self.parts().devices.samples(&device_ids);
        let keep = self.parts().admission.job_settings().breadcrumbs_keep;
        for key in &running {
            let own: BTreeSet<&str> = key
                .launch
                .iter()
                .flat_map(|launch| &launch.devices)
                .map(|lease| lease.device_id.as_str())
                .collect();
            let line = Breadcrumb {
                boot_id: now.boot_id.clone(),
                boot_ns: now.boot_ns,
                wall_ms: now.wall_ms,
                devices: samples
                    .iter()
                    .filter(|sample| own.contains(sample.device_id.as_str()))
                    .cloned()
                    .collect(),
            };
            let control_dir = key.id.control_dir(&self.paths().state_dir);
            if let Err(error) = append_breadcrumb(&control_dir, &line, keep) {
                tracing::warn!(key = %key.key, %error, "job breadcrumb line not written");
            }
        }
    }

    /// The key's breadcrumb lines, for its `Lost` end.
    pub(super) fn lost_breadcrumbs(&self, known: &NodeKey) -> Vec<Breadcrumb> {
        read_breadcrumbs(&known.id.control_dir(&self.paths().state_dir))
    }
}
