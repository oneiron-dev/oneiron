//! The `[execution_node]` files of the owner's machines in a test (pass 33
//! row R1): each machine's server reads its own file, named in its
//! configuration, fresh at each admission; the mesh listener serves the job
//! protocols only when the file enables the node as it starts.
//!
//! Test-only: shared by the crate's integration tests through
//! `#[path = "support/execution_nodes.rs"]`.
// Each including test binary uses part of it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use oneiron::EntityId;
use oneiron_server::config::SyncServerConfig;

/// The one template every test node holds.
pub(crate) const PROBE_TEMPLATE: &str = "probe";

/// A directory of node files, one per machine.
pub(crate) struct NodeFiles {
    dir: tempfile::TempDir,
}

impl NodeFiles {
    pub(crate) fn new() -> std::io::Result<Self> {
        Ok(Self {
            dir: tempfile::tempdir()?,
        })
    }

    /// The node file of machine `index`.
    pub(crate) fn path(&self, index: usize) -> PathBuf {
        self.dir.path().join(format!("node-{index}.toml"))
    }

    /// Writes machine `index`'s file: an enabled node whose one issuer is
    /// `issuer`, holding [`PROBE_TEMPLATE`]. Returns the server
    /// configuration that names it.
    pub(crate) fn enabled(&self, index: usize, issuer: EntityId) -> SyncServerConfig {
        self.write(index, &node_text(self.dir.path(), index, true, &[issuer]))
    }

    /// The `state_dir` machine `index`'s file names: its job journal's
    /// directory.
    pub(crate) fn state_dir(&self, index: usize) -> PathBuf {
        node_state_dir(self.dir.path(), index)
    }

    /// Writes machine `index`'s file with `enabled = false`.
    pub(crate) fn disabled(&self, index: usize) -> SyncServerConfig {
        self.write(index, &node_text(self.dir.path(), index, false, &[]))
    }

    /// A configuration that names no node file: the machine runs no jobs.
    pub(crate) fn none() -> SyncServerConfig {
        SyncServerConfig::default()
    }

    fn write(&self, index: usize, text: &str) -> SyncServerConfig {
        let path = self.path(index);
        // A file that did not land leaves the node unconfigured, which the
        // test's first answer shows.
        let _ = std::fs::write(&path, text);
        SyncServerConfig {
            execution_node_file: Some(path),
            ..SyncServerConfig::default()
        }
    }
}

/// The text of a node file under `dir` for machine `index`.
pub(crate) fn node_text(dir: &Path, index: usize, enabled: bool, issuers: &[EntityId]) -> String {
    let issuers = issuers
        .iter()
        .map(|issuer| format!("{:?}", issuer.to_hex()))
        .collect::<Vec<_>>()
        .join(", ");
    let state = node_state_dir(dir, index);
    let work = dir.join(format!("work-{index}"));
    format!(
        r#"[execution_node]
enabled = {enabled}
issuers = [{issuers}]
state_dir = {state:?}
work_dir = {work:?}

[execution_node.templates.{PROBE_TEMPLATE}]
repo = "/srv/git/probe.git"
entries = ["tools/units/*.sh"]
interpreter = ["/usr/bin/bash"]
returnable = ["verdict.json"]
max_secs = 1800
memory_gib = 8
disk_gib = 4
"#
    )
}

/// The `state_dir` of machine `index`'s file under `dir`.
fn node_state_dir(dir: &Path, index: usize) -> PathBuf {
    dir.join(format!("state-{index}"))
}
