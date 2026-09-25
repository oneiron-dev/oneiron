//! Explicit fleet workload and host settings; smoke cannot masquerade as fleet scale.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::Result;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub profile: String,
    pub host_label: String,
    pub storage_label: String,
    pub scratch: PathBuf,
    pub agents: usize,
    pub listeners: usize,
    pub concurrency: usize,
    pub runtime_threads: usize,
    pub rounds: usize,
    pub hold_ms: u64,
    pub timeout_secs: u64,
    pub map_size: usize,
    pub ppr_nodes: usize,
    pub ppr_samples: usize,
}

impl Plan {
    pub(super) fn fixture(scratch: PathBuf) -> Self {
        Self {
            profile: "fixture-v1".into(),
            host_label: "fixture".into(),
            storage_label: "fixture".into(),
            scratch,
            agents: 4,
            listeners: 2,
            concurrency: 2,
            runtime_threads: 2,
            rounds: 1,
            hold_ms: 10,
            timeout_secs: 30,
            map_size: 64 * 1024 * 1024,
            ppr_nodes: 32,
            ppr_samples: 4,
        }
    }

    pub(super) fn validate(&self) -> Result<()> {
        let fleet = self.profile == "fleet20k-v1";
        if !fleet && self.profile != "fixture-v1" {
            return Err("profile must be fleet20k-v1 or fixture-v1".into());
        }
        if (fleet && self.agents < 20_000)
            || !(1..=100_000).contains(&self.agents)
            || !(1..=16).contains(&self.listeners)
            || self.listeners > self.agents
            || !(1..=1024).contains(&self.concurrency)
            || self.concurrency > self.agents
            || !(2..=64).contains(&self.runtime_threads)
            || !(1..=100).contains(&self.rounds)
            || !(1..=3600).contains(&self.timeout_secs)
            || self.hold_ms == 0
            || self.hold_ms > 3_600_000
            || (fleet && self.hold_ms < 1000)
            || !(16..=100_000).contains(&self.ppr_nodes)
            || self.ppr_samples == 0
            || self.ppr_samples > self.ppr_nodes
            || (fleet && self.ppr_samples < 100)
            || self.map_size < 32 * 1024 * 1024
        {
            return Err(
                "invalid fleet dimensions (fleet needs >=20k agents, >=1s hold, >=100 PPR pairs)"
                    .into(),
            );
        }
        if self.host_label.trim().is_empty()
            || self.storage_label.trim().is_empty()
            || !self.scratch.is_absolute()
            || !self.scratch.is_dir()
        {
            return Err(
                "host/storage labels and an existing absolute scratch directory are required"
                    .into(),
            );
        }
        Ok(())
    }
}
