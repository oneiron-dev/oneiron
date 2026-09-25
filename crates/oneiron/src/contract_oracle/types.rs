//! Contract input, snapshot and persisted verdict types.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Every declared output must be observed; omitted checks never count as green.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSpec {
    /// Crate name -> root source file relative to the materialized tree.
    pub rust_crates: BTreeMap<String, String>,
    /// Contract name -> JSON schema file relative to the materialized tree.
    pub schemas: BTreeMap<String, String>,
    /// Host check identifiers. Hosts run their own bounded, sandboxed commands.
    pub outputs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSnapshot {
    pub public_names: BTreeSet<String>,
    pub schemas: BTreeMap<String, serde_json::Value>,
    pub outputs: BTreeMap<String, CommandOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractBaseline {
    pub schema_version: u8,
    pub id: String,
    pub spec: ContractSpec,
    pub snapshot: ContractSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractDiff {
    RemovedPublicName {
        name: String,
    },
    SchemaDrift {
        contract: String,
        pointer: String,
        before: Option<serde_json::Value>,
        after: Option<serde_json::Value>,
    },
    OutputDrift {
        contract: String,
        before: Option<CommandOutput>,
        after: Option<CommandOutput>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractVerdict {
    pub schema_version: u8,
    pub id: String,
    pub baseline_id: String,
    /// Immutable tested tree and check-plan identity supplied by the queue.
    pub candidate: String,
    pub tests_passed: bool,
    pub diffs: Vec<ContractDiff>,
}

impl ContractVerdict {
    #[must_use]
    pub fn passes(&self) -> bool {
        self.tests_passed && self.diffs.is_empty()
    }
}
