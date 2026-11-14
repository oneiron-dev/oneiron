//! Moved from `crates/oneiron/src/gate/policy_manifest_doors/agent_verb_classes.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// One owner verb-class row: a class an agent Grant may name, and the exact
/// verbs it admits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentVerbClassRow {
    /// The class name a Grant's `verb_classes` names: nonempty, no
    /// surrounding whitespace, never `git_push`.
    pub name: String,
    /// Its member verbs, exact verb strings: nonempty, never `git_push`,
    /// never another row's class.
    pub verbs: BTreeSet<String>,
}

/// `vault.agents.verb_classes.configure`'s input: the whole table, against
/// the manifest the owner read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentVerbClassesConfigureRequest {
    pub expected_body_hash: String,
    /// Every row the table holds after the edit, one per class; empty
    /// clears it.
    pub classes: Vec<AgentVerbClassRow>,
}

/// The owner's verb-class rows and the default manifest's edit precondition.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentVerbClassesView {
    pub manifest_ref: String,
    pub body_hash: String,
    /// The rows, in class order.
    pub classes: Vec<AgentVerbClassRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentVerbClassesReceipt {
    pub configuration: AgentVerbClassesView,
    pub receipt_ref: String,
}
