//! Moved from `crates/oneiron/src/dreamer_consolidation/thing_agent.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::BudgetGuard;
use oneiron_model::llm::Scope;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// `self.dreamer.thing.extract`'s input: one lent slice input, by its name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThingExtractInput {
    /// A slice input's name, as `src` lists it; any piece of the slice names
    /// it.
    pub input: String,
}

/// What `self.dreamer.thing.extract` staged for one slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThingExtractOutput {
    /// The slice's input name.
    pub input: String,
    /// `staged`: its draft is staged and each candidate has its ref.
    pub state: String,
    /// One engine-issued ref for each candidate the reply drafted.
    pub proposals: Vec<ThingProposalRef>,
    /// The people the reply declares.
    pub persons: u32,
    /// Whether the reply is a deterministic fallback.
    pub fallback: bool,
}

/// One engine-staged draft candidate: the child run it was staged for, the
/// path of the draft in its parent's ledger, and the candidate's engine id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThingProposalRef {
    pub child_run: String,
    pub output_path: String,
    pub candidate_id: String,
}

/// `self.dreamer.thing.decide`'s input: one lent pack, by its name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThingDecideInput {
    /// A pack input's name, as `src` lists it.
    pub pack: String,
}

/// What `self.dreamer.thing.decide` came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThingDecideOutput {
    /// The pack's input name.
    pub pack: String,
    /// `decided` once its kept answers are staged; `pending` while a slice
    /// it reads is not extracted yet; `deferred` when it reads a low-trust
    /// slice the agent was not lent, so the engine decides it on its own
    /// path once that slice is extracted (FIX 9017).
    pub state: String,
    /// The candidates the pack decided for.
    pub questions: u32,
    /// The slice inputs it still waits on.
    pub missing: Vec<String>,
}
