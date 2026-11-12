//! Moved from `crates/oneiron/src/runtime_hooks/replay.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::runtime_hooks::source::FactKind;
use crate::runtime_hooks::source::FactPositionHex;
use crate::runtime_hooks::source::FactSource;
use crate::store::pack_hook_proposal::HookPhase;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::cell::RefCell;
use std::sync::Arc;

/// One past entry the hook takes, and what its body returns for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct HookReplayEntry {
    pub case: HookReplayCase,
    pub result: HookReplayResult,
}

/// What a replayed entry is: a fact the hook took, or a verb run it saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "on", rename_all = "snake_case")]
pub enum HookReplayCase {
    /// A fact the hook took, at its source position.
    Fact {
        source: FactSource,
        position: FactPositionHex,
        kind: FactKind,
        #[serde(with = "oneiron_contracts::serialize::entity_ref")]
        #[schemars(with = "String")]
        entity: EntityId,
    },
    /// A verb run the hook saved, by its run key.
    Verb {
        /// The run's key, as 64 hex.
        run_key: String,
        /// The call's invocation, as 32 hex.
        invocation: String,
        verb: String,
        phase: HookPhase,
    },
    /// A run the run index names whose saved row is gone: only its run key
    /// remains, so this entry carries nothing else (FIX 2394).
    UnknownRun {
        /// The run's key, as 64 hex.
        run_key: String,
    },
}

/// How a replayed outcome stands to the one its run recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookReplayCompare {
    /// The same outcome, as JSON.
    Same,
    /// Another outcome, or none where the run returned one.
    Differs,
    /// Nothing to compare with: the run kept no outcome, or none ran.
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HookReplayResult {
    /// The body ran on this entry. Nothing landed.
    Ran {
        outcome_json: Option<String>,
        /// The outcome kind, or `refused` / `failed`.
        outcome: String,
        reason: Option<String>,
        /// The outcome the live run recorded, when one ran.
        recorded: Option<String>,
        /// The outcome JSON the live run recorded, when it kept one.
        recorded_outcome_json: Option<String>,
        compare: HookReplayCompare,
        /// The input came from the run's saved row: its memo, or its saved
        /// verb run.
        from_memo: bool,
        /// No run pinned this entry's reads; they read current rows.
        reads_live: bool,
    },
    /// The hook's current grant no longer shows a saved dependency.
    Withheld { reason: String },
    /// The entry's inputs are gone: replay will not read newer state instead.
    MissingHistory { reason: String },
}
