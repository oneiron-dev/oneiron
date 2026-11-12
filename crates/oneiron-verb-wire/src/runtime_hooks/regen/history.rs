//! Moved from `crates/oneiron/src/runtime_hooks/regen/history.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::runtime_hooks::regen::HookContractStamp;
use crate::runtime_hooks::regen::HookGoldenDiff;
use crate::runtime_hooks::regen::HookGoldenManifest;
use crate::runtime_hooks::regen::HookRegenFailure;
use crate::runtime_hooks::regen::HookRegenOutcome;
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Who ran or enacted a regen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "by", rename_all = "snake_case")]
pub enum HookRegenActor {
    /// The engine's own pass after a verb-table or sandbox-contract change.
    Engine,
    /// The vault's owner, on any hook of the vault's own packs.
    Owner {
        #[serde(with = "oneiron_contracts::serialize::entity_ref")]
        #[schemars(with = "String")]
        actor: EntityId,
    },
    /// A resident agent, on a hook it authored.
    Agent {
        #[serde(with = "oneiron_contracts::serialize::entity_ref")]
        #[schemars(with = "String")]
        agent: EntityId,
    },
}

/// What a regen decided, as its receipt keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookRegenDecision {
    AutoAdopt,
    NeedsHumanStamp,
    RolledBack,
}

/// One step in a hook's regen history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HookRegenEvent {
    /// A regen ran and decided: the candidate it holds, the contract it ran
    /// against, and the golden manifest and diff it stood on. A failed regen
    /// keeps its failure and no candidate.
    Decided {
        decision: HookRegenDecision,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        candidate_hash: Option<String>,
        target: HookContractStamp,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        diff: Option<HookGoldenDiff>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        golden: Option<HookGoldenManifest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure: Option<HookRegenFailure>,
    },
    /// A pending candidate was installed as the hook's body. `stamped` says
    /// the owner's stamp enacted it; an identical fingerprint needs none.
    Adopted {
        candidate_hash: String,
        target: HookContractStamp,
        stamped: bool,
        /// The binding the new body bound under, when it is a new id.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "oneiron_contracts::serialize::entity_ref::optional"
        )]
        #[schemars(with = "Option<String>")]
        rebound: Option<EntityId>,
    },
    /// A waiting decision was set aside unenacted; the hook stays on its
    /// body, and the contract it targeted is declined.
    Cancelled {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        candidate_hash: Option<String>,
        declined: HookContractStamp,
    },
    /// An adoption was reverted by hand: the body it replaced is the hook's
    /// body again, and the contract in force is declined.
    Reverted {
        /// The adopted body taken out.
        from_hash: String,
        /// The body put back.
        to_hash: String,
        declined: HookContractStamp,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "oneiron_contracts::serialize::entity_ref::optional"
        )]
        #[schemars(with = "Option<String>")]
        rebound: Option<EntityId>,
    },
}

impl HookRegenEvent {
    /// The receipt event of a regen decision.
    pub fn decided(outcome: &HookRegenOutcome) -> Self {
        match outcome {
            HookRegenOutcome::AutoAdopt {
                target,
                diff,
                golden,
                ..
            }
            | HookRegenOutcome::NeedsHumanStamp {
                target,
                diff,
                golden,
                ..
            } => Self::Decided {
                decision: if matches!(outcome, HookRegenOutcome::AutoAdopt { .. }) {
                    HookRegenDecision::AutoAdopt
                } else {
                    HookRegenDecision::NeedsHumanStamp
                },
                candidate_hash: outcome.candidate_hash(),
                target: target.clone(),
                diff: Some(diff.clone()),
                golden: Some(golden.clone()),
                failure: None,
            },
            HookRegenOutcome::RolledBack { failure, target } => Self::Decided {
                decision: HookRegenDecision::RolledBack,
                candidate_hash: None,
                target: target.clone(),
                diff: None,
                golden: None,
                failure: Some(failure.clone()),
            },
        }
    }
}

/// One regen receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookRegenReceipt {
    /// Its place in the hook's history, from 0.
    pub sequence: u64,
    /// The binding the event acted on.
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub binding: EntityId,
    /// When it was recorded, in the vault clock's seconds.
    pub recorded_at: u64,
    pub actor: HookRegenActor,
    /// The hook's last good body once the event stood, as BLAKE3 hex.
    pub body_hash: String,
    pub event: HookRegenEvent,
}
