//! Durable spend scopes and their typed reads (OF-532). Records confer no
//! authority; they bound spend.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::llm::run_admission::{JobStartRefused, LeaseUnit};
use crate::side_table::{self, LegacyJson, SideTable};

use super::spend_calibration::AgentSpendCalibration;

/// One launch tree's spend scopes. Key: the scope id.
pub(super) const SCOPE: SideTable<String, SpendScope, LegacyJson> =
    SideTable::new(&side_table::AGENT_DISPATCH_SPEND_SCOPE);

pub use crate::workspace_roster::spend_scope::{SpendScopeId, SpendState};

/// The payer's consent a root scope carries (OF-531): this PERSON was shown
/// the root's cap and accepted it for this scope. Children inherit it by
/// walking to their root; it is never copied. A cap, a scope id or an attempt
/// id is never this evidence by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpendPayer {
    /// The PERSON whose funds the tree spends.
    pub party: EntityId,
    /// The actor that took the payer's yes: the payer's own PERSON, or an
    /// actor anchored to it. Checked against the stored binding, never a label;
    /// `None` once the actor that took the yes was erased.
    pub granted_by: Option<EntityId>,
    /// When the payer accepted the cap, in host milliseconds.
    pub at_ms: u64,
}

/// The owner's agent Grant a root's work is funded by (FIX 7766, Engine
/// 19:59 W-B/W-E): chosen once when the root opens, validated in that
/// writer against the live Grant row and the owner's counted signed mint,
/// and frozen here. Children, retries, reservations and top-ups read it by
/// walking to their root; it is never copied onto a child and never
/// rebound. Every host-paid call the tree admits draws on `wallet_ref`'s
/// allocation, or is refused. It confers no authority and is no permission
/// axis: the cap stays the root's, the payer's consent stays the payer's.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantSpendBinding {
    /// The owner's agent Grant (its FEDERATION_GRANT row) that funds the work.
    pub grant_ref: EntityId,
    /// The authority entry of the owner's counted signed mint of that Grant
    /// (64 lowercase hex), which names the wallet.
    pub mint_act: String,
    /// The host wallet the Grant and its signed mint name.
    pub wallet_ref: crate::federation::WalletRef,
}

impl GrantSpendBinding {
    /// The binding the owner's selected funding Grant, proved in the root's
    /// writer, freezes.
    pub(crate) fn from_proof(proof: &crate::federation::SelectedOwnerAgentFundingGrant) -> Self {
        Self {
            grant_ref: proof.grant_ref(),
            mint_act: crate::entity_id::bytes_to_hex_lower(proof.mint_act()),
            wallet_ref: proof.wallet_ref().clone(),
        }
    }
}

/// The local calibration state before one scope's sample was folded.
/// The wrapper distinguishes the first sample (`before: None`) from a scope
/// that never contributed a sample on this vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpendCalibrationSample {
    pub before: Option<AgentSpendCalibration>,
}

impl SpendCalibrationSample {
    pub(super) fn ordinal(&self) -> u64 {
        self.before.as_ref().map_or(0, |row| row.samples)
    }
}

/// One node of a launch's lease tree.
///
/// `cap_units` is a hard scope's cap, or what a soft scope holds from its
/// parent (it grows when the scope tops up). `ceiling_units`, when present,
/// independently bounds that subtree without reserving it all. `held_units` is what this scope's
/// open children hold from it. What the scope may spend itself, before any top
/// up, is `cap_units - spent_units - held_units`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpendScope {
    pub scope: SpendScopeId,
    pub parent: Option<SpendScopeId>,
    pub unit: LeaseUnit,
    pub cap_units: u64,
    /// An admitted task's own subtree ceiling, separate from the amount
    /// currently held from its parent. It does not grant funds or consent.
    pub ceiling_units: Option<u64>,
    /// A root, or a child spawned with `budget`: it never draws past its cap.
    /// A soft child tops up from its parent chain to the nearest hard ancestor.
    pub hard: bool,
    /// Spent here, plus what settled children spent. Never truncated.
    pub spent_units: u64,
    /// What open children hold from this scope.
    pub held_units: u64,
    pub state: SpendState,
    /// When the customer was shown a root's cap, in host milliseconds.
    pub shown_at_ms: Option<u64>,
    /// Unix seconds.
    pub opened_at: u64,
    /// Unix seconds.
    pub closed_at: Option<u64>,
    /// The AGENT_DEF this scope's settlement calibrates; `None` for a root or
    /// an inert workflow wrapper, which are not agents.
    pub agent: Option<EntityId>,
    /// This vault's folded calibration sample; absent until settlement or
    /// when this scope has no local sample. Handoffs do not carry it.
    pub calibration_sample: Option<SpendCalibrationSample>,
    /// The attempt whose terminal settled this scope's exploration charge.
    /// A retry can own the route while sharing an earlier attempt's scope.
    pub exploration_attempt: Option<AttemptId>,
    /// A root's payer consent (OF-531); `None` on every child, which reads its
    /// root's, and on a root no payer accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<SpendPayer>,
    /// The owner's agent Grant a root's tree is funded by (FIX 7766), frozen
    /// when the root opened; `None` on every child, which reads its root's,
    /// and on a root no Grant funds, which draws on the host's live
    /// allocation as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding: Option<GrantSpendBinding>,
}

impl SpendScope {
    /// What this scope may spend from its own cap, without topping up.
    #[must_use]
    pub fn local_available(&self) -> u64 {
        self.cap_units
            .saturating_sub(self.spent_units.saturating_add(self.held_units))
    }

    pub(super) fn is_boundary(&self) -> bool {
        self.hard || self.ceiling_units.is_some()
    }

    pub(super) fn limit_units(&self) -> u64 {
        self.ceiling_units.map_or(self.cap_units, |ceiling| {
            if self.hard {
                ceiling.min(self.cap_units)
            } else {
                ceiling
            }
        })
    }

    /// A closed boundary retains its ceiling, not the hold already released
    /// into its parent at settlement.
    pub(super) fn boundary_available(&self) -> u64 {
        self.limit_units()
            .saturating_sub(self.spent_units.saturating_add(self.held_units))
    }

    pub(super) fn clamp_available(&self, available: u64) -> u64 {
        self.ceiling_units.map_or(available, |ceiling| {
            available.min(ceiling.saturating_sub(self.spent_units.saturating_add(self.held_units)))
        })
    }
}

pub use crate::workspace_roster::spend_scope::ChildSpend;

/// The one refusal of the lease tree: spend or a reservation beyond the cap.
#[derive(Debug, thiserror::Error)]
pub enum SpendRefused {
    #[error(
        "spend scope {scope} cannot cover {asked_units} units: {available_units} available under its cap"
    )]
    OverCap {
        scope: SpendScopeId,
        available_units: u64,
        asked_units: u64,
    },
    /// A root cap opens only as [`crate::llm::run_admission::JobMaximum`]
    /// starts: set, shown at the start, and more than zero.
    #[error(transparent)]
    Start(JobStartRefused),
    /// A storage or structural failure, not a refusal.
    #[error(transparent)]
    Engine(#[from] Error),
}

impl From<heed::Error> for SpendRefused {
    fn from(error: heed::Error) -> Self {
        Self::Engine(error.into())
    }
}

impl From<SpendRefused> for Error {
    fn from(refused: SpendRefused) -> Self {
        match refused {
            SpendRefused::Engine(error) => error,
            refused => Self::InvalidConfig(refused.to_string()),
        }
    }
}

/// What a spend crossed. The lease's own Suspend is the stop; these steer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "signal", rename_all = "snake_case")]
pub enum SpendSignal {
    /// At most 5 percent of the binding hard cap is left: start no new work,
    /// save partial results. Returned at every spend from here on.
    WrapUp {
        available_units: u64,
        cap_units: u64,
    },
    /// Nothing is left under the binding hard cap.
    AtCap { cap_units: u64 },
}

/// One scope after a spend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpendRead {
    pub scope: SpendScopeId,
    pub unit: LeaseUnit,
    pub spent_units: u64,
    /// What the scope may still spend, walking soft scopes up to the nearest
    /// hard ancestor.
    pub available_units: u64,
    /// The nearest hard scope or admitted task ceiling and its limit.
    pub cap_scope: SpendScopeId,
    pub cap_units: u64,
    pub signal: Option<SpendSignal>,
}

/// A child's settlement: its spend folded into its parent, its unused hold
/// released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendSettlement {
    pub scope: SpendScopeId,
    /// The open scope its spend was charged to; `None` for a pinned scope
    /// outside any tree.
    pub charged_to: Option<SpendScopeId>,
    pub spent_units: u64,
    pub released_units: u64,
    /// The child was already settled; nothing moved.
    pub already_settled: bool,
}

/// Forgets `actor` in every local spend scope, in its erase's transaction
/// (FIX 11777): an erased agent or payer party leaves `None`, and an erased
/// grantor leaves `granted_by` as `None` with the party kept, its spend still
/// on the party's standing. A row that does not read is passed over with a
/// WARN and never fails the erase.
pub(crate) fn erase_spend_scope_actor_in_txn(
    vault: &crate::Vault,
    txn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> crate::error::Result<()> {
    let mut scrubbed = Vec::new();
    for row in SCOPE.iter_raw_from(&vault.store, txn, &[])? {
        let (key, value) = row?;
        let scope = <String as crate::side_table::SideKey>::decode_key(&key)
            .ok_or_else(|| crate::error::Error::InvalidConfig("unreadable key".to_owned()))
            .and_then(|id| SCOPE.decode_value(&value).map(|scope| (id, scope)));
        let (id, mut scope) = match scope {
            Ok(row) => row,
            Err(error) => {
                tracing::warn!(%error, "an actor erase passed over a spend scope that does not read");
                continue;
            }
        };
        let mut hit = false;
        if scope.agent == Some(*actor) {
            scope.agent = None;
            hit = true;
        }
        if scope
            .payer
            .as_ref()
            .is_some_and(|payer| payer.party == *actor)
        {
            scope.payer = None;
            hit = true;
        } else if let Some(payer) = &mut scope.payer
            && payer.granted_by == Some(*actor)
        {
            payer.granted_by = None;
            hit = true;
        }
        if hit {
            scrubbed.push((id, scope));
        }
    }
    for (id, scope) in &scrubbed {
        SCOPE.put(&vault.store, txn, id, scope)?;
    }
    Ok(())
}
