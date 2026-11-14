//! Moved from `crates/oneiron/src/agent_dispatch/spend_calibration.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The expected spend of an agent with no settled launch yet. A PRIOR, never
/// a calibration: one model call's default reservation
/// ([`oneiron_model::llm::DEFAULT_BUDGET_RESERVE_UNITS`]).
pub const LAUNCH_COST_PRIOR_UNITS: u64 = oneiron_model::llm::DEFAULT_BUDGET_RESERVE_UNITS;

/// Where an expected spend comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpendBasis {
    /// Learned from settled launches of this agent.
    Calibrated,
    /// [`LAUNCH_COST_PRIOR_UNITS`]: no settled launch yet. Never calibrated.
    Prior,
}

/// Where an expected dollar figure comes from. Calibrated native units do
/// not make the dollars calibrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DollarBasis {
    /// The host quotes no USD price for this unit, model or route: the
    /// figure is unknown, never zero.
    UnknownPrice,
    /// Every native unit priced at the model's highest catalog rate (input,
    /// output or cache), so the figure is an upper bound until the
    /// calibration measures an input/output mix.
    UpperBoundRate,
    /// A tree's sum of its nodes' priced figures; each keeps its own basis.
    Sum,
    /// A node had no price, or the dollar sum overflowed: unknown, never a
    /// priced subtotal.
    IncompleteOrOverflow,
}

impl DollarBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownPrice => "unknown_price",
            Self::UpperBoundRate => "upper_bound_rate",
            Self::Sum => "sum",
            Self::IncompleteOrOverflow => "incomplete_or_overflow",
        }
    }
}

/// What a launch's dollar figure prices: a local agent, or a peer consult,
/// which is never priced at a local agent's rate. An agent's `model` is its
/// plan's resolved model, a pin included, when the launch has one (FIX
/// 3043); `None` prices the role's binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsdPriceTarget<'a> {
    Agent {
        agent: EntityId,
        model: Option<&'a oneiron_model::llm::ModelId>,
    },
    PeerConsult(EntityId),
}
