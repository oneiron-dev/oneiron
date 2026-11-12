//! Moved from `crates/oneiron/src/agent_dispatch/spend_calibration.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The expected spend of an agent with no settled launch yet. A PRIOR, never
/// a calibration: one model call's default reservation
/// ([`oneiron_model::llm::DEFAULT_BUDGET_RESERVE_UNITS`]).
pub const LAUNCH_COST_PRIOR_UNITS: u64 = oneiron_model::llm::DEFAULT_BUDGET_RESERVE_UNITS;

/// What one agent's settled launches spent, in one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSpendCalibration {
    pub samples: u64,
    /// Saturating.
    pub total_units: u64,
    /// Exponentially weighted mean, alpha 1/4; the first sample sets it.
    pub ewma_units: u64,
    pub last_units: u64,
    /// Unix seconds.
    pub updated_at: u64,
}

impl AgentSpendCalibration {
    fn fold(previous: Option<Self>, units: u64, now: u64) -> Self {
        match previous {
            None => Self {
                samples: 1,
                total_units: units,
                ewma_units: units,
                last_units: units,
                updated_at: now,
            },
            Some(previous) => {
                // (3 * mean + sample) / 4, rounded, in wide integer math.
                let ewma = (u128::from(previous.ewma_units) * 3 + u128::from(units) + 2) / 4;
                Self {
                    samples: previous.samples.saturating_add(1),
                    total_units: previous.total_units.saturating_add(units),
                    ewma_units: u64::try_from(ewma).unwrap_or(u64::MAX),
                    last_units: units,
                    updated_at: now,
                }
            }
        }
    }
}

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
