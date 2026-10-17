//! Per-agent spend calibration, learned from settled launches (OF-532).
//!
//! A child's settlement is its receipt: what the child and its settled
//! subtree actually spent. Each settlement folds one sample into its agent's
//! row. The key is the AGENT_DEF entity id the launch REQUESTED, before
//! attenuation: an attenuated fork is the same agent under a narrower
//! ceiling, so it shares its source's calibration. Seeded rows (`sys.*`) have
//! pinned entity ids, so the key is stable for them too.
//!
//! A peer consult is a TASK delivery, never a local agent, so it has its own
//! key (`consult:{peer hex}:{unit}`) and never reads an agent's row (OF-393).
//! A consult completion that carries its executor's measured total folds
//! one sample, in the commit that lands it; an unmeasured consult leaves its
//! peer on the labelled prior.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::run_admission::LeaseUnit;
use crate::side_table::{self, LegacyJson, SideTable};

use super::AgentDispatcher;

/// The expected spend of an agent with no settled launch yet. A PRIOR, never
/// a calibration: one model call's default reservation
/// ([`crate::llm::DEFAULT_BUDGET_RESERVE_UNITS`]).
pub const LAUNCH_COST_PRIOR_UNITS: u64 = crate::llm::DEFAULT_BUDGET_RESERVE_UNITS;

/// Per-agent, per-unit spend calibration. Key: `{agent_def hex}:{unit}`; a
/// peer consult's is `consult:{peer hex}:{unit}`.
pub(super) const CALIBRATION: SideTable<String, AgentSpendCalibration, LegacyJson> =
    SideTable::new(&side_table::AGENT_DISPATCH_SPEND_CALIBRATION);

/// What one agent's settled launches spent, in one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendBasis {
    /// Learned from settled launches of this agent.
    Calibrated,
    /// [`LAUNCH_COST_PRIOR_UNITS`]: no settled launch yet. Never calibrated.
    Prior,
}

/// An expected spend and the evidence behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedSpend {
    pub units: u64,
    /// The settled samples behind the figure (summed over a tree's nodes).
    pub samples: u64,
    pub basis: SpendBasis,
}

impl ExpectedSpend {
    /// The labelled prior: [`LAUNCH_COST_PRIOR_UNITS`], no samples.
    pub(super) const fn prior() -> Self {
        Self {
            units: LAUNCH_COST_PRIOR_UNITS,
            samples: 0,
            basis: SpendBasis::Prior,
        }
    }

    fn from_row(row: Option<AgentSpendCalibration>) -> Self {
        match row {
            Some(row) if row.samples > 0 => Self {
                units: row.ewma_units,
                samples: row.samples,
                basis: SpendBasis::Calibrated,
            },
            _ => Self::prior(),
        }
    }

    /// A tree's expected spend: the saturating sum. It is a prior if any node is.
    #[must_use]
    pub fn sum(nodes: impl IntoIterator<Item = Self>) -> Self {
        let mut total = Self {
            units: 0,
            samples: 0,
            basis: SpendBasis::Calibrated,
        };
        let mut any = false;
        for node in nodes {
            any = true;
            total.units = total.units.saturating_add(node.units);
            total.samples = total.samples.saturating_add(node.samples);
            if node.basis == SpendBasis::Prior {
                total.basis = SpendBasis::Prior;
            }
        }
        if !any {
            total.basis = SpendBasis::Prior;
        }
        total
    }
}

fn calibration_key(agent: &EntityId, unit: &LeaseUnit) -> String {
    format!("{}:{}", agent.to_hex(), unit.as_str())
}

fn consult_calibration_key(peer: &EntityId, unit: &LeaseUnit) -> String {
    format!("consult:{}:{}", peer.to_hex(), unit.as_str())
}

impl AgentDispatcher<'_> {
    /// One agent's expected spend in `unit`: its calibrated mean, or the
    /// labelled prior when it has no settled launch.
    pub fn expected_agent_spend(&self, agent: EntityId, unit: &LeaseUnit) -> Result<ExpectedSpend> {
        let txn = self.vault.store.env.read_txn()?;
        self.expected_agent_spend_in_txn(&txn, agent, unit)
    }

    /// The raw calibration row behind [`Self::expected_agent_spend`].
    pub fn agent_spend_calibration(
        &self,
        agent: EntityId,
        unit: &LeaseUnit,
    ) -> Result<Option<AgentSpendCalibration>> {
        let txn = self.vault.store.env.read_txn()?;
        CALIBRATION.get(&self.vault.store, &txn, &calibration_key(&agent, unit))
    }

    pub(super) fn expected_agent_spend_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
        unit: &LeaseUnit,
    ) -> Result<ExpectedSpend> {
        Ok(ExpectedSpend::from_row(CALIBRATION.get(
            &self.vault.store,
            txn,
            &calibration_key(&agent, unit),
        )?))
    }

    /// One consult's expected spend in `unit` when delivered to `peer`: its
    /// calibrated mean once consult samples exist, the labelled prior until
    /// then. Never an agent's row.
    pub fn expected_consult_spend(
        &self,
        peer: EntityId,
        unit: &LeaseUnit,
    ) -> Result<ExpectedSpend> {
        let txn = self.vault.store.env.read_txn()?;
        self.expected_consult_spend_in_txn(&txn, peer, unit)
    }

    pub(super) fn expected_consult_spend_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        peer: EntityId,
        unit: &LeaseUnit,
    ) -> Result<ExpectedSpend> {
        Ok(ExpectedSpend::from_row(CALIBRATION.get(
            &self.vault.store,
            txn,
            &consult_calibration_key(&peer, unit),
        )?))
    }

    /// Folds one settled launch's spend into its agent's calibration.
    pub(super) fn fold_spend_sample_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        agent: EntityId,
        unit: &LeaseUnit,
        units: u64,
        now: u64,
    ) -> Result<AgentSpendCalibration> {
        self.fold_sample_in_txn(txn, calibration_key(&agent, unit), units, now)
    }

    /// Folds one landed consult's measured spend into its peer's consult
    /// calibration. The caller fences replay: one sample per consult.
    pub(crate) fn fold_consult_spend_sample_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        peer: EntityId,
        unit: &LeaseUnit,
        units: u64,
        now: u64,
    ) -> Result<AgentSpendCalibration> {
        self.fold_sample_in_txn(txn, consult_calibration_key(&peer, unit), units, now)
    }

    fn fold_sample_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        key: String,
        units: u64,
        now: u64,
    ) -> Result<AgentSpendCalibration> {
        let previous = CALIBRATION.get(&self.vault.store, txn, &key)?;
        let row = AgentSpendCalibration::fold(previous, units, now);
        CALIBRATION.put(&self.vault.store, txn, &key, &row)?;
        Ok(row)
    }
}
