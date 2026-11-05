//! Partial provider observations on the existing research budget read.

use serde::{Deserialize, Serialize};

use crate::autoreason_campaign::research;
use crate::{AttemptId, Vault};

/// Recorded provider captures for one native spend scope. Runs sharing
/// that scope share these rows; they are not separately attributed charges.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResearchScopeProviderTokensWire {
    pub scope: Option<crate::agent_dispatch::SpendScopeId>,
    /// The actual native run identifiers, in hex, not entity references or authority.
    pub runs: Vec<String>,
    /// None means unavailable; an empty list means no captures recorded,
    /// not a measured zero or proof that every generation was covered.
    pub snapshots: Option<Vec<ResearchProviderTokenSnapshotWire>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResearchProviderTokenSnapshotWire {
    pub generation: String,
    pub observation_id: String,
    pub dispatched_calls: usize,
    pub unsettled_calls: usize,
    pub input: Option<u64>,
    pub output: Option<u64>,
    /// Native reports retained by failed leases, not complete call totals.
    pub failed_call_reports: Vec<ResearchProviderTokenMeasurementWire>,
    /// Actual native permit identities and their recorded receipt stages.
    /// Missing permits or stages remain unknown; this is not a scope inventory.
    pub leases: Vec<ResearchProviderLeaseTokenObservationWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResearchProviderTokenMeasurementWire {
    pub input: Option<u64>,
    pub output: Option<u64>,
}

impl From<crate::llm::ProviderTokenMeasurement> for ResearchProviderTokenMeasurementWire {
    fn from(report: crate::llm::ProviderTokenMeasurement) -> Self {
        Self {
            input: report.input,
            output: report.output,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResearchProviderLeaseTokenObservationWire {
    /// Actual RunReceipt instance, in hex. This is not an AttemptId.
    pub instance: String,
    pub lease: String,
    pub admitted_receipt: bool,
    pub dispatched_receipt: bool,
    pub answered: Option<bool>,
    pub settlement: Option<ResearchProviderLeaseTokenSettlementWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResearchProviderLeaseTokenSettlementWire {
    /// Only this native permit ended, not the research run or spend scope.
    pub dispatched: bool,
    pub answer: Option<ResearchProviderTokenMeasurementWire>,
    /// Native inference receipts can be partial. No physical-request finality
    /// or complete call total is inferred from the list or its presence.
    pub reports: Vec<ResearchProviderTokenMeasurementWire>,
}

pub(super) fn read(vault: &Vault, root: AttemptId) -> Option<Vec<ResearchScopeProviderTokensWire>> {
    match research::research_provider_token_observations(vault, root) {
        Ok(scopes) => Some(
            scopes
                .into_iter()
                .map(|row| ResearchScopeProviderTokensWire {
                    scope: row.scope,
                    runs: row
                        .runs
                        .into_iter()
                        .map(|run| crate::entity_id::bytes_to_hex_lower(run.as_bytes()))
                        .collect(),
                    snapshots: row.snapshots.map(|snapshots| {
                        snapshots
                            .into_iter()
                            .map(|capture| {
                                let snapshot = capture.snapshot;
                                ResearchProviderTokenSnapshotWire {
                                    generation: crate::entity_id::bytes_to_hex_lower(
                                        &snapshot.generation,
                                    ),
                                    observation_id: crate::entity_id::bytes_to_hex_lower(
                                        &snapshot.observation_id,
                                    ),
                                    dispatched_calls: snapshot.observation.dispatched_calls,
                                    unsettled_calls: snapshot.observation.unsettled_calls,
                                    input: snapshot.observation.input,
                                    output: snapshot.observation.output,
                                    failed_call_reports: snapshot
                                        .failed_call_reports
                                        .into_iter()
                                        .map(Into::into)
                                        .collect(),
                                    leases: capture
                                        .leases
                                        .into_iter()
                                        .map(|lease| ResearchProviderLeaseTokenObservationWire {
                                            instance: crate::entity_id::bytes_to_hex_lower(
                                                lease.instance.as_bytes(),
                                            ),
                                            lease: lease.lease,
                                            admitted_receipt: lease.admitted_receipt,
                                            dispatched_receipt: lease.dispatched_receipt,
                                            answered: lease.answered,
                                            settlement: lease.settlement.map(|settlement| {
                                                ResearchProviderLeaseTokenSettlementWire {
                                                    dispatched: settlement.dispatched,
                                                    answer: settlement.answer.map(Into::into),
                                                    reports: settlement
                                                        .reports
                                                        .into_iter()
                                                        .map(Into::into)
                                                        .collect(),
                                                }
                                            }),
                                        })
                                        .collect(),
                                }
                            })
                            .collect()
                    }),
                })
                .collect(),
        ),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "research provider observations were not read");
            None
        }
    }
}
