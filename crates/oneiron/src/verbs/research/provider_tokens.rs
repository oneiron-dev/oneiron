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
    /// Native scoped model-call entries and observed future returns. This
    /// does not seal the run, enumerate all sources or finalize its scope.
    pub run_observations: Vec<ResearchProviderRunTokenObservationWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResearchProviderRunTokenObservationWire {
    pub instance: String,
    /// Actual executed caller, when its native lease supplied one; not authority.
    pub owner_attempt: Option<String>,
    pub entry_recorded: bool,
    pub model_future_returned: bool,
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
    /// This permit's executed caller, not an attribution of scope aggregates.
    pub owner_attempt: Option<String>,
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
    /// Every slot registered on this native lease at its settlement capture,
    /// including empty slots. No full-source or scope completeness implied.
    pub observed_slots: Vec<ResearchObservedInferenceSlotWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResearchObservedInferenceSlotWire {
    /// Native index within this actual run instance and lease, not a global id.
    pub slot: usize,
    /// None means the publisher recorded nothing, not zero usage or no request.
    pub observation: Option<ResearchObservedInferenceTokensWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResearchObservedInferenceTokensWire {
    /// Only the native publisher's Partial/Final tag supplies this status.
    pub final_observed: bool,
    pub tokens: ResearchProviderTokenMeasurementWire,
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
                                            owner_attempt: lease.owner_attempt.map(|attempt| {
                                                crate::entity_id::bytes_to_hex_lower(attempt.as_bytes())
                                            }),
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
                                                    observed_slots: settlement
                                                        .observed_slots
                                                        .into_iter()
                                                        .map(|slot| ResearchObservedInferenceSlotWire {
                                                            slot: slot.slot,
                                                            observation: slot.observation.map(|observation| {
                                                                ResearchObservedInferenceTokensWire {
                                                                    final_observed: observation.final_observed,
                                                                    tokens: observation.tokens.into(),
                                                                }
                                                            }),
                                                        })
                                                        .collect(),
                                                }
                                            }),
                                        })
                                        .collect(),
                                    run_observations: capture
                                        .run_observations
                                        .into_iter()
                                        .map(|run| ResearchProviderRunTokenObservationWire {
                                            instance: crate::entity_id::bytes_to_hex_lower(
                                                run.instance.as_bytes(),
                                            ),
                                            owner_attempt: run.owner_attempt.map(|attempt| {
                                                crate::entity_id::bytes_to_hex_lower(attempt.as_bytes())
                                            }),
                                            entry_recorded: run.entry_recorded,
                                            model_future_returned: run.model_future_returned,
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
