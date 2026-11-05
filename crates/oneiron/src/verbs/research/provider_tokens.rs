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
                            .map(|snapshot| ResearchProviderTokenSnapshotWire {
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
