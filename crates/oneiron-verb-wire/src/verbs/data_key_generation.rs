//! `vault.data_key.generation.propose`'s wire: an agent's ask that the owners
//! start a new vault data-key generation, carrying the agent's reason.
//! `oneiron` re-exports each item from `verbs::data_key_generation`.

use serde::Deserialize;
use serde::Serialize;

/// `vault.data_key.generation.propose`'s input: the agent's reason for the
/// ask, shown to the owners as it is. Absent, or blank, the ask names no
/// reason.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DataKeyGenerationProposeRequest {
    #[serde(default)]
    pub reason: Option<String>,
}
