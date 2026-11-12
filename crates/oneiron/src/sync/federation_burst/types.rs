//! Public peer-relative burst policy, receipts and retained-work addresses.
use serde::{Deserialize, Serialize};

use super::FederationPeer;
use crate::federation::SelectorRange;
use crate::sync::{SyncSelector, SyncSelectorWorld};
use crate::{EntityId, Error, FederationGrantScope, Result};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FederationBurstScope {
    Vault { vault_id: u64 },
    Connect { peer_vault_id: String },
}

impl FederationBurstScope {
    fn engine(&self) -> Result<FederationGrantScope> {
        Ok(match self {
            Self::Vault { vault_id } => FederationGrantScope::Vault {
                vault_id: *vault_id,
            },
            Self::Connect { peer_vault_id } => FederationGrantScope::Connect {
                peer_vault_id: crate::deletion::parse_hex::<32>(peer_vault_id)
                    .ok_or_else(|| Error::InvalidConfig("invalid peer_vault_id".into()))?,
            },
        })
    }
}

#[doc(hidden)]
pub use oneiron_verb_wire::sync::federation_burst::types::{
    FederationBurstBaseline, FederationBurstBaselineState, FederationBurstDisposition,
    FederationBurstOutcome, FederationBurstPolicy, FederationBurstReceipt,
    FederationBurstReviewReceipt, FederationBurstReviewRequest, FederationBurstWorkState,
    FederationBurstWorld,
};

/// A grant-backed address of retained peer work. Public lifecycle calls
/// take the owner's proof; no field authenticates an incoming peer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationBurstPeerRequest {
    pub principal: EntityId,
    pub grant: EntityId,
    pub scope: FederationBurstScope,
    pub world: FederationBurstWorld,
    #[serde(default)]
    pub facets: Vec<EntityId>,
    #[serde(default)]
    pub bands: Vec<SelectorRange>,
}

impl FederationBurstPeerRequest {
    pub fn authorize(&self, vault: &crate::Vault) -> Result<FederationPeer> {
        let world = match self.world {
            FederationBurstWorld::All => SyncSelectorWorld::All,
            FederationBurstWorld::Base => SyncSelectorWorld::Base,
            FederationBurstWorld::World { world_ref } => {
                SyncSelectorWorld::World(crate::entity_id::LocalWorldId::try_from(world_ref)?)
            }
        };
        let selector = SyncSelector::new(
            self.grant,
            self.principal,
            world,
            self.facets.clone(),
            self.bands.clone(),
        );
        FederationPeer::authorize(vault, self.principal, self.scope.engine()?, &selector)
    }
}

impl Default for FederationBurstPolicy {
    fn default() -> Self {
        Self {
            baseline: None,
            unusual_rate: FederationBurstOutcome::Defer,
            unusual_streak: FederationBurstOutcome::IsolateAndPropose,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationBurstPolicySetRequest {
    pub peer: FederationBurstPeerRequest,
    pub policy: FederationBurstPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationBurstReplayRequest {
    pub peer: FederationBurstPeerRequest,
    pub batch_ref: String,
}
