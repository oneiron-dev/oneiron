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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FederationBurstWorld {
    All,
    Base,
    World { world_ref: EntityId },
}

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

/// A named normal rate and normal completed structural-failure streak.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationBurstBaseline {
    pub name: String,
    pub writes_per_sec: f64,
    pub structural_streak: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum FederationBurstOutcome {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "isolate-and-propose")]
    IsolateAndPropose,
    #[serde(rename = "defer")]
    Defer,
}

/// Ordinary work is allowed. These outcomes route an unusual rate, then an
/// unusual rate with an unusual structural-failure streak. No model is used.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationBurstPolicy {
    /// None uses the peer's observed, completed-tick baseline.
    pub baseline: Option<FederationBurstBaseline>,
    pub unusual_rate: FederationBurstOutcome,
    pub unusual_streak: FederationBurstOutcome,
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

impl FederationBurstPolicy {
    pub(super) fn validate(&self) -> Result<()> {
        if self.baseline.as_ref().is_some_and(|row| {
            row.name.trim().is_empty()
                || !row.writes_per_sec.is_finite()
                || row.writes_per_sec <= 0.0
                || !row.structural_streak.is_finite()
                || row.structural_streak <= 0.0
        }) {
            return Err(Error::InvalidConfig(
                "burst baseline needs a name and positive finite rates".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationBurstBaselineState {
    pub baseline: FederationBurstBaseline,
    pub learned: bool,
    pub vault_size: u64,
    pub recent_writes: u64,
    pub rate_ratio: f32,
    pub streak: u32,
    pub streak_ratio: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FederationBurstWorkState {
    Pending,
    Imported,
    Rejected,
    /// Its wait ended before its turn came; nothing was imported (FIX 7997).
    Expired,
    /// It was held under a grant or pact scope that has changed since. Its
    /// bytes were never imported, and it counts as no structural failure
    /// (FIX 7999).
    StaleAuthority,
    /// An erase took a row its bytes carried; only this receipt is kept
    /// (FIX 7998).
    Erased,
}

impl FederationBurstWorkState {
    /// Whether the batch's delivery is settled for good, so a resend of the
    /// same bytes answers with this receipt. A batch that ended any other
    /// way may be sent again, and that delivery starts afresh.
    pub const fn is_settled(self) -> bool {
        matches!(self, Self::Imported | Self::Rejected)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome")]
pub enum FederationBurstDisposition {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "isolate-and-propose")]
    IsolateAndPropose {
        bundle_ref: String,
        replay_ref: String,
    },
    #[serde(rename = "defer")]
    Defer { replay_ref: String },
}

/// A stable batch identity, its original routed outcome, and its current
/// completion state. Replay does not erase the original disposition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationBurstReceipt {
    pub batch_ref: String,
    pub principal: EntityId,
    pub grant: EntityId,
    pub window_key: String,
    pub disposition: FederationBurstDisposition,
    pub state: FederationBurstWorkState,
    pub baseline: FederationBurstBaselineState,
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

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationBurstReviewRequest {
    pub bundle_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationBurstReviewReceipt {
    pub bundle_ref: String,
    pub batches: Vec<FederationBurstReceipt>,
}
