//! Moved from `crates/oneiron/src/authority/slip_vault/connect_lifecycle.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use ed25519_dalek::Signer;
use oneiron_authority::federation::FederationDirectionScope;
use oneiron_authority::federation::Scope;
use oneiron_authority::federation::SelectorRange;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use rand_core::OsRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;

/// Filtered bytes bound by the host signature to a pact, epoch and destination.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectWindow {
    pub pact: String,
    pub epoch: u64,
    pub source_vault: String,
    pub recipient_vault: String,
    pub world_ref: oneiron_contracts::entity_id::EntityId,
    pub facets: Vec<oneiron_contracts::entity_id::EntityId>,
    pub bands: Vec<SelectorRange>,
    pub window_key: String,
    pub update: Vec<u8>,
}

impl ConnectWindow {
    /// A signature binds the admitted bytes to the disclosed axes, peer and epoch.
    pub fn transcript(&self) -> oneiron_base::error::Result<Vec<u8>> {
        rmp_serde::to_vec_named(&("oneiron/connect/window/v1", self)).map_err(|_| {
            oneiron_base::error::Error::InvalidConfig("Connect window encoding failed".into())
        })
    }
}

/// The authority context signed together with the stripped canonical envelope body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestDocumentContext {
    pub pact: String,
    pub epoch: u64,
    pub ceiling: Scope,
    pub effective_scope: FederationDirectionScope,
}

impl GuestDocumentContext {
    pub fn transcript(&self, envelope: &[u8]) -> oneiron_base::error::Result<Vec<u8>> {
        rmp_serde::to_vec_named(&("oneiron/guest-document/v1", self, envelope)).map_err(|_| {
            oneiron_base::error::Error::InvalidConfig("guest document encoding failed".into())
        })
    }
}
