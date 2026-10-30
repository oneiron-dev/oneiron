//! Typed Connect, reciprocal re-scope, disconnect and foreign-world delivery.
use serde::{Deserialize, Serialize};

use crate::federation::{FederationDirectionScope, FederationPactScope, Scope, SelectorRange};
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectIdentity {
    pub vault: String,
    pub host_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MintConnectGrant {
    pub peer_vault: String,
    pub authority_scope: Scope,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectGrant {
    pub grant: String,
    pub guest_actor: String,
    pub resolved_scope: Scope,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferConnect {
    pub peer_vault: String,
    pub grant: String,
    pub outbound: FederationDirectionScope,
    pub inbound: FederationDirectionScope,
}

/// A host-signed Connect half; the two hosts sign identical disclosed terms.
/// It prints its key redacted.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub pact: String,
    pub nonce: String,
    pub from: String,
    pub to: String,
    pub scope: FederationPactScope,
    pub signer: String,
    pub signature: String,
    /// The pact epoch's scope opening key, 64 hex (FIX 7907, 7958): what
    /// the scope commitment is keyed by, outside the signed transcript and
    /// logged nowhere; each host's custody holds it until the pact ends.
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AcceptConnect {
    pub offer: Offer,
    pub grant: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectAccepted {
    pub pact: String,
    pub status: String,
    pub peer_key: String,
    pub counter: Offer,
}

/// A unilateral narrow never restores an axis excluded by the current overlay.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NarrowConnect {
    pub pact: String,
    pub epoch: u64,
    pub outbound: FederationDirectionScope,
}

/// Fresh reciprocal consent, including the full directional disclosure.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RescopeConnect {
    pub pact: String,
    pub epoch: u64,
    pub outbound: FederationDirectionScope,
    pub inbound: FederationDirectionScope,
}

/// A host-signed re-scope half. It prints its key redacted.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RescopeOffer {
    pub pact: String,
    pub epoch: u64,
    pub nonce: String,
    pub from: String,
    pub to: String,
    pub scope: FederationPactScope,
    pub signer: String,
    pub signature: String,
    /// The new epoch's scope opening key, 64 hex (FIX 7907, 7958).
    pub key: String,
}

impl std::fmt::Debug for Offer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Offer")
            .field("pact", &self.pact)
            .field("nonce", &self.nonce)
            .field("from", &self.from)
            .field("to", &self.to)
            .field("scope", &self.scope)
            .field("signer", &self.signer)
            .field("signature", &self.signature)
            .field("key", &"..")
            .finish()
    }
}

impl std::fmt::Debug for RescopeOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RescopeOffer")
            .field("pact", &self.pact)
            .field("epoch", &self.epoch)
            .field("nonce", &self.nonce)
            .field("from", &self.from)
            .field("to", &self.to)
            .field("scope", &self.scope)
            .field("signer", &self.signer)
            .field("signature", &self.signature)
            .field("key", &"..")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AcceptRescopeConnect {
    pub offer: RescopeOffer,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectPactRequest {
    pub pact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectPactReceipt {
    pub pact: String,
    pub status: crate::authority::FederationPactStatus,
    pub epoch: u64,
    pub scope: FederationPactScope,
    pub effective_scope: FederationDirectionScope,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectRescoped {
    pub receipt: ConnectPactReceipt,
    pub counter: RescopeOffer,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectDisconnected {
    pub receipt: ConnectPactReceipt,
    /// Both directions at this host stop; a retained peer copy is not erased.
    pub outbound_access: bool,
    pub inbound_access: bool,
    pub sync_stopped: bool,
    pub copied_bytes_recallable: bool,
    #[schemars(with = "String")]
    pub recipient_copy_state: crate::receipt::GuestCopyState,
}

/// One named sender world. Empty facet/band requests leave the pact ceiling alone.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectExportRequest {
    pub pact: String,
    pub window_key: String,
    pub world_ref: crate::EntityId,
    #[serde(default)]
    pub facets: Vec<crate::EntityId>,
    #[serde(default)]
    pub bands: Vec<SelectorRange>,
}

/// Filtered bytes bound by the host signature to a pact, epoch and destination.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectWindow {
    pub pact: String,
    pub epoch: u64,
    pub source_vault: String,
    pub recipient_vault: String,
    pub world_ref: crate::EntityId,
    pub facets: Vec<crate::EntityId>,
    pub bands: Vec<SelectorRange>,
    pub window_key: String,
    pub update: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectDelivery {
    pub body: ConnectWindow,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectRejoinStatus {
    Imported,
    Deferred,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectRejoined {
    pub pact: String,
    pub epoch: u64,
    pub world_ref: crate::EntityId,
    pub status: ConnectRejoinStatus,
    pub request: Option<String>,
}

/// Embedded vaults hold no host-root signer or served window manager.
pub fn connect_host_only<T, I>(memory: &Memory<'_>, verb: &str, _input: &I) -> MemoryResult<T> {
    let _owner = memory.embedded_owner(verb)?;
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{verb} requires the serving host's signer and federation transport"),
        &[super::host::SERVED_CLIENT_HINT],
    ))
}

impl ConnectWindow {
    /// A signature binds the admitted bytes to the disclosed axes, peer and epoch.
    pub(crate) fn transcript(&self) -> crate::Result<Vec<u8>> {
        rmp_serde::to_vec_named(&("oneiron/connect/window/v1", self))
            .map_err(|_| crate::Error::InvalidConfig("Connect window encoding failed".into()))
    }
}
