//! Typed Connect, reciprocal re-scope, disconnect and foreign-world delivery.

use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};

pub use crate::authority::{
    FederationPactInactiveReason, FederationPactStatusRow, FederationStatus,
};

/// Reads this install's current pact status as the embedded vault owner.
pub fn federation_status(memory: &Memory<'_>) -> MemoryResult<FederationStatus> {
    let owner = memory.embedded_owner("vault.federation.status")?;
    Ok(memory.vault().federation_status_as_owner(&owner)?)
}

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::federation::{
    AcceptConnect, AcceptRescopeConnect, ConnectAccepted, ConnectDetachBinding,
    ConnectDisconnected, ConnectGrant, ConnectIdentity, ConnectPactReceipt, ConnectPactRequest,
    ConnectRescoped, MintConnectGrant, NarrowConnect, Offer, OfferConnect, RescopeConnect,
    RescopeOffer,
};

pub use crate::connect_delivery::{
    ConnectDelivery, ConnectExportRequest, ConnectRejoinStatus, ConnectRejoined,
};

pub use crate::authority::ConnectWindow;

/// Embedded vaults hold no host-root signer or served window manager.
pub fn connect_host_only<T, I>(memory: &Memory<'_>, verb: &str, _input: &I) -> MemoryResult<T> {
    let _owner = memory.embedded_owner(verb)?;
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{verb} requires the serving host's signer and federation transport"),
        &[super::host::SERVED_CLIENT_HINT],
    ))
}
