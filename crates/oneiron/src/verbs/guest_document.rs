//! Typed guest document sharing over live Connect grants (ARCH-0043).
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::federation::{FederationDirectionScope, GuestShareEnvelope, Scope, SelectorRange};
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};

/// One named, locally authored world under the recipient's existing guest grant.
/// Empty requested axes leave the grant ceiling in force; they never widen it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestDocumentShareRequest {
    pub grant_ref: EntityId,
    pub world_ref: EntityId,
    pub window_key: String,
    #[serde(default)]
    pub facets: Vec<EntityId>,
    #[serde(default)]
    pub bands: Vec<SelectorRange>,
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

/// The actual recipient update, not a summary or a server-generated expected view.
/// `envelope.signature` signs its canonical body, as the engine envelope codec
/// specifies. `signature` also binds the context and canonical signed envelope
/// in a domain-separated MessagePack tuple. `signer` is the host's Ed25519
/// public key in hex. No member roster or originating topology is included.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestDocumentEnvelope {
    pub context: GuestDocumentContext,
    pub envelope: GuestShareEnvelope,
    pub signer: String,
    pub signature: Vec<u8>,
}

impl GuestDocumentContext {
    pub(crate) fn transcript(&self, envelope: &[u8]) -> crate::Result<Vec<u8>> {
        rmp_serde::to_vec_named(&("oneiron/guest-document/v1", self, envelope))
            .map_err(|_| crate::Error::InvalidConfig("guest document encoding failed".into()))
    }
}

/// An embedded handle has no serving host's signing key or window manager.
pub fn guest_document_host_only<T, I>(
    _memory: &Memory<'_>,
    verb: &str,
    _input: &I,
) -> MemoryResult<T> {
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{verb} requires the serving host's guest document signer"),
        &[super::sdk_host::SERVED_CLIENT_HINT],
    ))
}
