//! Holder-owned attenuation of the credential a transport admitted.
use serde::{Deserialize, Serialize};

/// Append a holder-signed narrowing to this request's own slip. The seed is
/// the current holder's 32-byte Ed25519 seed, not a host signing secret.
/// Omitting `next_binding_key` keeps the current holder; a transfer names
/// the recipient's public key only. No actor, grant or logged mint changes.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialAttenuationRequest {
    pub holder_seed: [u8; 32],
    pub caveat: crate::authority::SlipCaveat,
    #[serde(default)]
    pub next_binding_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for CredentialAttenuationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialAttenuationRequest")
            .field("caveat", &self.caveat)
            .field("next_binding_key", &self.next_binding_key)
            .finish_non_exhaustive()
    }
}

/// A v2 slip for the retained holder key or the recipient's public key.
/// Its holder keeps their seed locally, beside this token, in the same
/// credential format pairing returns. This is not a newly minted grant.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialAttenuated {
    pub token: String,
    pub binding_key: [u8; 32],
}

impl std::fmt::Debug for CredentialAttenuated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialAttenuated")
            .field("binding_key", &self.binding_key)
            .finish_non_exhaustive()
    }
}
