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
    pub caveat: CredentialCaveat,
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

/// Holder-authored restrictions. Scope is explicitly a ceiling on this door,
/// so a record position cannot be supplied in its place.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialCaveat {
    pub scope: Option<crate::memory::CredentialCeiling>,
    pub expires_at: Option<u64>,
    pub ttl_secs: Option<u64>,
    pub single_use: bool,
    pub records: Option<std::collections::BTreeSet<String>>,
    pub channels: Option<std::collections::BTreeSet<String>>,
    pub pact: Option<CredentialPactCeiling>,
}

/// A pact-bound attenuation, retaining the grant the credential already holds.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialPactCeiling {
    pub grant_ref: crate::federation::ScopeId,
    pub ceiling: crate::federation::FederationDirectionScope,
}

impl CredentialCaveat {
    /// Lifts the public role-tagged ceiling onto the existing slip primitive.
    /// That primitive verifies every narrowing, including the live pact.
    pub fn into_engine(self) -> crate::authority::SlipCaveat {
        crate::authority::SlipCaveat {
            scope: self
                .scope
                .map(|crate::memory::CredentialCeiling::Ceiling(scope)| scope),
            expires_at: self.expires_at,
            ttl_secs: self.ttl_secs,
            single_use: self.single_use,
            records: self.records,
            channels: self.channels,
            pact: self.pact.map(|pact| (pact.grant_ref.0, pact.ceiling)),
        }
    }
}
