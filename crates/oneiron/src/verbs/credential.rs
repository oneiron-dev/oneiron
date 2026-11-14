//! Holder-owned attenuation of the credential a transport admitted.
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::credential::{
    CredentialAttenuated, CredentialAttenuationRequest, CredentialCaveat, CredentialPactCeiling,
};
