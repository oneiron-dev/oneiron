//! A verified read proof kept in engine-owned state (FIX 1667): the effective
//! view the verifier produced for a presented credential, so work that
//! outlives its request reads under that same proof, never under the
//! actor's wider grants.
//!
//! It is captured only from a [`VerifiedSlip`] and restored only as one. It
//! holds no signature, holder key or token, so it proves nothing on its own
//! and is never a wire input: every read under the restored view still
//! checks the slip's liveness and the holder's binding in its own snapshot.

use serde::{Deserialize, Serialize};

use super::{SlipClaims, VerifiedSlip};

/// The four facts of a [`VerifiedSlip`]: its effective claims (every caveat
/// met, the current scope included), its pact bound, and the verifier's two
/// flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredReadProof {
    claims: SlipClaims,
    #[serde(
        serialize_with = "super::serialize_pact",
        deserialize_with = "super::deserialize_pact"
    )]
    pact: Option<(crate::EntityId, crate::federation::FederationDirectionScope)>,
    unattenuated: bool,
    transferred: bool,
}

impl StoredReadProof {
    /// The stored form of `proof`, exactly as verified.
    pub(crate) fn of(proof: &VerifiedSlip) -> Self {
        Self {
            claims: proof.claims.clone(),
            pact: proof.pact.clone(),
            unattenuated: proof.unattenuated,
            transferred: proof.transferred,
        }
    }

    /// The verified view this was stored from, fact for fact.
    pub(crate) fn restore(&self) -> VerifiedSlip {
        VerifiedSlip {
            claims: self.claims.clone(),
            pact: self.pact.clone(),
            unattenuated: self.unattenuated,
            transferred: self.transferred,
        }
    }
}
