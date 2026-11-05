//! FIX 4325: the trusted-contact binding a contact-bound slip carries, signed in
//! its claims beside `grant_ref` and `invitation_ref`.
//!
//! A known live native PERSON without an app account receives a holder-bound
//! slip limited to one existing trusted-contact naming (person/contact/version).
//! The binding names the namer (`person`) and the exact relation version; the
//! claims' `holder_ref` names the contact. No new transport, identity or crypto:
//! the contact proves with the existing holder proof.

use oneiron_contracts::error::Result;
use serde::{Deserialize, Serialize};

use super::invalid_authority;

/// The signed binding of one trusted-contact slip (FIX 4325): the namer and
/// the exact relation version the contact may inspect, consent to or revoke.
/// The holder (contact) is the claims' `holder_ref`; the vault and lifetime
/// are the claims' own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedContactSlipBinding {
    /// The namer PERSON.
    pub person: crate::EntityId,
    /// The exact relation version bound; naming again supersedes it.
    pub version: u64,
}

impl TrustedContactSlipBinding {
    /// The binding's own shape: a non-zero version. The holder, the
    /// person-holder difference and the claim's kind checks are the mint's
    /// own validation ([`super::SlipClaims::validate`]).
    pub fn validate(&self) -> Result<()> {
        if self.version == 0 {
            return Err(invalid_authority());
        }
        Ok(())
    }
}
