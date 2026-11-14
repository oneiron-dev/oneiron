//! Moved from `crates/oneiron/src/authority/slip_pairing/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use serde::Deserialize;
use serde::Serialize;

/// Pairing descriptor is public liveness, not a credential or authority claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingDescriptor {
    pub protocol: String,
    pub slip_version: u8,
    pub binding: String,
    pub pairing_endpoint: String,
}

impl Default for PairingDescriptor {
    fn default() -> Self {
        Self {
            protocol: "oneiron-pairing".into(),
            slip_version: 2,
            binding: "ed25519".into(),
            pairing_endpoint: "/v1/core/pairing/redeem".into(),
        }
    }
}

/// Owner-approved identity constraints. Redemption can choose a connection key,
/// but cannot replace these claims or add organization authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingPrincipal {
    pub holder_ref: Option<String>,
    pub actor_class: Option<String>,
    pub org_ref: Option<String>,
    /// The facet (hex id) the credential's writes are born in, when its
    /// scope reads several: one of them. With none named, the smallest. The
    /// slip does not carry it; redemption keeps it beside the slip's id
    /// ([`Vault::paired_write_facet`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_facet: Option<String>,
    /// Whom the paired slip may message (FIX 3899): the owner sets it when
    /// he makes the link, and redemption copies it into the slip's signed
    /// claims; the redeemer never picks it. `None` is the vault-wide reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<super::CommReach>,
}
