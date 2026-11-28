//! Moved from `crates/oneiron/src/authority/slip_pairing/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
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
    /// The agent seat the credential is for (FIX MARKET-SEAT-MODEL-STAMP):
    /// the owner declares its harness and model when the owner makes the
    /// link, and redemption keeps them beside the slip's id
    /// ([`PairedSeat`]); the redeemer never picks them. The slip does not
    /// carry them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat: Option<PairingSeat>,
}

/// An agent seat's harness and model, as the owner declares them on its
/// credential's pairing link. The engine records the declaration and never
/// observes the model behind an attached harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingSeat {
    /// The harness that drives the agent, e.g. `claude-code`: 1..=64 bytes
    /// of `[a-z0-9._-]`.
    pub harness: String,
    /// The model behind that harness: 1..=128 bytes of
    /// `[A-Za-z0-9._:/@+-]`.
    pub model: String,
}

/// A [`PairingSeat`] as the mint keeps it beside the slip's id: what the
/// owner declared, who declared it and when the slip was minted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedSeat {
    pub harness: String,
    pub model: String,
    /// The owner who made the link; none for a host-only link.
    pub owner: Option<EntityId>,
    pub at: u64,
}
