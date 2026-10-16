//! OF-232: the guest-revoke response and its copied-bytes disclosure.
//!
//! A revoke withdraws a guest's grant at this host and stops what that grant
//! would serve next. Bytes a guest already synced are the guest's copy: the
//! host can ask for their deletion, and it never claims recall. The
//! disclosure says so as typed machine state, so a host renders its own
//! wording through its own configuration; the engine carries no sentence and
//! no count of what a guest holds, because it cannot know one.
//!
//! [`project_guest_revoke`] turns what the withdrawing door did into the
//! response. The door reports each fact it made true; nothing here infers
//! one.

use serde::{Deserialize, Serialize};

use super::kernel::hex_lower;
use crate::authority::{FederationGrantActivation, FederationPactStatus};
use crate::entity_id::EntityId;

/// What one guest revoke did, as the withdrawing door reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestRevokeOutcome {
    /// The guest's FEDERATION_GRANT.
    pub grant_ref: EntityId,
    /// The guest actor the grant conferred on.
    pub guest_ref: EntityId,
    /// False when the grant was already withdrawn and this revoke changed
    /// nothing.
    pub changed: bool,
    /// The vault-clock instant of the withdrawal (Unix seconds).
    pub revoked_at: u64,
    /// Capability slips this revoke tombstoned, each one actually revoked.
    pub revoked_slips: Vec<[u8; 32]>,
    /// The grant's pact standing after the revoke, from the fold.
    pub pact: FederationGrantActivation,
    /// Whether the door asked the guest to delete its copy.
    pub deletion_request: GuestDeletionRequestStatus,
}

/// Whether a deletion request went to the guest. None of these states says
/// the guest deleted anything: a request is only a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestDeletionRequestStatus {
    /// No deletion request was made.
    NotRequested,
    /// A deletion request waits in this host's outbound queue.
    Queued,
    /// A deletion request left this host. Delivery and compliance are
    /// unknown.
    Sent,
}

/// What this host knows of the guest's copy: nothing it can attest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestCopyState {
    /// No receipt here proves what the guest kept or dropped.
    #[default]
    Unknown,
}

/// Bytes a guest already synced cannot be recalled. Serializes as `false`,
/// and reads back only from `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NotRecallable;

impl Serialize for NotRecallable {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(false)
    }
}

impl<'de> Deserialize<'de> for NotRecallable {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if bool::deserialize(deserializer)? {
            return Err(serde::de::Error::custom(
                "copied bytes are never recallable",
            ));
        }
        Ok(Self)
    }
}

/// The copied-bytes disclosure every guest revoke carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRevokeDisclosure {
    /// Always `false`: a synced copy is the guest's copy.
    pub copied_bytes_recallable: NotRecallable,
    /// Always `unknown`: the host attests nothing about the guest's copy.
    pub recipient_copy_state: GuestCopyState,
    pub deletion_request_status: GuestDeletionRequestStatus,
}

impl GuestRevokeDisclosure {
    /// The disclosure for a revoke whose deletion request stands at `status`.
    #[must_use]
    pub const fn new(status: GuestDeletionRequestStatus) -> Self {
        Self {
            copied_bytes_recallable: NotRecallable,
            recipient_copy_state: GuestCopyState::Unknown,
            deletion_request_status: status,
        }
    }
}

/// The grant's pact standing after the revoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestPactStanding {
    /// The grant was never bound to a pact.
    Unpacted,
    Active,
    Suspended,
    Promoted,
    Disconnected,
    Dissolved,
}

impl From<FederationGrantActivation> for GuestPactStanding {
    fn from(activation: FederationGrantActivation) -> Self {
        match activation {
            FederationGrantActivation::Unpacted => Self::Unpacted,
            FederationGrantActivation::Active
            | FederationGrantActivation::Inactive(FederationPactStatus::Active) => Self::Active,
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended) => Self::Suspended,
            FederationGrantActivation::Inactive(FederationPactStatus::Promoted) => Self::Promoted,
            FederationGrantActivation::Inactive(FederationPactStatus::Disconnected) => {
                Self::Disconnected
            }
            FederationGrantActivation::Inactive(FederationPactStatus::Dissolved) => Self::Dissolved,
        }
    }
}

/// A guest revoke's response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRevokeResponse {
    pub grant_ref: EntityId,
    pub guest_ref: EntityId,
    /// False when the grant was already withdrawn and this revoke changed
    /// nothing.
    pub changed: bool,
    /// Unix seconds, on the vault clock.
    pub revoked_at: u64,
    /// The capability slips this revoke tombstoned (hex).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_slip_refs: Vec<String>,
    pub pact_standing: GuestPactStanding,
    pub disclosure: GuestRevokeDisclosure,
}

/// The response for what a guest revoke did.
#[must_use]
pub fn project_guest_revoke(outcome: GuestRevokeOutcome) -> GuestRevokeResponse {
    GuestRevokeResponse {
        grant_ref: outcome.grant_ref,
        guest_ref: outcome.guest_ref,
        changed: outcome.changed,
        revoked_at: outcome.revoked_at,
        revoked_slip_refs: outcome
            .revoked_slips
            .iter()
            .map(|slip| hex_lower(slip))
            .collect(),
        pact_standing: outcome.pact.into(),
        disclosure: GuestRevokeDisclosure::new(outcome.deletion_request),
    }
}
