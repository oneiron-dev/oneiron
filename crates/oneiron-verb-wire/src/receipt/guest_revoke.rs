//! Moved from `crates/oneiron/src/receipt/guest_revoke.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::FederationGrantActivation;
use oneiron_authority::authority::FederationPactStatus;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A courtesy target as the response names it, in the courtesy-delete send
/// request's own field names, with what became of its ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestRevokeCourtesyTargetView {
    /// The ended pact (hex).
    pub pact: String,
    /// The peer vault the pact ran with (hex).
    pub peer_vault_id: String,
    pub epoch_cutoff: u64,
    /// `queued` once this target's ask waits in the outbox; `not_requested`
    /// when the revoke named no peer origin or the ask did not queue.
    pub deletion_request_status: GuestDeletionRequestStatus,
    /// The queued ask's request id (32 hex), as
    /// `vault.courtesy_delete.sent` lists it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    /// Why this target's ask did not queue. The revoke stands regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Whether a deletion request went to the guest. None of these states says
/// the guest deleted anything: a request is only a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
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

/// Its schema is its wire form: always `false`.
impl schemars::JsonSchema for NotRecallable {
    fn schema_name() -> String {
        "NotRecallable".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <bool as schemars::JsonSchema>::json_schema(generator)
    }
}

/// The copied-bytes disclosure every guest revoke carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The ended pacts the owner may send a courtesy delete for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub courtesy_targets: Vec<GuestRevokeCourtesyTargetView>,
    /// Why no courtesy-delete ask went to the named peer at all, when the
    /// server skipped them after the revoke committed: a hook-rewritten
    /// `peer` that fails the origin check (FIX 4186). The revoke stands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub courtesy_skipped: Option<String>,
}
