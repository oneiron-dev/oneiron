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
//!
//! Each pact the grant governed and that now stands ended is a courtesy
//! target (FIX 1634): the typed handoff the courtesy-delete courier takes
//! (`POST /v1/owner/courtesy-delete/send`, with the peer host's origin, which
//! no grant or pact records). A revoke that names that origin has the
//! server queue each target's ask after the revoke is durable, and each
//! target says whether its ask was queued.

use serde::{Deserialize, Serialize};

use super::kernel::hex_lower;
use crate::entity_id::EntityId;
use oneiron_authority::authority::{FederationGrantActivation, FederationPactStatus};

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
    /// The ended pacts a courtesy delete may ask the guest's host about.
    pub courtesy_targets: Vec<GuestRevokeCourtesyTarget>,
}

/// One ended pact the revoked grant governed: what the courtesy-delete
/// courier asks a peer to drop, everything the pact delivered through
/// `epoch_cutoff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestRevokeCourtesyTarget {
    pub pact_id: [u8; 32],
    pub peer_vault_id: [u8; 32],
    /// The epoch the pact ended at.
    pub epoch_cutoff: u64,
}

#[doc(hidden)]
pub use oneiron_verb_wire::receipt::guest_revoke::{
    GuestCopyState, GuestDeletionRequestStatus, GuestPactStanding, GuestRevokeCourtesyTargetView,
    GuestRevokeDisclosure, GuestRevokeResponse, NotRecallable,
};

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
        courtesy_targets: outcome
            .courtesy_targets
            .iter()
            .map(|target| GuestRevokeCourtesyTargetView {
                pact: hex_lower(&target.pact_id),
                peer_vault_id: hex_lower(&target.peer_vault_id),
                epoch_cutoff: target.epoch_cutoff,
                deletion_request_status: GuestDeletionRequestStatus::NotRequested,
                request: None,
                error: None,
            })
            .collect(),
        courtesy_skipped: None,
    }
}
