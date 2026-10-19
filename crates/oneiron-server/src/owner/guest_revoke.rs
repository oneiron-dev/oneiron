//! The courtesy deletes a guest revoke queues (OF-232, FIX 1634). A revoke
//! that names the former peer's host origin (`peer`) asks that host, once
//! per courtesy target, to drop what the ended pact delivered: the same
//! signed ask `vault.courtesy_delete.send` queues, signed by this host, over
//! every world the pact delivered, up to the epoch the pact ended at.
//!
//! The owner route and the host door both call it after the revoke's
//! grouped writer returned, so the withdrawal is durable before any ask is
//! staged, and inside each one's own hook boundary. Queuing writes the
//! outbox and waits on no network: the courier delivers. A target whose ask
//! does not queue keeps `not_requested` with its error, and the committed
//! revoke still answers. A malformed `peer` refuses the whole revoke before
//! its writer runs ([`check_peer`], FIX 4186).

use oneiron::consent::AuthenticatedOwner;
use oneiron::receipt::{GuestDeletionRequestStatus, GuestRevokeResponse};
use oneiron::task_verb::sdk::CourtesyDeleteSendRequest;

use super::{OwnerResult, cooperative_deletion};
use crate::server::SyncServer;

/// Refuses a `peer` the courtesy ask would refuse, before the revoke
/// commits (FIX 4186). Both the owner route and the host door run it on
/// the hook-rewritten input, so a malformed origin is a bad request with
/// nothing written, even for a revoke that ends no pact. No `peer` passes.
pub(crate) fn check_peer(peer: Option<&str>) -> OwnerResult<()> {
    peer.map_or(Ok(()), cooperative_deletion::check_peer)
}

/// Queues one courtesy-delete ask to `peer` per courtesy target `revoked`
/// names, and records each outcome on its target. With no `peer` it sends
/// nothing. The disclosure says `queued` when at least one ask queued.
pub(crate) fn queue_courtesy_deletes(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    peer: Option<&str>,
    revoked: &mut GuestRevokeResponse,
) {
    let Some(peer) = peer else {
        return;
    };
    for target in &mut revoked.courtesy_targets {
        let ask = CourtesyDeleteSendRequest {
            pact: target.pact.clone(),
            worlds: Vec::new(),
            epoch_cutoff: Some(target.epoch_cutoff),
            peer: peer.to_owned(),
            signed: None,
        };
        match cooperative_deletion::send(server, owner, &ask) {
            Ok(sent) => {
                target.deletion_request_status = GuestDeletionRequestStatus::Queued;
                target.request = Some(sent.request);
            }
            Err(error) => target.error = Some(error.to_string()),
        }
    }
    if revoked
        .courtesy_targets
        .iter()
        .any(|target| target.deletion_request_status == GuestDeletionRequestStatus::Queued)
    {
        revoked.disclosure.deletion_request_status = GuestDeletionRequestStatus::Queued;
    }
}
