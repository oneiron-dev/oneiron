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
//! revoke still answers.
//!
//! A guest revoke always commits (FIX 4186). A malformed `peer` the caller
//! typed is a bad request before anything runs on the owner route
//! ([`check_peer`]); a `peer` a verb hook rewrote is checked only here,
//! after the revoke, and one that fails the origin check skips the asks
//! alone: the answer and the owner's inbox say why
//! ([`COURTESY_PEER_INVALID`]).

use oneiron::consent::AuthenticatedOwner;
use oneiron::receipt::{GuestDeletionRequestStatus, GuestRevokeResponse};
use oneiron::task_verb::sdk::CourtesyDeleteSendRequest;

use super::{OwnerResult, cooperative_deletion};
use crate::server::SyncServer;

/// Why a committed revoke sent no courtesy-delete ask: its hook-rewritten
/// `peer` failed the origin check. The answer's targets and
/// `courtesy_skipped`, and the owner's inbox notice, carry it.
pub(crate) const COURTESY_PEER_INVALID: &str = "courtesy notice not sent: peer origin invalid";

/// Refuses a `peer` the caller typed that the courtesy ask would refuse,
/// before anything runs (FIX 4186): the owner route runs it on the request
/// as sent, never on a hook's rewrite, so a hook can never stop a revoke.
/// No `peer` passes.
pub(crate) fn check_peer(peer: Option<&str>) -> OwnerResult<()> {
    peer.map_or(Ok(()), cooperative_deletion::check_peer)
}

/// A committed revoke whose `peer` fails the origin check: every target
/// keeps `not_requested` with the reason, the answer says it, and the
/// owner's inbox is told.
fn skip_courtesy_deletes(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    revoked: &mut GuestRevokeResponse,
) {
    for target in &mut revoked.courtesy_targets {
        target.error = Some(COURTESY_PEER_INVALID.to_owned());
    }
    revoked.courtesy_skipped = Some(COURTESY_PEER_INVALID.to_owned());
    if let Err(error) = oneiron::task_verb::sdk::notify_guest_revoke_courtesy_skipped(
        server.vault(),
        owner,
        revoked,
        COURTESY_PEER_INVALID,
    ) {
        tracing::warn!(
            %error,
            "guest revoke: the owner notice of a skipped courtesy ask did not record"
        );
    }
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
    if cooperative_deletion::check_peer(peer).is_err() {
        skip_courtesy_deletes(server, owner, revoked);
        return;
    }
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
