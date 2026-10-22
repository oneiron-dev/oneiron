//! The owner's own named delete through `/v1/core/memory/verbs` (FIX
//! 1465). A delete by the proven owner of a record only secret orders keep
//! is accepted as "erase confirmed; completion pending", not refused: the
//! engine records it under its own reason and runs it once nothing holds
//! the record. Only an owner-grade credential's proof is asked for, after
//! the route's own host-act admission; every other caller the route admits
//! deletes on the raw rail as before, and no owner is made from a request's
//! asserted actor.

use oneiron::{DeleteReason, EntityId};

use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Whether the owner's delete of `id` under `reason` was accepted as
/// pending. False when the caller is not the proven owner, or the engine
/// did not accept it so: the raw rail then runs, and refuses as it does.
pub(super) fn owner_pending_delete(
    server: &SyncServer,
    auth: &CoreAuth,
    id: &EntityId,
    reason: DeleteReason,
) -> oneiron::Result<bool> {
    if !auth.is_owner_grade() {
        return Ok(false);
    }
    let Ok((owner, _actor)) = crate::api::owner_routes::hooked_owner(auth, server) else {
        return Ok(false);
    };
    server.vault.owner_pending_delete(&owner, id, reason)
}
