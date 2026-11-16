//! Access requests put in bulk, for the pending-page measurement (FIX 14).

use crate::{EntityId, Result, Vault};

/// Puts `decided` requests denied by `answered_by`, then one pending request
/// per entry of `pending` asking that addressee (None: the owner alone), in
/// one write transaction; the pending requests' ids in key order.
pub fn seed_access_requests(
    vault: &Vault,
    answered_by: EntityId,
    decided: usize,
    pending: &[Option<EntityId>],
) -> Result<Vec<EntityId>> {
    crate::access_grant::seed_access_requests_for_test(vault, answered_by, decided, pending)
}
