//! A retired device's successor in a fold, for the integration tests of the
//! owner-proof rule (row CARRIER-OWNER-PROOF, the succession door): the
//! fold's device successions are crate-private.

use crate::EntityId;
use crate::authority::AuthorityFold;
use crate::error::Result;

/// The machine the fold counts as the successor of device key `device_key`
/// under client id `client`; `None` while no succession of the pair counts.
///
/// # Errors
/// A pair no succession target derives from.
pub fn successor(
    fold: &AuthorityFold,
    client: u64,
    device_key: &[u8; 32],
) -> Result<Option<EntityId>> {
    fold.device_successor(client, device_key)
}
