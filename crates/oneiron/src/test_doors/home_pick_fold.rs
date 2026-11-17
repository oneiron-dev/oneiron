//! The vault's home pick in a fold, for the integration tests of the
//! owner-proof rule (row CARRIER-OWNER-PROOF, test 3): the fold's picks are
//! crate-private.

use crate::authority::AuthorityFold;

/// The node the fold's last unconflicted home pick names; `None` while no
/// pick counts, or for a clear.
pub fn home_pick_in_force(fold: &AuthorityFold) -> Option<u64> {
    fold.home_pick
        .in_force
        .as_ref()
        .and_then(|head| head.choice)
}
