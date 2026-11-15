//! Door for `tests/booking_feed_move_held.rs`: an emergency's apology goes
//! out on `email`, a channel a built-in pack serves, and a seeded vault
//! refuses a send on such a channel until that pack is installed Active with
//! its connection checked (OF-519). That test covers a feed's hold on a
//! fenced booking, not the pack, so its vault drops the seed marker.

use crate::Vault;
use crate::error::Result;

/// Removes `vault`'s first-open built-in pack seed marker: the built-in
/// channel check then passes every channel, as on an unseeded vault, while
/// every other seeded row stays.
///
/// # Errors
///
/// The write's failure.
pub fn remove_builtin_pack_seed_marker(vault: &Vault) -> Result<()> {
    vault.remove_builtin_pack_seed_marker_for_test()
}
