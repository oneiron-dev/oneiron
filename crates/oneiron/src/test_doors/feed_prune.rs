//! Door for `tests/restriction_wave_16_doors.rs`: the feeds' housekeeping prune, which is
//! otherwise crate-private.

use crate::Vault;
use crate::error::Result;

/// Runs the feeds' housekeeping prune, taking up to `max_rows` rows a feed.
///
/// # Errors
///
/// The read or the write.
pub fn prune_feeds(vault: &Vault, max_rows: usize) -> Result<()> {
    crate::feeds::prune_feeds(vault, max_rows)
}
