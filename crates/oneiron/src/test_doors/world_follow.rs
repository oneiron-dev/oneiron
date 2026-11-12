//! The thin index's window choice on a device lane, for the integration
//! test of a device following its worlds (census L7-42, ARCH-0023b
//! #partial-sync).

use crate::sync::SyncClient;
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;

/// The windows the thin index of `client` enrols at `now_secs` for its
/// current `current_window_count` months: the residence index fetch's own
/// choice, without its socket.
///
/// # Errors
///
/// The client's: an unreadable vault or authority fold.
pub fn thin_index_windows(
    client: &SyncClient,
    now_secs: u64,
    current_window_count: usize,
) -> Result<Vec<WindowKey>, TransportError> {
    client.thin_index_windows(now_secs, current_window_count)
}
