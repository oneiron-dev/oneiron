//! The thin index's window choice and a negotiation's follow set on a device
//! lane, for the integration tests of a device following its worlds (census
//! L7-42, ARCH-0023b #partial-sync).

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

/// Begins a negotiation on `client`, as each socket's handshake does before
/// its first frame: the worlds it follows are read here.
pub fn begin_connection_sync(client: &mut SyncClient) {
    client.begin_connection_sync();
}

/// Whether the steady loop of `client`'s connection renegotiates now: the
/// worlds it follows differ from the ones its negotiation read as it began.
#[must_use]
pub fn follow_set_changed(client: &SyncClient) -> bool {
    client.follow_set_changed()
}

/// Whether `client` may exchange window `key` in full on its connection now:
/// the gate each full-window frame meets, in and out.
///
/// # Errors
///
/// The client's: an unreadable promotion marker.
pub fn full_window_exchange_allowed(
    client: &SyncClient,
    key: &WindowKey,
) -> Result<bool, TransportError> {
    client.full_window_exchange_allowed(key.as_str())
}
