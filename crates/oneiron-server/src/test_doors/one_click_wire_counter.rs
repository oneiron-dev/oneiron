//! Door for `tests/campaign_one_click_unsubscribe.rs`: runs a closure while
//! the wire window's counter lock is held, as a window rollover's persist
//! holds it, so the test can show that a call waits for that lock on the
//! blocking pool, never on a runtime worker (FIX
//! [WIRE-TELEMETRY-SYNC-PERSIST-ON-ASYNC-PATH]).

use crate::server::SyncServer;

/// Runs `held` while `server`'s wire counter lock is held, and returns what
/// it returns.
pub fn while_wire_counter_held<T>(server: &SyncServer, held: impl FnOnce() -> T) -> T {
    server.wire_telemetry.while_counter_held(held)
}
