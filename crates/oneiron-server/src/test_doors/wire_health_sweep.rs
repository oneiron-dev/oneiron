//! Door for `tests/own_rate_health_ask.rs`: one pass of the health check's
//! worker (`wire_health::sweep`), run now instead of on its 15 s tick, and the
//! two halves of a pass apart, so an erase can land between a pass's read of
//! a held check and its ask.

use oneiron::Error;

use crate::server::SyncServer;
use crate::wire_health::HealthCheck;

/// Folds every new crossing in, asks each held check on the host's ladder
/// and looks for role holders' answers, once.
///
/// # Errors
///
/// What the pass returns.
pub fn sweep_once(server: &SyncServer) -> oneiron::Result<()> {
    crate::wire_health::sweep(server)
}

/// Folds every new crossing into its check and asks nothing: a pass stopped
/// between its fold and its asks.
///
/// # Errors
///
/// What the fold returns.
pub fn fold_once(server: &SyncServer) -> oneiron::Result<()> {
    crate::wire_health::fold_unread(server)
}

/// Asks `check` on the host's ladder as a pass that read it held asks it,
/// whether or not its row is still kept.
///
/// # Errors
///
/// No owner principal, or what the ask returns.
pub fn ask_read_check(server: &SyncServer, check: HealthCheck) -> oneiron::Result<()> {
    let owner = server
        .vault()
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(format!("no owner principal: {error}")))?;
    crate::wire_health::ask(server, owner, check)
}
