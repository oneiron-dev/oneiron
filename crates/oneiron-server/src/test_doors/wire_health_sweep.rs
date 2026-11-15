//! Door for the health-check tests (`tests/own_rate_health_ask.rs`,
//! `tests/wire_health_actor_erase.rs`): one pass of the health check's
//! worker (`wire_health::sweep`), run now instead of on its 15 s tick, and the
//! two halves of a pass apart, so an erase can land between a pass's read of
//! a held check and its ask. The wire and spend crossings a pass folds are
//! kept through here too.

use oneiron::{EntityId, Error, Vault};

use crate::server::SyncServer;
use crate::wire_health::HealthCheck;
use crate::wire_telemetry::WireThresholds;

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

/// Raises one caller's `ai.verdict` spend check, held for the next sweep.
///
/// # Errors
///
/// What keeping the check returns.
pub fn raise_spend(
    vault: &Vault,
    caller: EntityId,
    spent_units: u64,
    threshold: u64,
    window_started_at: u64,
    raised_at: u64,
) -> oneiron::Result<()> {
    crate::wire_health::raise_verdict_spend(
        vault,
        caller,
        spent_units,
        threshold,
        window_started_at,
        raised_at,
    )
}

/// Sets the wire call-volume thresholds the telemetry counts against.
///
/// # Errors
///
/// An invalid policy, or what keeping it returns.
pub fn set_wire_thresholds(
    server: &SyncServer,
    thresholds: &WireThresholds,
) -> oneiron::Result<()> {
    server.wire_telemetry.set_thresholds(thresholds)
}

/// Counts `calls` calls of `verb` by `actor` at `now`, keeping a
/// call-volume question when one more actor or verb crosses its row.
///
/// # Errors
///
/// An overlong verb or actor, or what counting returns.
pub fn record_wire_calls(
    server: &SyncServer,
    verb: &str,
    actor: &str,
    calls: u64,
    now: u64,
) -> oneiron::Result<()> {
    for _ in 0..calls {
        server.wire_telemetry.record(verb, actor, now)?;
    }
    Ok(())
}
