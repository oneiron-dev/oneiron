//! Doors for `tests/live_run_payer_erased.rs` ([LIVE-RUN-PAYER-REQUIRED]):
//! the payer a live run's meter bills, read as each of that run's model
//! doors reads it.

use oneiron::agent_dispatch::SpendScopeId;
use oneiron::attempt_queue::AttemptRecord;
use oneiron::{EntityId, Vault};

use crate::mcp::ScopeMeter;

/// The PERSON whose account the meter bills that one entry of the live run
/// whose leased try is `leased` opens on `scope` (`ScopeMeter::open`, which
/// the run's entry, its repo model door and its pattern starts open):
/// `Ok(None)` keeps the vault owner's default.
///
/// # Errors
///
/// The open's refusal, in its own words: a payer fault starts with its
/// reason code (`payer_missing`, `payer_needed`, `grant_wallet_unbound`).
pub fn entry_meter_payer(
    vault: &Vault,
    leased: &AttemptRecord,
    scope: &SpendScopeId,
) -> Result<Option<EntityId>, String> {
    ScopeMeter::open(vault, leased, scope)
        .map(|meter| meter.payer.map(|payer| payer.person))
        .map_err(|error| error.to_string())
}
