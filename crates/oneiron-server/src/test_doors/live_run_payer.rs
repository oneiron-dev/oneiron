//! Doors for `tests/live_run_payer_erased.rs` ([LIVE-RUN-PAYER-REQUIRED],
//! [LIVE-RUN-BROWSER-FILL-PAYER-FALLBACK]): the payer a live run's meter
//! bills, read as each of that run's model doors reads it, and the payer its
//! browser door's Fill writer bills.

use oneiron::agent_dispatch::SpendScopeId;
use oneiron::attempt_queue::AttemptRecord;
use oneiron::{EntityId, Vault};

use crate::ai_host::payer_funding::LiveRunPayer;
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

/// What the browser door of the live run whose leased try is `leased`,
/// spending under `scope`, keeps for its Fill writer's payer: made once per
/// lease, as `ResolvedLiveRun::browser_guests` makes it, and asked at each
/// writer call.
pub struct FillWriterPayer(LiveRunPayer);

impl FillWriterPayer {
    /// The door's payer source for the run, as its first browser call makes it.
    pub fn of_run(leased: &AttemptRecord, scope: &SpendScopeId) -> Self {
        Self(LiveRunPayer::new(leased.clone(), Some(scope.clone())))
    }

    /// The PERSON whose account the run's next Fill writer call bills (the
    /// line each browser call's `RunFieldWriter` opens on code mode's meter):
    /// `Ok(None)` keeps the vault owner's default.
    ///
    /// # Errors
    ///
    /// The writer's refusal words: a payer fault starts with its reason code
    /// (`payer_missing`, `payer_needed`, `grant_wallet_unbound`).
    pub fn next_call(&self, vault: &Vault) -> Result<Option<EntityId>, String> {
        self.0
            .funding(vault)
            .map(|payer| payer.map(|payer| payer.person))
            .map_err(|fault| fault.to_string())
    }
}
