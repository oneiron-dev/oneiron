//! The attribution judge's held-out audits on the host's ladder (ARCH-0053,
//! OF-542). The job puts both built-in fixture sets to the host's model
//! rungs for the vault's owner, with a Coach note on each doubtful answer,
//! so the `attribution_unclear_floor` fitter reads model answers. The rule
//! tier answers the fixtures' settled facts at full confidence and would fit
//! nothing, so the audit's ladder starts on the model rungs.
use oneiron::EntityId;
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::skill_attribution::{ATTRIBUTION_CALL_PURPOSE_NAME, ATTRIBUTION_DIAL};

use super::super::code_fix::HostModels;
use super::super::skill_discovery::CoachNotes;
use crate::server::SyncServer;

/// What one job's note calls may spend.
const BUDGET_UNITS: u64 = 1 << 20;

/// One audit job: both fixture sets through the host's attribution ladder.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let run_id = format!(
        "coach-attribution-audits:{}",
        EntityId::from_bytes(*admitted.status.attempt.id.as_bytes())?.to_hex()
    );
    let models = HostModels::open(server, run_id, ATTRIBUTION_CALL_PURPOSE_NAME, BUDGET_UNITS)?;
    let principal = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| oneiron::Error::InvalidConfig(format!("no owner principal: {error}")))?;
    let host = server.decision_host();
    let ladder = host.attribution_ladder();
    let notes = CoachNotes { models: &models };
    let mut decisions = host.attribution_decisions(&ladder, principal, &notes);
    decisions.dial = ATTRIBUTION_DIAL;
    let audits = vault.run_coach_attribution_audits(admitted, &decisions, now)?;
    tracing::debug!(?audits, "the Coach ran the attribution judge's audits");
    Ok(())
}
