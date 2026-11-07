//! The unclear-note clustering on the host's ladder (ARCH-0056 §5 #unclear,
//! FIX 7824). The job puts each recurring `no_label_fits` note the attribution
//! judge left to the host's model rungs for the vault's owner, as one
//! same-pattern choice within its scope; the engine lands the answers and
//! files a Proposed label for a pattern that recurs. A choice no rung answers
//! (the rungs' budgets suspend them) parks the job until the next night.
use oneiron::EntityId;
use oneiron::dreamer_runner::DreamerAdmittedAttempt;

use crate::server::SyncServer;

/// Choices one job puts to the ladder; the rest wait for the next night.
const CHOICES_PER_JOB: usize = 32;

/// One clustering job.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let principal = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| oneiron::Error::InvalidConfig(format!("no owner principal: {error}")))?;
    let host = server.decision_host();
    let ladder = host.attribution_ladder();
    let decisions = host.unclear_pattern_decisions(&ladder, principal);
    let report = vault.run_coach_attribution_labels(admitted, &decisions, CHOICES_PER_JOB, now)?;
    tracing::debug!(
        ?report,
        run = %EntityId::from_bytes(*admitted.status.attempt.id.as_bytes())?.to_hex(),
        "the Coach clustered the unclear attribution notes"
    );
    Ok(())
}
