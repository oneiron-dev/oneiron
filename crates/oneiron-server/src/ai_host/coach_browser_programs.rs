//! The Coach's browser programs on the host (CUA E8, FIX 7605): the
//! engine's fixed-code pass under the leased job, its counts logged. No
//! model, no browser and no admission here: an aligned candidate's job goes
//! to the admission worker, which the engine wakes once the job is queued.
use oneiron::dreamer_runner::DreamerAdmittedAttempt;

use crate::server::SyncServer;

/// One browser-programs pass.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let report = server.vault().run_coach_browser_programs(admitted, now)?;
    for error in &report.errors {
        tracing::warn!(%error, "a browser-programs write rolled back");
    }
    tracing::info!(
        groups = report.groups,
        cleaned = report.groups_cleaned,
        covered = report.groups_covered,
        withheld = report.withheld,
        evidence = report.evidence,
        failed_programs = report.failed_programs,
        candidates = report.candidates,
        findings = report.findings,
        diagnostics = report.diagnostics,
        already_seen = report.already_seen,
        jobs = report.jobs,
        repairs_pending = report.repairs_pending.len(),
        "the Coach proposed browser programs"
    );
    Ok(())
}
