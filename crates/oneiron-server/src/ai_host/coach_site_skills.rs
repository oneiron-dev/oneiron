//! The Coach's site skills on the host (CUA E8b, FIX 7606): the engine's
//! fixed-code distill pass under the leased job, its counts logged. No
//! model, no browser and no admission here: a distilled skill lands as a
//! Candidate and waits on the ordinary skill gate like any other birth.
use oneiron::dreamer_runner::DreamerAdmittedAttempt;

use crate::server::SyncServer;

/// One site-skills pass.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let report = server.vault().run_coach_site_skills(admitted, now)?;
    for error in &report.errors {
        tracing::warn!(%error, "a site-skills write rolled back");
    }
    tracing::info!(
        sites = report.sites,
        created = report.skills_created,
        dup = report.skills_dup,
        findings = report.findings,
        diagnostics = report.diagnostics,
        withheld = report.withheld,
        "the Coach distilled site skills"
    );
    Ok(())
}
