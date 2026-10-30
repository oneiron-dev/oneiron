//! A run's site skills (CUA E10): the host's [`SiteSkillLoader`] on the
//! run's browser and on its proposals' fresh guests. A load reads the
//! skills the vault's skill hub matches to the page's exact site
//! (`Vault::site_skills_for`), and a candidate resolves to its seed's exact
//! bytes (`Vault::resolve_seed`), both under the run's skill-load lease:
//! the exact leased try and executor its runner registered, checked current
//! at each load. An admission job loads under its own leased try (CUA E8b).
//!
//! A run with no such lease loads nothing (CALL 8): its open goes on with
//! a note naming why, and a candidate it names does not resolve. The
//! browser itself stays the run's as before.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::attempt_queue::AttemptRecord;
use oneiron_browser::site::{
    SeedBody, SiteSkillError, SiteSkillErrorCode, SiteSkillLoader, SiteSkillMatch, SiteSkillQuery,
};

use crate::server::{LiveRuns, SyncServer};

/// The note an open carries, and the error a candidate answers, on a run
/// with no skill-load lease.
const NO_SKILL_LEASE: &str = "no skill-load lease for this run";

/// One run's site skills.
pub(super) struct RunSiteSkills {
    vault: Arc<oneiron::Vault>,
    live_runs: Arc<LiveRuns>,
    run_id: EntityId,
    /// The admission job's own leased try (CUA E8b); none takes the live
    /// run the server registered under `run_id`.
    job: Option<AttemptRecord>,
}

impl RunSiteSkills {
    /// The site skills of run `run_id`, under `job`'s leased try for an
    /// admission job, else its registered live run's.
    pub(super) fn new(server: &SyncServer, run_id: EntityId, job: Option<&AttemptRecord>) -> Self {
        Self {
            vault: Arc::clone(&server.vault),
            live_runs: Arc::clone(&server.live_runs),
            run_id,
            job: job.cloned(),
        }
    }

    /// The skill-load lease (CALL 8): the exact registered try and its
    /// executor, never one built from an attempt id. A job's try that names
    /// no executor holds none.
    fn lease(&self) -> Result<(AttemptRecord, String), SiteSkillError> {
        let lease = match &self.job {
            Some(leased) => Ok(leased
                .executor_model
                .clone()
                .map(|executor| (leased.clone(), executor))),
            None => self.live_runs.skill_lease(&self.vault, self.run_id),
        };
        match lease {
            Ok(Some(lease)) => Ok(lease),
            Ok(None) => Err(SiteSkillError::new(
                SiteSkillErrorCode::NoLease,
                NO_SKILL_LEASE,
            )),
            Err(error) => Err(read_failed(&error)),
        }
    }
}

impl SiteSkillLoader for RunSiteSkills {
    fn site_skills(&self, query: &SiteSkillQuery) -> Result<Vec<SiteSkillMatch>, SiteSkillError> {
        let (leased, executor) = self.lease()?;
        let at = self.vault.now_recorded_at();
        self.vault
            .site_skills_for(&leased, &executor, query, at)
            .map_err(|error| read_failed(&error))
    }

    fn seed(&self, candidate: &str) -> Result<SeedBody, SiteSkillError> {
        let (leased, _) = self.lease()?;
        let at = self.vault.now_recorded_at();
        self.vault
            .resolve_seed(&leased, candidate, at)
            .map_err(|error| match error {
                oneiron::Error::EntityNotFound => SiteSkillError::new(
                    SiteSkillErrorCode::Unresolved,
                    format!("the skill hub resolves no seed for candidate {candidate}"),
                ),
                oneiron::Error::Artifact(oneiron::error::ArtifactError::InvalidSkillBody(
                    detail,
                )) if detail == oneiron::skill_hub::SITE_SEED_DIGEST_MISMATCH => {
                    SiteSkillError::new(SiteSkillErrorCode::DigestMismatch, detail)
                }
                error => read_failed(&error),
            })
    }

    fn note_delivered(&self, seq: u64, scope: &str, matches: &[SiteSkillMatch]) {
        if matches.is_empty() {
            return;
        }
        let at = self.vault.now_recorded_at();
        let rows: Vec<_> = matches
            .iter()
            .filter_map(|found| {
                oneiron::skill_attribution::SiteSkillExposure::delivered(
                    self.run_id,
                    scope,
                    seq,
                    &found.skill_id,
                    &found.revision,
                    &found.knowledge,
                    at,
                )
            })
            .collect();
        if rows.is_empty() {
            return;
        }
        if let Err(error) = oneiron::skill_attribution::record_site_exposures(&self.vault, &rows) {
            tracing::warn!(
                kind = ?error.kind(),
                %error,
                "a run's site-skill exposure was not recorded"
            );
        }
    }
}

/// A skill-hub read that failed, in the engine's words.
fn read_failed(error: &oneiron::Error) -> SiteSkillError {
    SiteSkillError::new(SiteSkillErrorCode::Loader, error.to_string())
}
