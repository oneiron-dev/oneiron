//! Site skills for the run's browser (CUA E10): the loadable skills whose
//! `site.json` origin matches a page exactly, and the seed programs their
//! folders hold. L10's seam: these bodies answer "not available yet" (an
//! empty list, an unresolved seed) until the skill hub's site import fills
//! them; the signatures stand.
use oneiron_browser::site::{SeedBody, SiteSkillMatch, SiteSkillQuery};

use crate::attempt_queue::AttemptRecord;
use crate::{Result, Vault};

impl Vault {
    /// Loadable (Active + Auto/Approved, lease-readable) skills whose
    /// site.json origin matches exactly. A URL match never activates a
    /// Candidate.
    pub fn site_skills_for(
        &self,
        _leased: &AttemptRecord,
        _executor: &str,
        _query: &SiteSkillQuery,
        _at: u64,
    ) -> Result<Vec<SiteSkillMatch>> {
        Ok(Vec::new())
    }

    /// Exact seed bytes and provenance from import metadata for a candidate
    /// handle that site_skills_for returned.
    pub fn resolve_seed(
        &self,
        _leased: &AttemptRecord,
        _candidate: &str,
        _at: u64,
    ) -> Result<SeedBody> {
        Err(crate::Error::EntityNotFound)
    }
}
