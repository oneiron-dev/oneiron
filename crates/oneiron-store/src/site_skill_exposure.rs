//! Site-skill exposures (FIX 11436): the site knowledge a run's browser was shown.
//!
//! Site knowledge delivered on an observation is not a `TaskExposure` byte
//! span, so a contribution check that finds no span for its target reads
//! here instead. One row per skill per observation; a run's rows for one
//! skill share a key prefix. Skill attribution (`skill_attribution`) records
//! and reads them through its re-exports; the row's side-table declaration
//! names its erase hook.

use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// `(run, skill, rest)`: the run that was shown the knowledge, the skill it
/// came from, and `be64(seq)` plus the first 8 bytes of `blake3(scope)`.
pub type SiteExposureKey = ([u8; 16], [u8; 16], Vec<u8>);

/// One skill's site knowledge a run's browser was shown on observation
/// `seq` of `scope`; it has no byte span in the run's task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteSkillExposure {
    pub run: EntityId,
    pub scope: String,
    pub seq: u64,
    pub skill: EntityId,
    pub revision: String,
    pub content_hash: [u8; 32],
    pub at: u64,
}

impl SiteSkillExposure {
    /// The exposure of `knowledge` shown to `run` on observation `seq` of
    /// `scope`; `None` when `skill_id` names no skill id.
    #[must_use]
    pub fn delivered(
        run: EntityId,
        scope: &str,
        seq: u64,
        skill_id: &str,
        revision: &str,
        knowledge: &str,
        at: u64,
    ) -> Option<Self> {
        let skill = EntityId::from_hex(skill_id).ok()?;
        Some(Self {
            run,
            scope: scope.to_owned(),
            seq,
            skill,
            revision: revision.to_owned(),
            content_hash: *blake3::hash(knowledge.as_bytes()).as_bytes(),
            at,
        })
    }

    pub fn key(&self) -> SiteExposureKey {
        let mut rest = self.seq.to_be_bytes().to_vec();
        rest.extend_from_slice(&blake3::hash(self.scope.as_bytes()).as_bytes()[..8]);
        (*self.run.as_bytes(), *self.skill.as_bytes(), rest)
    }
}
