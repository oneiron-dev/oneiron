//! Retained pack-manifest entries for queued work.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::store::revision_ref::RevisionRef;

/// What one [`ManifestEntry`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ManifestKind {
    /// The tier-1 skill dependency index included in the dispatched composition.
    SkillIndex,
    /// A SKILL pulled into the attempt's pack (`skill_id` + version).
    Skill,
    /// An `actor.*` claim row loaded into the attempt's pack.
    ActorClaim,
}

impl ManifestKind {
    /// Returns the stable wire string for this manifest kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkillIndex => "skill_index",
            Self::Skill => "skill",
            Self::ActorClaim => "actor_claim",
        }
    }
}

/// One append-only row of an attempt's PACK MANIFEST (ARCH-0053 §2/§3).
///
/// The pack is alive: the tier-1 index is stamped at `t0` and every mid-run
/// tier-2 body pull appends its own row WHEN it happens, so the terminal
/// receipt carries the full accumulated manifest and attribution can name
/// what was actually loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ManifestEntry {
    pub kind: ManifestKind,
    /// The loaded thing's stable identity (`skill_id`, claim id hex, …).
    pub reference: String,
    /// The loaded revision (`SkillRecord::version`, a claim revision, …).
    pub version: String,
    /// Unix seconds at which the pack loaded it.
    pub at: u64,
    /// For a skill load, the entity whose body loaded and its exact retained
    /// revision, so attribution reads what loaded after an in-place update
    /// (FIX 10110); `None` for every other row.
    pub revision: Option<(EntityId, RevisionRef)>,
}

impl ManifestEntry {
    /// Builds one manifest row.
    #[must_use]
    pub fn new(
        kind: ManifestKind,
        reference: impl Into<String>,
        version: impl Into<String>,
        at: u64,
    ) -> Self {
        Self {
            kind,
            reference: reference.into(),
            version: version.into(),
            at,
            revision: None,
        }
    }

    /// This row bound to the exact revision of `entity` the load read.
    #[must_use]
    pub fn with_revision(mut self, entity: EntityId, revision: RevisionRef) -> Self {
        self.revision = Some((entity, revision));
        self
    }

    /// The `reference@version` wire form the terminal receipt projects.
    #[must_use]
    pub fn wire_form(&self) -> String {
        format!("{}@{}", self.reference, self.version)
    }

    /// Splits a [`Self::wire_form`] string back into `(reference, version)`.
    ///
    /// The delimiter is the FIRST `@` (owner ruling R-20260807-04). The
    /// grammar is asymmetric on purpose: a reference may not contain `@` —
    /// `validate::validate_manifest_entry` refuses one at the door — while a
    /// VERSION may, so `s@1@beta` is the skill `s` at revision
    /// `1@beta`. Splitting from the right instead read that row as skill `s@1`
    /// at revision `beta`, attributing an outcome to a skill that never
    /// existed.
    ///
    /// Returns `None` for a string carrying no `@` at all, which is not a
    /// wire form.
    #[must_use]
    pub fn parse_wire_form(wire_form: &str) -> Option<(&str, &str)> {
        wire_form.split_once('@')
    }
}
