//! Where a declared skill comes from, as a seed writes it (ARCH-0053). A row
//! names a hub source, never package bytes. Apply imports it through the
//! owner's hub doors, where it lands a candidate behind its own permission
//! ask, so declaring a skill activates nothing.
use super::invalid;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::skill::SkillLifecycle;
use crate::skill_hub::pack_catalog::hub_pin;
use crate::{EntityId, TimeRange, Vault};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A skill's hub source as plain fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum ShapeSkillSource {
    /// The shipped library, by subtree, at the released commit.
    Library { subtree: String },
    /// A configured hub (entity id hex): the skill's folder there, a pin,
    /// and the publisher to admit for it.
    Hub {
        hub: String,
        folder: String,
        /// `semver`, `tag`, `commit` or `content_hash`.
        pin_type: String,
        pin_value: String,
        publisher: String,
    },
}

impl ShapeSkillSource {
    /// The door an import from this source lands through.
    pub(super) const fn door(&self) -> &'static str {
        match self {
            Self::Library { .. } => "import_default_hub_skill",
            Self::Hub { .. } => "import_skill_from_hub_ref",
        }
    }
}

impl Vault {
    /// Imports the skill `source` carries, as `owner`, and checks it is the
    /// skill the row declares. A source carrying another skill or version
    /// refuses the item; what it imported stays a candidate, and plans as
    /// undeclared.
    pub(super) fn import_shape_skill(
        &self,
        owner: &AuthenticatedOwner,
        skill_id: &str,
        version: Option<&str>,
        source: &ShapeSkillSource,
        now: u64,
    ) -> Result<String> {
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        owner.revalidate(self)?;
        let entity = match source {
            ShapeSkillSource::Library { subtree } => {
                self.import_default_hub_skill(subtree, occurred, now)?
            }
            ShapeSkillSource::Hub {
                hub,
                folder,
                pin_type,
                pin_value,
                publisher,
            } => self.import_skill_from_hub_ref(
                owner,
                EntityId::from_hex(hub).map_err(|_| invalid("a hub is named by entity id hex"))?,
                folder,
                hub_pin(pin_type, pin_value)?,
                publisher,
            )?,
        };
        let record = self
            .get_skill_record(&entity)?
            .ok_or_else(|| invalid("the import left no skill record"))?;
        if record.skill_id != skill_id || version.is_some_and(|version| version != record.version) {
            return Err(invalid(format!(
                "the source carries {} version {}, not the row's skill; it stays a candidate",
                record.skill_id, record.version
            )));
        }
        // An import never overrides the vault's own decision on a skill.
        if matches!(
            record.lifecycle_status,
            SkillLifecycle::Superseded | SkillLifecycle::Quarantined
        ) {
            return Err(invalid(
                "the vault holds this skill retired; the import does not revive it",
            ));
        }
        Ok(entity.to_hex())
    }
}
