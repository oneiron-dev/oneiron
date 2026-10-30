//! Where a declared skill comes from, as a seed writes it (ARCH-0053). A row
//! names a hub source, never package bytes. Apply imports it through the
//! owner's hub doors, where it lands a candidate behind its own permission
//! ask, so declaring a skill activates nothing.
use super::invalid;
use super::live::ShapeSources;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::skill::SkillLifecycle;
use crate::skill_hub::HubSyncDisposition;
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
    /// Imports the skill `source` carries, as `owner`, once it is the skill
    /// the row declares. The fetched package's id and the row's version are
    /// checked before any skill write (FIX 10202), and the import commits
    /// that same package: a source carrying another skill or version refuses
    /// the item and leaves skill state unchanged. `sources` lists the
    /// candidate as soon as it lands; an import refused before it lands one
    /// reads rows it does not name, so they are unknown.
    pub(super) fn import_shape_skill(
        &self,
        owner: &AuthenticatedOwner,
        skill_id: &str,
        version: Option<&str>,
        source: &ShapeSkillSource,
        now: u64,
        sources: &mut ShapeSources,
    ) -> Result<String> {
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        owner.revalidate(self)?;
        let imported = match source {
            ShapeSkillSource::Library { subtree } => self.import_default_hub_skill_expecting(
                owner, subtree, skill_id, version, occurred, now,
            ),
            ShapeSkillSource::Hub {
                hub,
                folder,
                pin_type,
                pin_value,
                publisher,
            } => EntityId::from_hex(hub)
                .map_err(|_| invalid("a hub is named by entity id hex"))
                .and_then(|hub| {
                    let pin = hub_pin(pin_type, pin_value)?;
                    self.import_skill_from_hub_ref_expecting(
                        owner, hub, folder, pin, publisher, skill_id, version,
                    )
                }),
        };
        let entity = imported.inspect_err(|_| sources.unknown())?;
        sources.list(entity);
        let record = self
            .get_skill_record(&entity)?
            .ok_or_else(|| invalid("the import left no skill record"))?;
        // The checked import read this before it wrote; a deduplicated
        // import answers with the skill it found, read again here.
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

    /// Moves an imported skill to the version the row pins, as `owner`:
    /// the owner's hub sync refetches what the skill's tracked ref names,
    /// checks it carries this skill at the pinned version before it marks
    /// the ref or moves the skill (FIX 10202), and applies that same package
    /// through the policy check. The item lands only when that applied the
    /// pinned version. A widening revision waits as the sync's own proposal,
    /// and a local skill's version moves only with its content, so both
    /// refuse the item with the reason.
    pub(super) fn update_shape_skill(
        &self,
        owner: &AuthenticatedOwner,
        entity: EntityId,
        version: &str,
        sources: &mut ShapeSources,
    ) -> Result<String> {
        // The sync reads the skill's hub records through its provenance to
        // refetch them; the tracked ref row it keys off them is named by
        // its hub.
        sources.list_read(
            self.skill_hub_sources(&entity)
                .map(|refs| refs.iter().map(|hub_ref| hub_ref.hub_id).collect::<Vec<_>>()),
        );
        match self.sync_skill_from_hub_ref_expecting(owner, &entity, version)? {
            HubSyncDisposition::Applied => {}
            HubSyncDisposition::Proposed { proposal_id, .. } => {
                return Err(invalid(format!(
                    "the hub's revision widens the skill; it waits as proposal {}",
                    proposal_id.to_hex()
                )));
            }
            HubSyncDisposition::RefusedByPolicy => {
                return Err(invalid("the skill's hub sync policy refused the revision"));
            }
        }
        let record = self
            .get_skill_record(&entity)?
            .ok_or_else(|| invalid("the sync left no skill record"))?;
        if record.version != version {
            return Err(invalid(format!(
                "the hub's revision carries version {}, not the row's {version}",
                record.version
            )));
        }
        Ok(entity.to_hex())
    }
}
