//! Pack-aware lens mount decision, evaluated against the live vault on each render.
use crate::{
    Vault,
    entity_id::EntityId,
    error::{ArtifactError, Error, Result},
    registry::ENTITY_TYPE_SKILL,
    vault::{LiveEntityRow, live_entity_row_in_txn},
};

/// A host-supplied code-lens binding. The engine owns no workbench catalog or
/// screen inventory; the host supplies only bindings it can actually render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LensMount {
    Vault,
    Admin,
    /// A lens shipped with an installed pack and backed by one of its skills.
    Pack {
        pack_name: String,
        skill_id: EntityId,
    },
}

impl Vault {
    /// Resolve a host's lens bindings against current install and skill state.
    /// Call again when displaying the available lenses; this is not a cache.
    pub fn mounted_lenses(&self, bindings: &[LensMount]) -> Result<Vec<LensMount>> {
        let mut mounted = vec![LensMount::Vault, LensMount::Admin];
        for binding in bindings {
            if matches!(binding, LensMount::Pack { .. }) && self.lens_is_mounted(binding)? {
                mounted.push(binding.clone());
            }
        }
        Ok(mounted)
    }

    /// Re-read the installation and skill lifecycle BEFORE every render. A
    /// hidden lens never invokes its host renderer, even if it mounted earlier.
    /// The host provides code, not an engine-defined screen or lens DSL.
    pub fn render_mounted_lens<T>(
        &self,
        binding: &LensMount,
        render: impl FnOnce() -> Result<T>,
    ) -> Result<Option<T>> {
        if !self.lens_is_mounted(binding)? {
            return Ok(None);
        }
        render().map(Some)
    }

    fn lens_is_mounted(&self, binding: &LensMount) -> Result<bool> {
        let LensMount::Pack {
            pack_name,
            skill_id,
        } = binding
        else {
            return Ok(true);
        };
        let txn = self.store.env.read_txn()?;
        let Some(install) = self.mounted_pack_in_txn(&txn, pack_name)? else {
            return Ok(false);
        };
        if !install
            .candidate_skills
            .iter()
            .any(|id| id == &skill_id.to_hex())
        {
            return Ok(false);
        }
        // A soft erase leaves a valid type-7 header without a SKILL body.
        // Resolve deletion before decoding, in the same snapshot as the pack.
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&self.store, &txn, skill_id)?
        else {
            return Ok(false);
        };
        if entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "entity is not a type-7 SKILL",
            )));
        }
        Ok(crate::skill::decode_skill_record(&body)?
            .lifecycle_status
            .loads_as_canon())
    }
}
