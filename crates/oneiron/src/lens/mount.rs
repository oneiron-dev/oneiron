//! Pack-aware lens mount decision, evaluated against the live vault on each render.
use crate::{Vault, entity_id::EntityId, error::Result};

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
        let Some(install) = self.installed_pack(pack_name)? else {
            return Ok(false);
        };
        if !install
            .candidate_skills
            .iter()
            .any(|id| id == &skill_id.to_hex())
        {
            return Ok(false);
        }
        Ok(self
            .get_skill_record(skill_id)?
            .is_some_and(|skill| skill.lifecycle_status.loads_as_canon()))
    }
}
