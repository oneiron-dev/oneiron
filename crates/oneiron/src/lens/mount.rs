//! Pack-aware lens mount decision, evaluated against the live vault on each render.
use super::GeneratedLens;
use crate::{
    Vault,
    entity_id::EntityId,
    error::{ArtifactError, Error, Result},
    registry::ENTITY_TYPE_SKILL,
    skill_hub::pack_catalog::PackInstallReceipt,
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

    /// Re-read the installation and skill state BEFORE every render. A hidden
    /// lens never invokes its host renderer, even if it mounted earlier.
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

    /// Render the generated lens the owner selected for a pack/skill slot.
    ///
    /// This is the render host for a compiled pack lens: it calls
    /// [`Vault::active_pack_lens`] before every render, so the slot's
    /// selection is rechecked against the live install (pack still Active
    /// at the content the lens was proposed against, skill still loading)
    /// in the same breath as the render. `render` runs only with the lens
    /// that check returns; when the slot holds none or no longer mounts,
    /// `render` never runs and the answer is `None`. Hosts render through
    /// this instead of caching a tree from `vault.lenses.list`.
    pub fn render_active_pack_lens<T>(
        &self,
        pack_name: &str,
        skill_id: &EntityId,
        render: impl FnOnce(&EntityId, &GeneratedLens) -> Result<T>,
    ) -> Result<Option<T>> {
        let Some((lens_ref, lens)) = self.active_pack_lens(pack_name, skill_id)? else {
            return Ok(None);
        };
        render(&lens_ref, &lens).map(Some)
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
        Ok(self
            .live_pack_skill_in_txn(&txn, pack_name, skill_id)?
            .is_some())
    }

    /// The installation a pack lens slot rests on, in `txn`: the pack is
    /// installed with a live source, `skill_id` is one of its skills, and that
    /// skill still loads. `None` when any of those fails. A proposed or
    /// selected generated lens takes the same check as a host code lens.
    pub(super) fn live_pack_skill_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        pack_name: &str,
        skill_id: &EntityId,
    ) -> Result<Option<PackInstallReceipt>> {
        let Some(install) = self.mounted_pack_in_txn(txn, pack_name)? else {
            return Ok(None);
        };
        if !install.skills.iter().any(|id| id == &skill_id.to_hex()) {
            return Ok(None);
        }
        // A soft erase leaves a valid type-7 header without a SKILL body.
        // Resolve deletion before decoding, in the same snapshot as the pack.
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&self.store, txn, skill_id)?
        else {
            return Ok(None);
        };
        if entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "entity is not a type-7 SKILL",
            )));
        }
        // H355: the skill must still LOAD (Active and approved), the same
        // invariant the load door applies; a rejected skill keeps no lens.
        Ok(
            crate::skill::skill_loadable(&crate::skill::decode_skill_record(&body)?)
                .then_some(install),
        )
    }
}
