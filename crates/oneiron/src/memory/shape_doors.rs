//! The vault shape on code mode and MCP (ARCH-0070): the free reads
//! `vault.shape.read` and `vault.shape.plan`, over the setup rows the
//! caller's read admits, and the gated effect `vault.shape.apply`. A caller
//! who cannot read a world plans as though it were not there.
use super::{Memory, MemoryResult};
use crate::claim::ClaimReadStatus;
use crate::vault_shape::{
    ShapeApplier, ShapeApplyReceipt, ShapeApplyRequest, ShapePlan, ShapePlanRequest, ShapeRead,
};

impl Memory<'_> {
    /// `vault.shape.read`: the stored seed and the live arrangement.
    pub fn shape_read(&self) -> MemoryResult<ShapeRead> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        Ok(self
            .vault
            .shape_read_visible(&mut |id| read.is_entity_readable(id))?)
    }

    /// `vault.shape.plan`: the difference between a seed, a preset pick's
    /// seed or the stored one, and the vault. Writes nothing.
    pub fn shape_plan(&self, input: &ShapePlanRequest) -> MemoryResult<ShapePlan> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let seed = input.seed_for(self.actor)?;
        Ok(self
            .vault
            .plan_shape_visible(seed.as_ref(), &mut |id| read.is_entity_readable(id))?)
    }

    /// `vault.shape.apply`: lands a plan. On an embedded handle the vault's
    /// owner lands it through the owner's doors; any other caller's apply
    /// stores the seed and leaves each item waiting for the owner's word.
    pub fn shape_apply(&self, input: &ShapeApplyRequest) -> MemoryResult<ShapeApplyReceipt> {
        let now = crate::unix_seconds_now();
        if let Ok(owner) = self.embedded_owner("vault.shape.apply") {
            return Ok(self
                .vault
                .apply_shape(
                    ShapeApplier::Owner {
                        owner: &owner,
                        slips: None,
                    },
                    input,
                    now,
                    &mut |_| Ok(true),
                )?);
        }
        self.shape_apply_as_principal(input)
    }

    /// `vault.shape.apply` as this handle's principal, never the owner: the
    /// seed is stored and every item waits for the owner's word. A new grant
    /// is also filed to the owner's widen inbox under the credential this
    /// handle reads with, when it has one.
    pub fn shape_apply_as_principal(
        &self,
        input: &ShapeApplyRequest,
    ) -> MemoryResult<ShapeApplyReceipt> {
        let now = crate::unix_seconds_now();
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        Ok(self.vault.apply_shape(
            ShapeApplier::Actor {
                actor: self.actor,
                credential: self.read_proof.as_ref(),
            },
            input,
            now,
            &mut |id| read.is_entity_readable(id),
        )?)
    }
}
