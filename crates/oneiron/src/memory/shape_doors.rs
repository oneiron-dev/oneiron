//! The vault shape's free reads on code mode and MCP (ARCH-0070):
//! `vault.shape.read` and `vault.shape.plan`, over the setup rows the
//! caller's read admits. A caller who cannot read a world plans as though it
//! were not there.
use super::{Memory, MemoryResult};
use crate::claim::ClaimReadStatus;
use crate::vault_shape::{ShapePlan, ShapePlanRequest, ShapeRead};

impl Memory<'_> {
    /// `vault.shape.read`: the stored seed and the live arrangement.
    pub fn shape_read(&self) -> MemoryResult<ShapeRead> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        Ok(self
            .vault
            .shape_read_visible(&mut |id| read.is_entity_readable(id))?)
    }

    /// `vault.shape.plan`: the difference between a seed, or the stored
    /// one, and the vault. Writes nothing.
    pub fn shape_plan(&self, input: &ShapePlanRequest) -> MemoryResult<ShapePlan> {
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        Ok(self
            .vault
            .plan_shape_visible(input.seed.as_ref(), &mut |id| read.is_entity_readable(id))?)
    }
}
