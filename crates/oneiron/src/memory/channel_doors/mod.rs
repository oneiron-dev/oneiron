//! Typed ChannelIdentity, selection, passport and delivery-window doors.
//! Authority comes from the bound credential or the authenticated owner;
//! request bodies carry names and policy, never permission booleans.

mod lifecycle;
mod passport;
mod policy;
mod selection;

pub use lifecycle::*;
pub use passport::*;
pub use policy::*;
pub use selection::*;

use super::{Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;

impl Memory<'_> {
    fn channel_readable(&self, id: EntityId) -> MemoryResult<()> {
        self.produced_from([id]);
        if self.get_entity(&id.to_hex())?.value.is_none() {
            return Err(MemoryError::not_found(
                "channel door record is absent or withheld",
            ));
        }
        Ok(())
    }

    fn channel_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<EntityId> {
        let actor = owner.revalidate(self.vault)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(MemoryError::new(
                super::MEMORY_CODE_FORBIDDEN,
                "channel setup acts as the authenticated owner",
                &[],
            ));
        }
        Ok(actor)
    }
}
