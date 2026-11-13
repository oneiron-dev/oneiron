//! The owner's explicit naming of this install's predecessor device key.

use serde::{Deserialize, Serialize};

use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::EdgeActorClass;
use crate::consent::AuthenticatedOwner;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::device_succession::DevicePredecessor;
#[doc(hidden)]
use oneiron_verb_wire::memory::device_succession::lower_hex;

impl Memory<'_> {
    /// `vault.devices.predecessor.name`: the actual owner names a predecessor
    /// under the native door, which supplies this install's successor and
    /// revalidates the owner in the authority writer before committing.
    pub fn device_predecessor_name_as(
        &self,
        owner: &AuthenticatedOwner,
        input: DevicePredecessor,
    ) -> MemoryResult<DevicePredecessor> {
        let actor = owner.revalidate(self.vault)?;
        if actor != self.actor || self.actor_class != EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "device predecessor naming acts as the authenticated owner",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        let (client, device_key) = input.identifiers()?;
        self.vault.name_device_predecessor_as_owner(
            owner,
            self.owner_surface(),
            client,
            device_key,
        )?;
        Ok(input)
    }
}
