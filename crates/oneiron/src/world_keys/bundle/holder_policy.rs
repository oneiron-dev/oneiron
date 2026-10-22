//! A holder's sealed-copy setting, apart from the section a world rides in
//! (FIX 8886): one rule for a private world's section and for a world read
//! everywhere that rides the base section.

use crate::authority::{AuthorityFold, Destination, SealedCopies};
use crate::entity_id::EntityId;

impl AuthorityFold {
    /// Whether a bundle `holder` keeps may hold `world`'s copy by its
    /// sealed-copy setting: "Cloud + my machines" for any holder, "My
    /// machines" for a machine trusted as the owner's here, "Off" for none.
    pub(crate) fn holder_keeps_sealed_copies(&self, world: EntityId, holder: Destination) -> bool {
        match self.world_privacy(world).sealed {
            SealedCopies::Off => false,
            SealedCopies::MyMachines => matches!(
                holder,
                Destination::Machine(machine) if self.trusted_machine(machine).is_some()
            ),
            SealedCopies::CloudAndMyMachines => true,
        }
    }

    /// Whether a bundle `holder` keeps carries `world`'s windows in its base
    /// section: base reality always, any other world read everywhere as the
    /// holder's sealed-copy setting allows (FIX 8886).
    #[cfg(feature = "sync")]
    pub(crate) fn base_section_carries(&self, world: EntityId, holder: Destination) -> bool {
        world == super::super::base_world() || self.holder_keeps_sealed_copies(world, holder)
    }
}
