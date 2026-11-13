//! Runtime routing boundaries for the entity-resolution waterfall.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::manifest_authenticity::PolicyRowOrigin;

pub(super) const KEY: &str = "entity_resolution_bands";

#[doc(hidden)]
pub use oneiron_verb_wire::gate::entity_resolution_bands::EntityResolutionBands;

/// Authored values replace seeds, never meet the compiled fallback.
#[derive(Default)]
pub(super) struct EntityResolutionBandFold {
    seeded: Option<EntityResolutionBands>,
    authored: Option<EntityResolutionBands>,
    narrowing: Option<EntityResolutionBands>,
}

impl EntityResolutionBandFold {
    pub(super) fn add(&mut self, origin: PolicyRowOrigin, bands: EntityResolutionBands) {
        let slot = match origin {
            PolicyRowOrigin::Seeded => &mut self.seeded,
            PolicyRowOrigin::Authored => &mut self.authored,
            PolicyRowOrigin::Narrowing => &mut self.narrowing,
        };
        *slot = Some(slot.map_or(bands, |current| current.combine(bands)));
    }

    pub(super) fn resolve(self) -> Option<EntityResolutionBands> {
        match (self.authored.or(self.seeded), self.narrowing) {
            (Some(base), Some(narrowing)) => Some(base.combine(narrowing)),
            (base, narrowing) => base.or(narrowing),
        }
    }
}
