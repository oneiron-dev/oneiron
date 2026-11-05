//! Runtime routing boundaries for the entity-resolution waterfall.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::manifest_authenticity::PolicyRowOrigin;

pub(super) const KEY: &str = "entity_resolution_bands";

/// Boundaries applied in order by the existing entity-resolution waterfall.
/// Any finite f32 is valid; equal or reversed boundaries can empty a band.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityResolutionBands {
    pub provisional_below: f32,
    pub soft_link_low_below: f32,
    pub soft_link_below: f32,
}

impl Default for EntityResolutionBands {
    fn default() -> Self {
        Self {
            provisional_below: 0.50,
            soft_link_low_below: 0.70,
            soft_link_below: 0.90,
        }
    }
}

impl EntityResolutionBands {
    pub(super) fn is_finite(self) -> bool {
        self.provisional_below.is_finite()
            && self.soft_link_low_below.is_finite()
            && self.soft_link_below.is_finite()
    }

    pub(super) fn parse(value: &Value) -> Option<Self> {
        let Value::Map(fields) = value else {
            return None;
        };
        let mut provisional = None;
        let mut soft_link_low = None;
        let mut soft_link = None;
        for (key, value) in fields {
            let boundary = value.as_f64()? as f32;
            if !boundary.is_finite() {
                return None;
            }
            match key.as_str()? {
                "provisional_below" if provisional.is_none() => provisional = Some(boundary),
                "soft_link_low_below" if soft_link_low.is_none() => soft_link_low = Some(boundary),
                "soft_link_below" if soft_link.is_none() => soft_link = Some(boundary),
                _ => return None,
            }
        }
        Some(Self {
            provisional_below: provisional?,
            soft_link_low_below: soft_link_low?,
            soft_link_below: soft_link?,
        })
    }

    fn combine(self, other: Self) -> Self {
        Self {
            provisional_below: self.provisional_below.max(other.provisional_below),
            soft_link_low_below: self.soft_link_low_below.max(other.soft_link_low_below),
            soft_link_below: self.soft_link_below.max(other.soft_link_below),
        }
    }
}

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
