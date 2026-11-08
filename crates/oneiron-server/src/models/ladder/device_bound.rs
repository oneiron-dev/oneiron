//! A ladder held to this device for one Dreamer pass (FIX 12735): each of
//! its rungs sends on the device, and its locality ceiling keeps every
//! owner's fallback there too (I2-LOCAL), so a rung that fails on the device
//! fails its call closed rather than send it on past the device. A pass
//! lists its sources for this device only while every route it sends on is
//! held so.
use super::*;

impl OfferLadder {
    /// This ladder held to this device: a call-local copy with the same
    /// rungs, name, pick, rests, prefix and agent list, its scope's locality
    /// ceiling on the device, so no owner's fallback that would take a call
    /// off the device is reachable ([`Self::can_serve`]) and no rung past it
    /// is sent ([`Self::passes_over`]). `None` when it has no rung, or a rung
    /// whose offer is not on the device or sends off it. The shared ladder is
    /// never changed.
    #[must_use]
    pub(crate) fn held_on_device(&self) -> Option<Arc<Self>> {
        if self.rungs.is_empty()
            || self.rungs.iter().any(|rung| {
                rung.offer.binding.locality != ModelLocality::OnDevice
                    || rung.offer.destination().is_off_device()
            })
        {
            return None;
        }
        Some(Arc::new(Self {
            name: self.name.clone(),
            rungs: self.rungs.clone(),
            picked: self.picked,
            rests: Arc::clone(&self.rests),
            scope: SeatScope {
                locality_ceiling: Some(ModelLocality::OnDevice),
                ..self.scope
            },
            prefix: self.prefix.clone(),
            listed: self.listed.clone(),
        }))
    }
}
