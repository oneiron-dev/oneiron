//! Input room for the models currently available on one ladder.

use std::collections::BTreeMap;

use oneiron::ModelId;

use super::OfferLadder;

impl OfferLadder {
    /// Minimum configured room across this ladder and its live fallbacks.
    /// Missing or zero room is explicit unknown (`Some(0)`); an empty ladder is `None`.
    pub(crate) fn input_window(&self, windows: &BTreeMap<ModelId, u64>) -> Option<u64> {
        self.rung_models()
            .map(|(model, _)| windows.get(model).copied().unwrap_or(0))
            .chain(
                self.fallback_rung_models()
                    .iter()
                    .map(|(model, _)| windows.get(model).copied().unwrap_or(0)),
            )
            .min()
    }
}
