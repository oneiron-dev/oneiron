//! The owner's standing quota fallback for each offer of a ladder, for the
//! integration tests (FIX-LIST REPLAY-REFUSED-FOR-WIDER-FALLBACK-RUNG).
//! Compiled only under `--cfg oneiron_test_support`;
//! `crate::test_doors::replay_admission` opens it.

use super::OfferLadder;

impl OfferLadder {
    /// Keeps `fallback`, an engine model id, as the owner's fallback for
    /// every offer of this ladder, as a `use_fallback` answer to each
    /// offer's quota question keeps it. How many offers.
    ///
    /// # Errors
    ///
    /// The vault's, and rests kept in no vault.
    pub(crate) fn keep_owner_fallback_for_each_offer(
        &self,
        fallback: &str,
    ) -> oneiron::Result<usize> {
        for rung in &self.rungs {
            self.rests
                .keep_owner_fallback(&rung.offer.binding, &rung.wire_model, fallback)?;
        }
        Ok(self.rungs.len())
    }
}
