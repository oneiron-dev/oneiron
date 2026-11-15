//! The owner's standing quota fallback, kept as a `use_fallback` answer
//! keeps it, for the integration tests (FIX-LIST
//! REPLAY-REFUSED-FOR-WIDER-FALLBACK-RUNG). Compiled only under
//! `--cfg oneiron_test_support`; `crate::test_doors::replay_admission` opens
//! it.

use oneiron::llm::run_admission::OfferBinding;

use super::{OfferCooldowns, PREFIX, key};

impl OfferCooldowns {
    /// Keeps `fallback`, an engine model id, as the owner's fallback for the
    /// offer serving `wire_model`, under the id the offer's quota question
    /// carries, as [`Self::answer`] keeps a `use_fallback` answer.
    ///
    /// # Errors
    ///
    /// The vault's; [`oneiron::Error::InvalidConfig`] for rests kept in no
    /// vault, which keep no owner's choice.
    pub(in crate::models) fn keep_owner_fallback(
        &self,
        offer: &OfferBinding,
        wire_model: &str,
        fallback: &str,
    ) -> oneiron::Result<()> {
        let vault = self.vault.as_ref().ok_or_else(|| {
            oneiron::Error::InvalidConfig("these rests keep no owner's choice".into())
        })?;
        vault.set_model_fallback(key(offer, wire_model).trim_start_matches(PREFIX), fallback)
    }
}
