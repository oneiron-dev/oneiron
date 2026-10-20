//! The check's outcome when the promise cannot be read (FIX 6265):
//! `unverifiable_unpriced_cache`. The approved model served the whole window
//! and every call in it is priced in one currency, except calls the rates
//! frozen on them could not price: they quote no rate for a cache dimension
//! the call measured. Such a call is never priced at zero, so the month's
//! bill is unknown. The check closes with this outcome instead of waiting
//! every night; it is neither a pass nor a fail, and neither confirms nor
//! withdraws the offer.
use super::{
    DAY_SECS, DreamerAdmittedAttempt, OfferCheckInput, SeatUsage, Sources, TrainingOffer, Vault,
    WINDOW_SECS,
};
use crate::usage::UnpricedCache;

/// The outcome's code, at the head of the check's note.
const CODE: &str = "unverifiable_unpriced_cache";

/// `unverifiable_unpriced_cache`: a window whose only unpriced calls lack a
/// quoted cache rate.
pub(super) struct UnverifiableUnpricedCache {
    /// Calls in the window.
    calls: u64,
    /// The unpriced ones, in all and per unquoted dimension.
    unpriced: UnpricedCache,
}

impl UnverifiableUnpricedCache {
    /// The outcome for `usage`, a window the approved model served
    /// throughout; `None` when every call is priced, or when any call lacks a
    /// price for another reason (another currency, or an older record that
    /// names no reason), which keeps the check waiting.
    pub(super) fn of(usage: &SeatUsage) -> Option<Self> {
        (!usage.complete && usage.complete_but_unpriced_cache && usage.unpriced_cache.calls > 0)
            .then(|| Self {
                calls: usage.calls,
                unpriced: usage.unpriced_cache.clone(),
            })
    }

    /// Records the check with this outcome where a pass or fail is recorded:
    /// the window's receipts, no observed cost, and the promise neither held
    /// nor broken, so the offer skill gets no evidence from it.
    pub(super) fn record(
        self,
        vault: &Vault,
        admitted: &DreamerAdmittedAttempt,
        offer: &TrainingOffer,
        approved: &str,
        refs: Vec<String>,
        now: u64,
    ) -> oneiron::Result<()> {
        // Each unquoted dimension with its unpriced calls, after the code.
        let dimensions = [
            ("cache_read", self.unpriced.cache_read),
            ("cache_write", self.unpriced.cache_write),
        ]
        .into_iter()
        .filter(|(_, calls)| *calls > 0)
        .map(|(dimension, calls)| format!("{dimension}: {calls} calls"))
        .collect::<Vec<_>>()
        .join(", ");
        let note = format!(
            "{CODE} ({dimensions}): {} of {} calls on {approved} over the {} days to the check \
             have no price, as the list price frozen on each quotes no rate for cached tokens it \
             measured; an unpriced call is never priced at zero, so whether the month kept the \
             promised {} {} is unknown.",
            self.unpriced.calls,
            self.calls,
            WINDOW_SECS / DAY_SECS,
            offer
                .cost
                .monthly_after
                .map_or_else(|| "an unknown".to_owned(), |after| format!("{after:.2}")),
            offer.cost.currency,
        );
        // Read as a pass or fail check reads (FIX 5482).
        let mut sources = Sources::new();
        sources.set(offer.source_rows.as_deref());
        sources.unknown();
        vault.run_coach_offer_check(
            admitted,
            OfferCheckInput {
                receipt_refs: refs,
                observed_monthly_cost: None,
                observed_score: None,
                held: None,
                note: Some(note),
                source_rows: sources.rows(),
            },
            now,
        )?;
        tracing::debug!(
            offer = %offer.id.to_hex(),
            outcome = CODE,
            "the Coach closed an offer's check unread"
        );
        Ok(())
    }
}
