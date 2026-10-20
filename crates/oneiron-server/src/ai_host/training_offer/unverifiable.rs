//! The check's outcome when the promise cannot be read (FIX 6265, 6317).
//! The approved model served the whole window, but some of its calls have no
//! price the check can sum: they measured no tokens, no list price was frozen
//! on them, the one frozen on them quotes no rate for cached tokens they
//! measured, they are priced in another currency, their price would overflow
//! the sum, or their record names no reason. No such call is priced at zero,
//! converted or clipped, so the month's bill is unknown. The check closes with
//! an `unverifiable_*` outcome instead of waiting every night; it is neither a
//! pass nor a fail, and neither confirms nor withdraws the offer.
use super::{
    DAY_SECS, DreamerAdmittedAttempt, OfferCheckInput, SeatUsage, Sources, TrainingOffer, Vault,
    WINDOW_SECS,
};
use crate::usage::UnpricedCache;

/// One kind of window call the check cannot price or sum. Each such call is
/// counted under one kind.
#[derive(Clone, Copy)]
enum Gap {
    /// It measured no tokens.
    NoUsage,
    /// No list price was frozen on it at admission.
    UnpricedModel,
    /// The list price frozen on it quotes no rate for cached tokens it
    /// measured.
    UnpricedCache,
    /// It is priced in a currency other than the window's.
    MixedCurrency,
    /// Its price would carry the window's sum past what it holds.
    SumOverflow,
    /// It has no price, and its record names no reason.
    Unclassified,
}

impl Gap {
    /// Every kind, in the fixed order a note names them.
    const ORDER: [Self; 6] = [
        Self::NoUsage,
        Self::UnpricedModel,
        Self::UnpricedCache,
        Self::MixedCurrency,
        Self::SumOverflow,
        Self::Unclassified,
    ];

    /// The outcome code, at the head of the check's note.
    const fn code(self) -> &'static str {
        match self {
            Self::NoUsage => "unverifiable_no_usage",
            Self::UnpricedModel => "unverifiable_unpriced_model",
            Self::UnpricedCache => "unverifiable_unpriced_cache",
            Self::MixedCurrency => "unverifiable_mixed_currency",
            Self::SumOverflow => "unverifiable_sum_overflow",
            Self::Unclassified => "unverifiable_unclassified",
        }
    }
}

/// An `unverifiable_*` outcome: a window the approved model served
/// throughout, with calls the check cannot price or sum.
pub(super) struct Unverifiable {
    /// Calls in the window.
    calls: u64,
    /// The currency the window's priced calls are summed in.
    currency: Option<String>,
    /// The calls of each kind, as [`SeatUsage`] counted them.
    no_usage: u64,
    unpriced_model: u64,
    /// In all and per unquoted dimension.
    unpriced_cache: UnpricedCache,
    mixed_currency: u64,
    sum_overflow: u64,
    unclassified: u64,
}

impl Unverifiable {
    /// The outcome for `usage`, a window the approved model served
    /// throughout; `None` when every call is priced and summed in one
    /// currency, which leaves the promise to compare.
    pub(super) fn of(usage: &SeatUsage) -> Option<Self> {
        (!usage.complete && usage.gap_calls() > 0).then(|| Self {
            calls: usage.calls,
            currency: usage.currency.clone(),
            no_usage: usage.no_usage,
            unpriced_model: usage.unpriced_model,
            unpriced_cache: usage.unpriced_cache.clone(),
            mixed_currency: usage.mixed_currency,
            sum_overflow: usage.sum_overflow,
            unclassified: usage.unclassified,
        })
    }

    /// The calls of one kind.
    fn calls_of(&self, gap: Gap) -> u64 {
        match gap {
            Gap::NoUsage => self.no_usage,
            Gap::UnpricedModel => self.unpriced_model,
            Gap::UnpricedCache => self.unpriced_cache.calls,
            Gap::MixedCurrency => self.mixed_currency,
            Gap::SumOverflow => self.sum_overflow,
            Gap::Unclassified => self.unclassified,
        }
    }

    /// One kind's count after its code: per unquoted dimension for a cache
    /// gap, in all for any other.
    fn count(&self, gap: Gap, calls: u64) -> String {
        match gap {
            Gap::UnpricedCache => [
                ("cache_read", self.unpriced_cache.cache_read),
                ("cache_write", self.unpriced_cache.cache_write),
            ]
            .into_iter()
            .filter(|(_, calls)| *calls > 0)
            .map(|(dimension, calls)| format!("{dimension}: {calls} calls"))
            .collect::<Vec<_>>()
            .join(", "),
            _ => format!("{calls} calls"),
        }
    }

    /// What one kind's calls are, in the note's body.
    fn clause(&self, gap: Gap, calls: u64) -> String {
        match gap {
            Gap::NoUsage => format!("{calls} measured no tokens"),
            Gap::UnpricedModel => format!(
                "{calls} had no list price frozen on them at admission (no catalog row or \
                 convertible price for the model)"
            ),
            Gap::UnpricedCache => {
                format!("{calls} measured cached tokens their frozen list price quotes no rate for")
            }
            Gap::MixedCurrency => format!(
                "{calls} are priced in a currency other than {} and cannot join its sum",
                self.currency.as_deref().unwrap_or("no currency")
            ),
            Gap::SumOverflow => format!("{calls} have a price the window's sum cannot hold"),
            Gap::Unclassified => format!("{calls} have no price and a record that names no reason"),
        }
    }

    /// Records the check with this outcome where a pass or fail is recorded:
    /// the window's receipts, no observed cost, and the promise neither held
    /// nor broken, so the offer skill gets no evidence from it. The note
    /// starts with each kind's code present, in [`Gap::ORDER`], with its
    /// calls.
    pub(super) fn record(
        self,
        vault: &Vault,
        admitted: &DreamerAdmittedAttempt,
        offer: &TrainingOffer,
        approved: &str,
        refs: Vec<String>,
        now: u64,
    ) -> oneiron::Result<()> {
        let gaps = Gap::ORDER
            .into_iter()
            .map(|gap| (gap, self.calls_of(gap)))
            .filter(|(_, calls)| *calls > 0)
            .collect::<Vec<_>>();
        let codes = gaps
            .iter()
            .map(|(gap, _)| gap.code())
            .collect::<Vec<_>>()
            .join("; ");
        let head = gaps
            .iter()
            .map(|&(gap, calls)| format!("{} ({})", gap.code(), self.count(gap, calls)))
            .collect::<Vec<_>>()
            .join("; ");
        let days = WINDOW_SECS / DAY_SECS;
        let promised = format!(
            "{} {}",
            offer
                .cost
                .monthly_after
                .map_or_else(|| "an unknown".to_owned(), |after| format!("{after:.2}")),
            offer.cost.currency,
        );
        let note = if let [(Gap::UnpricedCache, unpriced)] = gaps.as_slice() {
            // A gap of cache rates alone keeps its note (FIX 6265).
            format!(
                "{head}: {unpriced} of {} calls on {approved} over the {days} days to the check \
                 have no price, as the list price frozen on each quotes no rate for cached tokens \
                 it measured; an unpriced call is never priced at zero, so whether the month kept \
                 the promised {promised} is unknown.",
                self.calls,
            )
        } else {
            let clauses = gaps
                .iter()
                .map(|&(gap, calls)| self.clause(gap, calls))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{head}: of {} calls on {approved} over the {days} days to the check, {clauses}; \
                 no call is priced at zero, converted or clipped, so whether the month kept the \
                 promised {promised} is unknown.",
                self.calls,
            )
        };
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
        // A settlement always names why a call is unpriced, so these calls
        // are older records or posted ones: worth a look, never their content.
        if self.unclassified > 0 {
            tracing::warn!(
                offer = %offer.id.to_hex(),
                unclassified = self.unclassified,
                "an offer check closed on unpriced calls whose record names no reason"
            );
        }
        tracing::debug!(
            offer = %offer.id.to_hex(),
            outcome = %codes,
            "the Coach closed an offer's check unread"
        );
        Ok(())
    }
}
