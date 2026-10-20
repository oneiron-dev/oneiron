//! The check's outcome when the promise cannot be read (FIX 6265, 6317,
//! 6406, 6475, 6477). Once the whole window after the yes is over, the check
//! closes with an `unverifiable_*` outcome instead of waiting every night; it
//! is neither a pass nor a fail, and neither confirms nor withdraws the offer.
//! It closes this way when it reads no call of the approved model: the seat
//! ran none, the vault has no meter, a Train yes has no run that reached
//! Bound, or the offer's seat names no model role. It also closes this way
//! when some of the approved model's calls have no price the check can sum:
//! they measured no tokens, no list price was frozen on them, the one frozen
//! on them quotes no rate for cached tokens they measured, they are priced in
//! another currency, their price would overflow the sum, or their record
//! names no reason or does not decode. No such call is priced at zero,
//! converted or clipped, so the month's bill is unknown. The seat's calls on
//! another model, or on none, are counted out, and its note says how many;
//! with any counted out, the approved model's calls are only part of the
//! seat's month, so a window that would pass or fail closes as
//! `unverifiable_mixed_model` instead, with their calls and cost.
use super::{
    DAY_SECS, DreamerAdmittedAttempt, OfferCheckInput, SeatUsage, Sources, TrainingOffer, Vault,
    WINDOW_SECS,
};
use crate::usage::UnpricedCache;

/// Why the check read no call of the approved model. Each code stands alone
/// in its note, and comes before every other code in the fixed order
/// (no_calls; no_meter; not_bound; no_model_role): with no such call there
/// are no gaps to list.
#[derive(Clone, Copy)]
pub(super) enum Alone {
    /// The seat ran no call on the approved model in the window.
    NoCalls,
    /// The vault has no usage meter bound.
    NoMeter,
    /// The yes asked to train a custom model, and no run it handed off
    /// reached Bound.
    NotBound,
    /// The offer's seat names no model role, so it has no calls to read.
    NoModelRole,
}

impl Alone {
    /// The outcome code, alone at the head of the check's note.
    const fn code(self) -> &'static str {
        match self {
            Self::NoCalls => "unverifiable_no_calls",
            Self::NoMeter => "unverifiable_no_meter",
            Self::NotBound => "unverifiable_not_bound",
            Self::NoModelRole => "unverifiable_no_model_role",
        }
    }
}

/// The outcome code when the seat's calls on another model, or on none, were
/// counted out. It comes first among the codes after those that stand alone,
/// before every [`Gap`] code.
const MIXED_MODEL: &str = "unverifiable_mixed_model";

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
    /// Every kind, in the fixed order a note names them, after the codes
    /// that stand alone ([`Alone`]) and [`MIXED_MODEL`].
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

/// An `unverifiable_*` outcome: a window with no call of the approved model
/// to read, with calls of it the check cannot price or sum, or with the
/// seat's other calls counted out.
#[derive(Default)]
pub(super) struct Unverifiable {
    /// The code that stands alone, when the check read no call of the
    /// approved model.
    alone: Option<Alone>,
    /// The approved model's calls in the window.
    calls: u64,
    /// Their stamped prices summed, in 10^-9 units of `currency`.
    cost_amount: u64,
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
    /// The `unclassified` records that do not decode.
    undecodable: u64,
    /// The seat's other calls in the window, counted out.
    counted_out: u64,
}

impl Unverifiable {
    /// The outcome for `usage`, the approved model's calls over a window
    /// metered throughout: no such call, other calls counted out beside them,
    /// or some the check cannot price or sum; `None` when nothing was counted
    /// out and every call is priced and summed in one currency, which leaves
    /// the promise to compare.
    pub(super) fn of(usage: &SeatUsage) -> Option<Self> {
        let alone = (usage.calls == 0).then_some(Alone::NoCalls);
        let unread = !usage.complete && usage.gap_calls() > 0;
        (alone.is_some() || usage.counted_out > 0 || unread).then(|| Self {
            alone,
            calls: usage.calls,
            cost_amount: usage.cost_amount,
            currency: usage.currency.clone(),
            no_usage: usage.no_usage,
            unpriced_model: usage.unpriced_model,
            unpriced_cache: usage.unpriced_cache.clone(),
            mixed_currency: usage.mixed_currency,
            sum_overflow: usage.sum_overflow,
            unclassified: usage.unclassified,
            undecodable: usage.undecodable,
            counted_out: usage.counted_out,
        })
    }

    /// Closes the check with `alone`, a reason it read no call at all: no
    /// meter, no Bound run, or no model role.
    pub(super) fn unread(
        alone: Alone,
        vault: &Vault,
        admitted: &DreamerAdmittedAttempt,
        offer: &TrainingOffer,
        now: u64,
    ) -> oneiron::Result<()> {
        let outcome = Self {
            alone: Some(alone),
            ..Self::default()
        };
        outcome.record(vault, admitted, offer, "", Vec::new(), now)
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
            Gap::Unclassified if self.undecodable > 0 => format!(
                "{calls} have no price and a record that names no reason ({} of them stored \
                 records that do not decode, whose seat, model and time are unknown)",
                self.undecodable
            ),
            Gap::Unclassified => format!("{calls} have no price and a record that names no reason"),
        }
    }

    /// The note of a code that stands alone.
    fn alone_note(alone: Alone, approved: &str, days: u64, promised: &str) -> String {
        let code = alone.code();
        match alone {
            Alone::NoCalls => format!(
                "{code}: no metered call ran on {approved} over the {days} days to the check, so \
                 whether the month kept the promised {promised} is unknown."
            ),
            Alone::NoMeter => format!(
                "{code}: no usage meter is bound for this vault, so none of the seat's calls over \
                 the {days} days to the check could be read; whether the month kept the promised \
                 {promised} is unknown."
            ),
            Alone::NotBound => format!(
                "{code}: the yes asked to train a custom model, and no run it handed off had \
                 reached Bound by the check, {days} days or more after the yes, so no call on that \
                 model could be read; whether the month kept the promised {promised} is unknown."
            ),
            Alone::NoModelRole => format!(
                "{code}: the offer's seat names no model role, so none of its calls over the \
                 {days} days to the check could be read; whether the month kept the promised \
                 {promised} is unknown."
            ),
        }
    }

    /// Records the check with this outcome where a pass or fail is recorded:
    /// the window's receipts, no observed cost, and the promise neither held
    /// nor broken, so the offer skill gets no evidence from it. The note
    /// starts with a code that stands alone, or with [`MIXED_MODEL`] when
    /// calls were counted out and then each kind's code present, in
    /// [`Gap::ORDER`], with its calls; the counted-out calls close it.
    pub(super) fn record(
        self,
        vault: &Vault,
        admitted: &DreamerAdmittedAttempt,
        offer: &TrainingOffer,
        approved: &str,
        refs: Vec<String>,
        now: u64,
    ) -> oneiron::Result<()> {
        let days = WINDOW_SECS / DAY_SECS;
        let promised = format!(
            "{} {}",
            offer
                .cost
                .monthly_after
                .map_or_else(|| "an unknown".to_owned(), |after| format!("{after:.2}")),
            offer.cost.currency,
        );
        let (codes, note) = match self.alone {
            Some(alone) => (
                alone.code().to_owned(),
                Self::alone_note(alone, approved, days, &promised),
            ),
            None => self.gap_note(approved, days, &promised),
        };
        let note = format!("{note}{}", counted_out(self.counted_out));
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
        // The read itself named the records that do not decode.
        let unclassified = self.unclassified.saturating_sub(self.undecodable);
        if unclassified > 0 {
            tracing::warn!(
                offer = %offer.id.to_hex(),
                unclassified,
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

    /// The codes, and the note, of a window whose approved calls shared the
    /// seat with calls counted out, or include some the check cannot price
    /// or sum.
    fn gap_note(&self, approved: &str, days: u64, promised: &str) -> (String, String) {
        let gaps = Gap::ORDER
            .into_iter()
            .map(|gap| (gap, self.calls_of(gap)))
            .filter(|(_, calls)| *calls > 0)
            .collect::<Vec<_>>();
        let mixed = (self.counted_out > 0).then_some((MIXED_MODEL, self.counted_out));
        let codes = mixed
            .iter()
            .map(|(code, _)| *code)
            .chain(gaps.iter().map(|(gap, _)| gap.code()))
            .collect::<Vec<_>>()
            .join("; ");
        let head = mixed
            .iter()
            .map(|(code, calls)| format!("{code} ({calls} calls)"))
            .chain(
                gaps.iter()
                    .map(|&(gap, calls)| format!("{} ({})", gap.code(), self.count(gap, calls))),
            )
            .collect::<Vec<_>>()
            .join("; ");
        let note = match gaps.as_slice() {
            // Every approved call priced, beside calls counted out: their cost
            // is no month of the seat's, so it is neither kept nor broken
            // (FIX 6475).
            [] => format!(
                "{head}: {} calls on {approved} over the {days} days to the check, all priced, \
                 costing {} {} in all; with the seat's other calls counted out they are only part \
                 of its month, so whether the month kept the promised {promised} is unknown.",
                self.calls,
                self.cost_amount as f64 / 1e9,
                self.currency.as_deref().unwrap_or("no currency"),
            ),
            // A gap of cache rates alone keeps its note (FIX 6265).
            [(Gap::UnpricedCache, unpriced)] => format!(
                "{head}: {unpriced} of {} calls on {approved} over the {days} days to the check \
                 have no price, as the list price frozen on each quotes no rate for cached tokens \
                 it measured; an unpriced call is never priced at zero, so whether the month kept \
                 the promised {promised} is unknown.",
                self.calls,
            ),
            _ => {
                let clauses = gaps
                    .iter()
                    .map(|&(gap, calls)| self.clause(gap, calls))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "{head}: of {} calls on {approved} over the {days} days to the check, \
                     {clauses}; no call is priced at zero, converted or clipped, so whether the \
                     month kept the promised {promised} is unknown.",
                    self.calls,
                )
            }
        };
        (codes, note)
    }
}

/// The note's last sentence when the check counted calls out: the seat's
/// window calls on another model, or naming none. It names their count, never
/// a model or a call's content; empty when there are none.
fn counted_out(calls: u64) -> String {
    if calls == 0 {
        return String::new();
    }
    format!(
        " counted_out_other_model ({calls} calls): {calls} calls on the seat over the {} days to \
         the check ran on another model or named none (a fallback, the owner switching back, a \
         connector call), and the check left them out.",
        WINDOW_SECS / DAY_SECS
    )
}
