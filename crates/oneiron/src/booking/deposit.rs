//! BK-DEPOSITS: the deposit an event type asks before a booking is
//! confirmed (ARCH-0062 §7 `v1.5` row, the R3 payment note).
//!
//! The owner sets the terms per event type, inside its configuration
//! ([`crate::booking::EventTypeConfig::deposit`]; Engine ruling, Sun 15 Nov
//! 01:10): the amount, the currency and the refund rule, with the defaults
//! stated below. The visitor's card is authorized when the hold is extended
//! to the checkout window, captured at confirm, and the authorization is
//! voided when the hold dies unconfirmed. The money is the visitor's, paid to
//! the owner's own Stripe account; Oneiron holds no funds.
//!
//! The public card carries the same terms
//! ([`crate::booking::EventTypeCard::deposit`]), and the live publication read
//! refuses a card whose terms differ from its configuration, so the terms a
//! visitor pays are the ones the owner published.

use serde::{Deserialize, Serialize};

use crate::booking::BookingError;
use crate::booking::config::MAX_BOOKING_WINDOW_SECS;

/// The stated default of [`DepositRefundRule::full_refund_notice_secs`]: a
/// visitor who cancels at least a day before the start gets the whole
/// deposit back.
pub const DEFAULT_DEPOSIT_FULL_REFUND_NOTICE_SECS: u64 = 24 * 3_600;

/// The largest deposit one event type may ask, in the currency's smallest
/// unit: the provider's own eight-digit ceiling on one payment.
pub const MAX_DEPOSIT_AMOUNT_MINOR: u64 = 99_999_999;

/// The deposit one event type asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositTerms {
    /// In the currency's smallest unit, as the provider counts it: cents for
    /// `usd`, yen for `jpy`. `1..=MAX_DEPOSIT_AMOUNT_MINOR`.
    pub amount_minor: u64,
    /// ISO 4217, three lowercase letters, the provider's spelling.
    pub currency: String,
    /// What a visitor's cancel gets back. Omitted: the stated defaults of
    /// [`DepositRefundRule::default`].
    #[serde(default)]
    pub refund: DepositRefundRule,
}

/// What a visitor's own cancel refunds. A no-show refunds nothing: the
/// deposit was captured at confirm and stays captured. A move keeps the
/// deposit as paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositRefundRule {
    /// A cancel at least this long before the start refunds the whole
    /// deposit. Default [`DEFAULT_DEPOSIT_FULL_REFUND_NOTICE_SECS`].
    #[serde(default = "default_full_refund_notice_secs")]
    pub full_refund_notice_secs: u64,
    /// The percent of the deposit a later cancel refunds, `0..=100`.
    /// Default 0: the deposit is kept.
    #[serde(default)]
    pub late_cancel_refund_percent: u8,
}

const fn default_full_refund_notice_secs() -> u64 {
    DEFAULT_DEPOSIT_FULL_REFUND_NOTICE_SECS
}

impl Default for DepositRefundRule {
    fn default() -> Self {
        Self {
            full_refund_notice_secs: DEFAULT_DEPOSIT_FULL_REFUND_NOTICE_SECS,
            late_cancel_refund_percent: 0,
        }
    }
}

impl DepositTerms {
    /// The one defect table for deposit terms, read by the configuration's
    /// own table and by the publication card check. `None` means usable.
    pub(crate) fn defect(&self) -> Option<&'static str> {
        if self.amount_minor == 0 || self.amount_minor > MAX_DEPOSIT_AMOUNT_MINOR {
            return Some(
                "booking deposit amount_minor must be 1 to 99999999 in the currency's smallest unit",
            );
        }
        if self.currency.len() != 3 || !self.currency.bytes().all(|b| b.is_ascii_lowercase()) {
            return Some("booking deposit currency must be three lowercase ISO 4217 letters");
        }
        if self.refund.full_refund_notice_secs > MAX_BOOKING_WINDOW_SECS {
            return Some("booking deposit full_refund_notice_secs must be at most 366 days");
        }
        if self.refund.late_cancel_refund_percent > 100 {
            return Some("booking deposit late_cancel_refund_percent must be 0 to 100");
        }
        None
    }

    /// Validates the terms on their own.
    ///
    /// # Errors
    ///
    /// [`BookingError::InvalidConfig`] naming the first defect found.
    pub fn validate(&self) -> Result<(), BookingError> {
        self.defect().map_or(Ok(()), |reason| {
            Err(BookingError::InvalidConfig(reason.to_owned()))
        })
    }

    /// What the visitor's own cancel at `cancelled_at` of a booking that
    /// starts at `start_utc` refunds, in the currency's smallest unit: the
    /// whole deposit when the cancel comes at least
    /// [`DepositRefundRule::full_refund_notice_secs`] before the start, and
    /// otherwise [`DepositRefundRule::late_cancel_refund_percent`] of it,
    /// rounded down. A cancel at or after the start is a late one.
    #[must_use]
    pub fn visitor_cancel_refund_minor(&self, start_utc: u64, cancelled_at: u64) -> u64 {
        let notice = self.refund.full_refund_notice_secs;
        if cancelled_at < start_utc && start_utc - cancelled_at >= notice {
            return self.amount_minor;
        }
        let percent = u128::from(self.refund.late_cancel_refund_percent.min(100));
        // The share is at most the amount, so it always fits back in u64.
        u64::try_from(u128::from(self.amount_minor) * percent / 100).unwrap_or(self.amount_minor)
    }
}
