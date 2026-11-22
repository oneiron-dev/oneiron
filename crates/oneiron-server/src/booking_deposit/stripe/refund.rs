//! The Refund fields a deposit reads from Stripe, and what a payment's
//! refunds answer for the refund a settle row owes.

use std::collections::BTreeMap;

use oneiron::booking::lifecycle::DepositProviderFailure;
use serde::Deserialize;

/// The Refund fields a deposit reads.
#[derive(Deserialize)]
pub(super) struct RefundView {
    pub(super) id: String,
    pub(super) amount: u64,
    /// `pending`, `requires_action`, `succeeded`, `failed` or `canceled`.
    pub(super) status: String,
    #[serde(default)]
    pub(super) metadata: BTreeMap<String, String>,
}

/// One page of a PaymentIntent's refunds.
#[derive(Deserialize)]
pub(super) struct RefundList {
    pub(super) data: Vec<RefundView>,
    /// Whether more refunds follow the last one on this page. Stripe always
    /// says; a page that does not is refused, so a cut list is never read as
    /// the whole list (Sol blind review of #9862, round 2).
    pub(super) has_more: bool,
}

impl RefundView {
    /// What the deposit records of this refund: its amount once it
    /// succeeded; pending while Stripe still holds it; ended unpaid once it
    /// failed or was cancelled, which leaves the refund owed, its settle row
    /// asking again hourly, and the owner's card offering to ask Stripe
    /// again under a new key (FIX [BK-DEPOSIT-FAILED-REFUND-SURFACE]); a
    /// refusal on a status Stripe never documented.
    fn settled_amount(&self) -> Result<u64, DepositProviderFailure> {
        match self.status.as_str() {
            "succeeded" => Ok(self.amount),
            "pending" | "requires_action" => Err(DepositProviderFailure::RefundHeld {
                reason: format!("Stripe holds refund {} {}", self.id, self.status),
            }),
            _ if self.ended_unpaid() => Err(DepositProviderFailure::RefundEndedUnpaid {
                reason: format!("Stripe's refund {} is {}", self.id, self.status),
                part_refunded_by_hand: false,
            }),
            status => Err(DepositProviderFailure::Permanent(format!(
                "Stripe's refund {} is {status}",
                self.id
            ))),
        }
    }

    /// Whether Stripe ended this refund with nothing paid back.
    pub(super) fn ended_unpaid(&self) -> bool {
        matches!(self.status.as_str(), "failed" | "canceled")
    }
}

/// What a payment's refunds answer for the refund a settle row owes.
pub(super) enum OwedRefund {
    /// The refund made under the row's own key: the one found, or a new one.
    Keyed(RefundView),
    /// The payment holds refunds made under no settle key (a person's, in the
    /// Stripe dashboard), and none under the row's that pays or may still
    /// pay: what of them succeeded, and what Stripe still holds. The row
    /// asked for no refund in this pass.
    MadeElsewhere { succeeded: u64, held: u64 },
    /// The refund under the row's own key, or under a key the same refund
    /// was asked under before the owner asked again, ended unpaid, and
    /// refunds made under no settle key cover only a part of what is owed:
    /// the row asked for no refund, and only a hand refund pays the rest
    /// (review rounds 1 and 2 of #10149).
    EndedUnpaidPartRefundedByHand(RefundView),
    /// No refund is made: the payment holds none under the row's own key and
    /// none made under no settle key. A find answers it
    /// (FIX [BK-DEPOSIT-FAILED-REFUND-MARK-PAID]), and so does a row whose
    /// refund the deposit no longer lets Stripe make (review round 2 of
    /// #10267); any other row then makes the refund.
    NotMade,
}

impl OwedRefund {
    /// What the deposit records of the `owed` refund. A refund under the
    /// row's key answers for itself. Refunds made elsewhere stand as the
    /// deposit's refund once they have paid back at least what is owed, and
    /// the deposit records what was owed. While Stripe still holds a part of
    /// that, the answer is that Stripe holds the refund. Short of it the row adds nothing: the
    /// refund stays owed, on the owner's card with what is missing, until the
    /// owner refunds the rest by hand.
    pub(super) fn settled_amount(&self, owed: u64) -> Result<u64, DepositProviderFailure> {
        match self {
            Self::Keyed(refund) => refund.settled_amount(),
            Self::NotMade => Ok(0),
            Self::EndedUnpaidPartRefundedByHand(refund) => {
                Err(DepositProviderFailure::RefundEndedUnpaid {
                    reason: format!(
                        "Stripe's refund {} is {}, and refunds made by hand cover only part of \
                         the {owed} owed",
                        refund.id, refund.status
                    ),
                    part_refunded_by_hand: true,
                })
            }
            Self::MadeElsewhere { succeeded, .. } if *succeeded >= owed => Ok(owed),
            Self::MadeElsewhere { succeeded, held } => {
                let paid_or_held = succeeded.saturating_add(*held);
                if paid_or_held >= owed {
                    Err(DepositProviderFailure::RefundHeld {
                        reason: format!(
                            "Stripe holds a refund made outside the deposit: {succeeded} of the \
                             {owed} owed is refunded and {held} is pending"
                        ),
                    })
                } else {
                    Err(DepositProviderFailure::PartRefundedByHand {
                        reason: format!(
                            "the payment holds a refund made outside the deposit: \
                             {paid_or_held} of the {owed} owed is refunded or pending, and the \
                             missing {} is not refunded here; refund it by hand",
                            owed.saturating_sub(paid_or_held)
                        ),
                    })
                }
            }
        }
    }

    /// What a find of a refund the owner marked refunded outside Stripe
    /// answers for the `owed` refund (BK-DEPOSIT-MARK-PAID-STRIPE-HOLDS-REFUND
    /// = A): a refund Stripe paid or still holds answers as for a refund;
    /// one that ended with nothing paid back, refunds made by hand short of
    /// what is owed, and none at all answer 0, so the deposit settles
    /// refunded outside Stripe.
    pub(super) fn found_amount(&self, owed: u64) -> Result<u64, DepositProviderFailure> {
        match self {
            Self::Keyed(refund) if refund.ended_unpaid() => Ok(0),
            Self::EndedUnpaidPartRefundedByHand(_) | Self::NotMade => Ok(0),
            Self::MadeElsewhere { succeeded, held } if succeeded.saturating_add(*held) < owed => {
                Ok(0)
            }
            _ => self.settled_amount(owed),
        }
    }
}
