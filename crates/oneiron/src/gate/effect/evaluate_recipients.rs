use super::*;

/// Whether `effect`'s send, judged with its own counterparty, takes mail's
/// one-send operation: a native-mail cold send or a member-mailbox send.
/// Read with the counterparty's contact facts, as the evaluation reads them.
pub(super) fn mail_once_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    override_now: Option<u64>,
) -> Result<bool> {
    let (hydrated, _, _) =
        hydrate_external_effect_contact_at(store, txn, effect, policy, override_now)?;
    Ok(
        crate::channel_identity_provider::native_mail::native_mail_cold_send_in_txn(
            store, txn, &hydrated, policy,
        )? || crate::channel_identity_provider::member_mail::member_mail_send_in_txn(
            store, txn, &hydrated,
        )?,
    )
}

impl ExternalEffectJudgment {
    /// Folds `judged`, the same message judged with another of its
    /// recipients as the counterparty, into this, its first recipient's
    /// (fix list row 17645). The decision is the more restrictive. Every
    /// recipient was judged against the one message operation, so a press
    /// either is found for all of them or for none; one found apart is no
    /// press on this message. A recipient's envelope slot, or its place in a
    /// full window's line, is the message's, and the standing grant that
    /// released a recipient is touched as used with the message's Allow.
    pub(super) fn fold_recipient(&mut self, judged: Self) -> Result<()> {
        if self.approve_once != judged.approve_once {
            return Err(crate::error::Error::InvariantViolation(
                "one message's recipients found different presses",
            ));
        }
        if outcome_restriction(judged.decision.outcome())
            > outcome_restriction(self.decision.outcome())
        {
            self.decision = judged.decision;
        }
        // An owner press releases the message only where it releases every
        // recipient (FIX 22102).
        self.press_supplies_authority &= judged.press_supplies_authority;
        if self.envelope_reservation.is_none() {
            self.envelope_reservation = judged.envelope_reservation;
        }
        if self.envelope_wait.is_none() {
            self.envelope_wait = judged.envelope_wait;
        }
        if let Some(grant) = judged.matched_grant
            && self
                .matched_grant
                .as_ref()
                .is_none_or(|matched| matched.grant_ref() != grant.grant_ref())
            && !self
                .recipient_grants
                .iter()
                .any(|recorded| recorded.grant_ref() == grant.grant_ref())
        {
            self.recipient_grants.push(grant);
        }
        Ok(())
    }
}

/// How far `outcome` restricts an effect: a denial most, then a hold.
const fn outcome_restriction(outcome: GateOutcome) -> u8 {
    match outcome {
        GateOutcome::Allow => 0,
        GateOutcome::Pending => 1,
        GateOutcome::Deny => 2,
    }
}
