//! Counterparty hydration: the send gate's ask of the claims-read door.

use crate::claim::enforcement_read::{
    SendTarget, enforcement_heads_for_send_in_txn, send_override_head_in_txn,
};
use crate::counterparty_contact::{CounterpartyFirstTouch, normalize_channel_class};
use crate::error::Result;
use crate::gate::input::{ExternalEffectGateInput, ExternalEffectPolicyRisk};
use crate::store::Store;
use crate::write_envelope::communication::SendOverrideMatch;

/// Hydrates the counterparty consent facts the external-effect door decides on.
///
/// ONE-1868: `counterparty` is the ONLY required input. The lookup key is
/// `(party_ref, channel_class)` per ARCH-0057 §3, and `channel_identity_ref` is
/// ENRICHMENT that may add candidates — its absence can never return early,
/// because every shipping constructor leaves it `None` and the legal-class hard
/// deny below it was therefore unreachable.
///
/// ARCH-0057 §3 cutover: the restrictive sources are the claims-read door's
/// registry-selected enforcement heads ([`enforcement_heads_for_send_in_txn`]),
/// OR-folded: no head may clear suppression another established, and a
/// caller's own opt-out flag only adds. The contact family's own opt-out head
/// is no longer one of them. The contacts the door rebuilt from their claims
/// give the claim-backed `first_touch`.
///
/// ONE-1752 adds ONE read and no new suppression source: once the send is
/// held, the owner's `comm.send_override` heads are read on THIS transaction
/// and returned BESIDE the input. [`ExternalEffectGateInput`] stays
/// byte-unchanged — an override is never something a caller may assert — so
/// the match travels back as its own value and the single caller writes it
/// onto the gate-internal context. Whether a head no override lifts (an
/// owner-revoked contact) holds the send travels back the same way.
pub(crate) fn hydrate_external_effect_contact(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &crate::gate::PolicyManifestResolution,
) -> Result<(ExternalEffectGateInput, Option<SendOverrideMatch>, bool)> {
    hydrate_external_effect_contact_at(store, txn, effect, policy, None)
}

pub(crate) fn hydrate_external_effect_contact_at(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &crate::gate::PolicyManifestResolution,
    override_now: Option<u64>,
) -> Result<(ExternalEffectGateInput, Option<SendOverrideMatch>, bool)> {
    let mut hydrated = effect.clone();
    let Some(party_ref) = effect.counterparty.as_deref() else {
        return Ok((hydrated, None, false));
    };

    let channel_class = normalize_channel_class(&effect.channel);
    let enforcement = enforcement_heads_for_send_in_txn(
        store,
        txn,
        &SendTarget {
            party_ref,
            channel_class: &channel_class,
            verb: &effect.verb,
        },
    )?;
    for record in &enforcement.contacts {
        hydrated.counterparty_first_touch = hydrated
            .counterparty_first_touch
            .or(Some(record.first_touch));
        if record.first_touch == CounterpartyFirstTouch::Public
            && hydrated.policy_risk == ExternalEffectPolicyRisk::Normal
        {
            hydrated.policy_risk = ExternalEffectPolicyRisk::HoldToProposal;
        }
    }

    // A native-mail sender resolves the vault's recipient-class and initial
    // posture rows on this SAME Gate transaction as the CID-7 contact facts.
    // An absent/malformed policy keeps the send in the asking lane.
    let native_mail = if channel_class == "email" && effect.verb == "send" {
        effect.channel_identity_ref.map_or(Ok(false), |identity| {
            crate::channel_identity_provider::native_mail::is_native_mail_sender_in_txn(
                store, txn, identity,
            )
        })?
    } else {
        false
    };
    if native_mail {
        let mail = policy.native_mail_policy_for(
            effect.provenance.actor_entity_ref,
            effect.channel_identity_ref,
        );
        if mail
            .as_ref()
            .is_none_or(|row| !row.is_known(hydrated.counterparty_first_touch))
        {
            let risk = mail.as_ref().map_or(
                ExternalEffectPolicyRisk::HoldToProposal,
                crate::gate::mail_policy::MailPolicy::cold_risk,
            );
            if risk == ExternalEffectPolicyRisk::HoldToProposal {
                hydrated.policy_risk = risk;
            }
        }
    }

    let any_revoked = enforcement.revoked();
    if let Some(head) = enforcement.heads.first() {
        hydrated.counterparty_opted_out = true;
        // A reason the caller already carries wins; otherwise the hold would
        // reach the receipt with no reason at all.
        if hydrated.counterparty_opt_out_receipt_reason.is_none() {
            hydrated.counterparty_opt_out_receipt_reason = Some(head.receipt_reason);
        }
    }
    // A send override answers the counterparty's opt-out. The owner's own
    // revocation is not an opt-out, so no override lifts it (nor does the
    // opt-out posture; see the evaluator).
    let send_override = if hydrated.counterparty_opted_out && !any_revoked {
        send_override_head_in_txn(
            store,
            txn,
            party_ref,
            &channel_class,
            hydrated.send_ref.as_deref(),
            override_now,
        )?
    } else {
        // Nothing to override. The token names the DECISION SOURCE of an
        // opt-out fall-through, so an unsuppressed send must not carry one.
        None
    };
    Ok((hydrated, send_override, any_revoked))
}

/// The owner's `comm.send_override` head for this send, read on the caller's
/// transaction through the claims-read door, on the store clock
/// ([`send_override_head_in_txn`]).
pub(crate) fn counterparty_send_override_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    send_ref: Option<&str>,
) -> Result<Option<SendOverrideMatch>> {
    send_override_head_in_txn(store, txn, party_ref, channel_class, send_ref, None)
}
