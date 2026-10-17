//! Counterparty hydration plus send-override and do-not-contact fold.

use crate::comm::SendOverrideMatch;
use crate::counterparty_contact::{
    CounterpartyContactStatus, CounterpartyFirstTouch, normalize_channel_class,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::input::{ExternalEffectGateInput, ExternalEffectPolicyRisk};
use crate::store::Store;

/// Receipt reason for a deny whose only restrictive source is a CA-01
/// `comm.do_not_contact` head. Inside `store.rs`'s closed `counterparty_*`
/// receipt-reason family.
const COUNTERPARTY_OPT_OUT_DO_NOT_CONTACT_RECEIPT_REASON: &str =
    "counterparty_opt_out_do_not_contact";

/// Receipt reason for a hold whose restrictive source is an owner-revoked
/// `COUNTERPARTY_CONTACT` row. Same closed `counterparty_*` family.
const COUNTERPARTY_CONTACT_REVOKED_RECEIPT_REASON: &str = "counterparty_contact_revoked";

/// Hydrates the counterparty consent facts the external-effect door decides on.
///
/// ONE-1868: `counterparty` is the ONLY required input. The lookup key is
/// `(party_ref, channel_class)` per ARCH-0057 §3, and `channel_identity_ref` is
/// ENRICHMENT that may add candidates — its absence can never return early,
/// because every shipping constructor leaves it `None` and the legal-class hard
/// deny below it was therefore unreachable.
///
/// Every restrictive source is OR-folded: COUNTERPARTY_CONTACT records AND CA-01's
/// `comm.do_not_contact` heads. No leg may clear suppression another leg
/// established.
///
/// ONE-1752 adds ONE read and no new suppression source: once the fold has
/// decided the counterparty is opted out, the owner's `comm.send_override`
/// heads are read on THIS transaction and returned BESIDE the input.
/// [`ExternalEffectGateInput`] stays byte-unchanged — an override is never
/// something a caller may assert — so the match travels back as its own value
/// and the single caller writes it onto the gate-internal context. Whether a
/// matching contact is owner-revoked travels back the same way.
pub(crate) fn hydrate_external_effect_contact(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &crate::gate::PolicyManifestResolution,
) -> Result<(ExternalEffectGateInput, Option<SendOverrideMatch>, bool)> {
    let mut hydrated = effect.clone();
    let Some(party_ref) = effect.counterparty.as_deref() else {
        return Ok((hydrated, None, false));
    };

    let channel_class = normalize_channel_class(&effect.channel);
    let mut any_revoked = false;
    for record in crate::counterparty_contact::counterparty_contacts_for_send_in_claims_in_txn(
        store,
        txn,
        party_ref,
        &channel_class,
    )? {
        hydrated.counterparty_first_touch = hydrated
            .counterparty_first_touch
            .or(Some(record.first_touch));
        if record.first_touch == CounterpartyFirstTouch::Public
            && hydrated.policy_risk == ExternalEffectPolicyRisk::Normal
        {
            hydrated.policy_risk = ExternalEffectPolicyRisk::HoldToProposal;
        }
        // An owner-revoked contact is unreachable: it suppresses the send like
        // an opt-out, under its own reason, and an active sibling row never
        // clears it.
        let revoked = record.status == CounterpartyContactStatus::Revoked;
        any_revoked |= revoked;
        hydrated.counterparty_opted_out |= record.is_opted_out() || revoked;
        if hydrated.counterparty_opt_out_receipt_reason.is_none() {
            hydrated.counterparty_opt_out_receipt_reason = record
                .opt_out
                .map(crate::counterparty_contact::CounterpartyOptOut::receipt_reason)
                .or_else(|| revoked.then_some(COUNTERPARTY_CONTACT_REVOKED_RECEIPT_REASON));
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

    // Every PERSON that carries the counterparty's key, read once for both
    // comm legs: the node-local party shortcut would fail open.
    let persons = crate::campaign::claims::do_not_contact_subjects_in_txn(store, txn, party_ref)?;
    fold_matching_comm_do_not_contact_heads(store, txn, &persons, &channel_class, &mut hydrated)?;
    fold_comm_stop(
        store,
        txn,
        &persons,
        party_ref,
        &channel_class,
        &mut hydrated,
    )?;
    // A send override answers the counterparty's opt-out. The owner's own
    // revocation is not an opt-out, so no override lifts it (nor does the
    // opt-out posture; see the evaluator).
    let send_override = if hydrated.counterparty_opted_out && !any_revoked {
        counterparty_send_override_in_txn(
            store,
            txn,
            party_ref,
            &channel_class,
            hydrated.send_ref.as_deref(),
        )?
    } else {
        // Nothing to override. The token names the DECISION SOURCE of an
        // opt-out fall-through, so an unsuppressed send must not carry one.
        None
    };
    Ok((hydrated, send_override, any_revoked))
}

/// The owner's `comm.send_override` head for this send, read on the caller's
/// transaction.
///
/// Expiry is measured on the engine's trusted clock, never a caller timestamp:
/// a one-shot override is expiry-bound at mint, and letting the requester
/// supply "now" would hand them the lifetime too. A comm-side failure is
/// propagated, never swallowed — an unreadable override head means the send
/// holds, exactly like no override at all, and never becomes a silent allow.
pub(crate) fn counterparty_send_override_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    send_ref: Option<&str>,
) -> Result<Option<SendOverrideMatch>> {
    let Some(party) = comm_result(crate::comm::resolve_party_ref_from_store_in_txn(
        store, txn, party_ref,
    ))?
    else {
        return Ok(None);
    };
    comm_result(crate::comm::send_override_for_send_in_txn(
        store,
        txn,
        &party,
        channel_class,
        send_ref,
        store.clock.now_recorded_at(),
    ))
}

/// Lowers a comm-family read failure into the gate's error type. An engine
/// error travels unchanged; a comm-shaped one (an undecodable head) becomes a
/// corrupted-index refusal rather than an answer.
fn comm_result<T>(result: crate::comm::CommResult<T>) -> Result<T> {
    result.map_err(|error| match error {
        crate::comm::CommError::Engine(error) => error,
        _ => Error::CorruptedIndex("comm send override head"),
    })
}

/// OR-folds CA-01's `comm.do_not_contact` heads into the hydrated effect.
///
/// The predicate, the value codec, and the restrictive-wins semantics
/// (`Proposed` is effective; staleness never clears; only an authorized clear
/// stamp removes a head) are CA-01's — imported, never redefined here. The fold
/// is monotonic: it can only ADD suppression.
fn fold_matching_comm_do_not_contact_heads(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    persons: &[EntityId],
    channel_class: &str,
    hydrated: &mut ExternalEffectGateInput,
) -> Result<()> {
    if !crate::campaign::claims::subjects_do_not_contact_in_txn(
        store,
        txn,
        persons,
        Some(channel_class),
        &hydrated.verb,
    )? {
        return Ok(());
    }
    hydrated.counterparty_opted_out = true;
    // A COUNTERPARTY_CONTACT reason already folded above wins; otherwise the deny would
    // reach the receipt with no reason at all.
    if hydrated.counterparty_opt_out_receipt_reason.is_none() {
        hydrated.counterparty_opt_out_receipt_reason =
            Some(COUNTERPARTY_OPT_OUT_DO_NOT_CONTACT_RECEIPT_REASON);
    }
    Ok(())
}

/// OR-folds the counterparty's standing comm opt-out (F06): a STOP's
/// `comm.opt_out` head and a party-wide one, which the contact rows above only
/// cache and a supported drop removes (R2-F5), and a STOP this replica has not
/// projected yet. Each holds the send as the contact row it projects to does,
/// so an owner override or posture answers it the same way. Monotonic, like
/// every leg here.
fn fold_comm_stop(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    persons: &[EntityId],
    party_ref: &str,
    channel_class: &str,
    hydrated: &mut ExternalEffectGateInput,
) -> Result<()> {
    // A send already held, with its reason, gains nothing here.
    if hydrated.counterparty_opted_out && hydrated.counterparty_opt_out_receipt_reason.is_some() {
        return Ok(());
    }
    let Some(reason) = comm_result(crate::comm::send_stop_reason_in_txn(
        store,
        txn,
        persons,
        party_ref,
        channel_class,
    ))?
    else {
        return Ok(());
    };
    hydrated.counterparty_opted_out = true;
    if hydrated.counterparty_opt_out_receipt_reason.is_none() {
        hydrated.counterparty_opt_out_receipt_reason = Some(reason);
    }
    Ok(())
}
