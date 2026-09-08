//! Counterparty hydration plus send-override and do-not-contact fold.

use crate::comm::SendOverrideMatch;
use crate::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyFirstTouch, counterparty_contact_index_key,
    counterparty_contact_matches_channel_class, counterparty_contacts_by_party_channel,
    counterparty_contacts_by_party_full_scan, decode_counterparty_contact_index_value,
    normalize_channel_class, read_counterparty_contact_in_txn,
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
/// and the single caller writes it onto the gate-internal context.
pub(super) fn hydrate_external_effect_contact(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
) -> Result<(ExternalEffectGateInput, Option<SendOverrideMatch>)> {
    let mut hydrated = effect.clone();
    let Some(party_ref) = effect.counterparty.as_deref() else {
        return Ok((hydrated, None));
    };

    let channel_class = normalize_channel_class(&effect.channel);
    for record in counterparty_contacts_for_send(
        store,
        txn,
        party_ref,
        &channel_class,
        effect.channel_identity_ref.as_ref(),
    )? {
        hydrated.counterparty_first_touch = hydrated
            .counterparty_first_touch
            .or(Some(record.first_touch));
        if record.first_touch == CounterpartyFirstTouch::Public
            && hydrated.policy_risk == ExternalEffectPolicyRisk::Normal
        {
            hydrated.policy_risk = ExternalEffectPolicyRisk::HoldToProposal;
        }
        hydrated.counterparty_opted_out |= record.is_opted_out();
        if record.is_opted_out() && hydrated.counterparty_opt_out_receipt_reason.is_none() {
            hydrated.counterparty_opt_out_receipt_reason = record
                .opt_out
                .map(crate::counterparty_contact::CounterpartyOptOut::receipt_reason);
        }
    }

    fold_matching_comm_do_not_contact_heads(store, txn, party_ref, &channel_class, &mut hydrated)?;
    let send_override = if hydrated.counterparty_opted_out {
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
    Ok((hydrated, send_override))
}

/// The owner's `comm.send_override` head for this send, read on the caller's
/// transaction.
///
/// Expiry is measured on the engine's trusted clock, never a caller timestamp:
/// a one-shot override is expiry-bound at mint, and letting the requester
/// supply "now" would hand them the lifetime too. A comm-side failure is
/// propagated, never swallowed — an unreadable override head means the send
/// holds, exactly like no override at all, and never becomes a silent allow.
fn counterparty_send_override_in_txn(
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
        crate::unix_seconds_now(),
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

/// Every contact record that participates in this send's restrictive aggregate.
///
/// Three CANDIDATE sources, de-duplicated by contact ref and ordered by it so
/// the folded first-touch and receipt reason are deterministic:
///
/// 1. the identity-independent `(party_ref, channel_class)` index;
/// 2. the legacy identity+counterparty index, when an identity is known — it may
///    only ADD candidates;
/// 3. an unbounded COUNTERPARTY_CONTACT scan, which is MANDATORY: the party-channel index
///    cannot prove its own completeness at HEAD, and a bounded fallback that
///    missed one opted-out row would answer a false "no".
///
/// Channel scope is then applied ONCE, here, to the merged set. Sources find
/// rows for the party; this predicate decides which are in scope for the class.
/// Keeping it at the single fold point is what makes `channel_identity_ref`
/// enrichment rather than a verdict input: source 2 is keyed by identity alone,
/// so a stale or explicitly-pinned cross-class identity would otherwise drag a
/// foreign-channel opt-out into the aggregate and let enrichment move the
/// verdict. A per-source predicate is one forgotten call from that bug; this is
/// zero.
fn counterparty_contacts_for_send(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    channel_identity_ref: Option<&EntityId>,
) -> Result<Vec<CounterpartyContactRecord>> {
    let mut candidates =
        counterparty_contacts_by_party_channel(store, txn, party_ref, channel_class)?;
    if let Some(identity_ref) = channel_identity_ref
        && let Some(hit) =
            counterparty_contact_by_identity_index(store, txn, identity_ref, party_ref)?
    {
        candidates.push(hit);
    }
    candidates.extend(counterparty_contacts_by_party_full_scan(
        store, txn, party_ref,
    )?);

    candidates.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    candidates.dedup_by(|(left, _), (right, _)| left == right);

    let mut records = Vec::with_capacity(candidates.len());
    for (_, record) in candidates {
        if counterparty_contact_matches_channel_class(store, txn, &record, channel_class)? {
            records.push(record);
        }
    }
    Ok(records)
}

/// Legacy identity+counterparty index hit, when a channel identity is known.
fn counterparty_contact_by_identity_index(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: &EntityId,
    counterparty: &str,
) -> Result<Option<(EntityId, CounterpartyContactRecord)>> {
    let key = counterparty_contact_index_key(identity_ref, counterparty)?;
    let Some(raw_id) = store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    let id = decode_counterparty_contact_index_value(&raw_id)?;
    let Some(record) = read_counterparty_contact_in_txn(store, txn, &id)? else {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index entity row",
        ));
    };
    if !record.matches_counterparty(identity_ref, counterparty) {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index assignment",
        ));
    }
    Ok(Some((id, record)))
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
    party_ref: &str,
    channel_class: &str,
    hydrated: &mut ExternalEffectGateInput,
) -> Result<()> {
    if !crate::campaign::claims::counterparty_do_not_contact_in_txn(
        store,
        txn,
        party_ref,
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
