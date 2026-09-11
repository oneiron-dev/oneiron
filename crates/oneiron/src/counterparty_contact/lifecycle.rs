//! Counterparty contact cache rematerialization, claim supersession, and opt-out folding.

use super::codec::{
    counterparty_contact_body_key, decode_counterparty_contact_value,
    encode_counterparty_contact_body,
};
use super::storage::{
    counterparty_contact_channel_class, counterparty_contact_index_key_for_record,
    counterparty_contact_matches_channel_class, counterparty_contacts_by_party_full_scan,
    read_counterparty_contact_in_txn, remove_counterparty_contact_party_channel_index,
};
use super::types::{
    COUNTERPARTY_CONTACT_CLAIM_PREDICATES, COUNTERPARTY_CONTACT_SCHEMA_VERSION,
    CounterpartyContactRecord, CounterpartyOptOut, CounterpartyOptOutReason, KEY_SCHEMA_VERSION,
};
use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, RecordError, Result};
use crate::temporal::TimeRange;
use rmpv::Value;

/// Closes `old_id` in favour of `new_id` for one claim whose FAMILY DOOR owns
/// the transition, inside the caller's write transaction.
///
/// The transition itself is the ordinary ARCH-0003 one — the old body is closed
/// `superseded` with `valid_to = now`, its envelope end is refreshed, and the
/// `supersedes` edge is written from the replacement — on the engine-owned
/// setting, for the same reason the family's head writer uses it: the door
/// already decided and validated this write, and a criticality ladder that
/// could REFUSE the close would leave the family with two live heads for one
/// predicate, which is the one state its readers must never see. The general
/// public door (`Vault::supersede_claim_in_txn`) remains the door for claims
/// nobody's family owns, and the reserved door stays scoped to the engine's own
/// `skill.*`/`actor.*` namespaces.
pub(crate) fn supersede_family_owned_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    new_id: &EntityId,
    old_id: &EntityId,
    now: u64,
) -> Result<()> {
    if new_id == old_id {
        return Err(Error::Claim(ClaimError::ClaimSelfSupersession));
    }
    let raw = vault
        .store
        .entities
        .get(&*wtxn, old_id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    let mut body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::InvalidClaimBody(
            "family-owned supersession target is not active",
        ));
    }
    body.lifecycle = ClaimLifecycleStatus::Superseded;
    body.valid_to = Some(now);
    let data = crate::claim::encode_claim_body(&body)?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![
            BatchOp::Put {
                id: *old_id,
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: header.occurred_start,
                    end: now.max(header.occurred_start),
                },
                learned_at: header.learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
            BatchOp::EdgeWithCreatedAt {
                src: *new_id,
                kind: crate::edge::EdgeKind::Supersedes,
                tgt: *old_id,
                weight: crate::vault::SUPERSEDES_DEFAULT_WEIGHT,
                created_at: now,
                vad: crate::affect::Vad::NEUTRAL,
                provenance: None,
            },
        ],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )
}

/// Re-derives the type-132 cache row for `contact_id` from claims, inside the
/// caller's write transaction (ONE-1752).
///
/// This is the SOLE rebuild engine for the type-132 row, and the only
/// production caller of `apply_counterparty_contact_body`. Every writer of
/// contact or opt-out truth supersedes claim heads and then calls this in the
/// SAME transaction, so the direction of truth is always claims → cache and a
/// reader can never observe the two disagreeing.
///
/// The rebuilt opt-out is a RESTRICTIVE OR-fold over two sources: this
/// contact's own `counterparty_contact.opt_out` head, and every live
/// `comm.opt_out` head for the resolved party that COVERS this contact's
/// channel class — party-wide heads cover all of them, a channel-scoped STOP
/// head covers only its own class, and a contact with no resolvable class is
/// covered by every head. If any covering source stands, the rebuilt record is
/// opted out. Reason and timestamp come from the newest standing source by
/// `issued_at`; on a tie the contact-family head wins as the more specific one.
///
/// Because the scope decision lives in the fold rather than in each caller's
/// choice of which contacts to re-derive, ANY writer may re-derive ANY row of
/// the party without a foreign-channel head bleeding into it.
///
/// The row is rebuilt DETERMINISTICALLY from heads — `now` stamps the envelope,
/// never the body — so re-running this on unchanged claims reproduces
/// byte-identical `encode_counterparty_contact_body` output.
pub(crate) fn rematerialize_contact_cache_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    contact_id: &EntityId,
    now: u64,
) -> Result<()> {
    let mut record = counterparty_contact_record_from_claims_in_txn(vault, &*wtxn, contact_id)?;
    fold_party_opt_out_heads_in_txn(vault, &*wtxn, &mut record)?;
    let data = encode_counterparty_contact_body(&record)?;
    vault.apply_counterparty_contact_body(wtxn, contact_id, now, data)
}

/// Re-derives the type-132 cache for EVERY contact of `party_ref` a head on
/// `channel_class` can reach, inside the caller's write transaction (ONE-1752).
///
/// `None` is the party-wide key: every contact of the party, whatever channel
/// it sends on. A named class re-derives the contacts that class covers —
/// including any whose identity resolves to no class, because unknown is
/// covered by every head and its row must therefore follow every head.
///
/// A writer that moved PARTY-scoped opt-out truth must use this rather than
/// re-deriving the one contact it was handed: a party-wide head that left a
/// sibling contact's row not-opted-out would leave the gate reading a stale
/// "no" for a party that said stop (fail-open). The enumeration is the same
/// mandatory full scan the send-time aggregate uses — the party-channel index
/// cannot prove its own completeness at HEAD, and a bounded lookup that missed
/// one row would reintroduce exactly that hole. Which heads then apply to each
/// row stays the fold's decision, so re-deriving a row is never a suppression
/// source of its own.
pub(crate) fn rematerialize_party_contact_cache_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: &str,
    channel_class: Option<&str>,
    now: u64,
) -> Result<()> {
    let mut targets = Vec::new();
    for (contact_id, record) in
        counterparty_contacts_by_party_full_scan(&vault.store, &*wtxn, party_ref)?
    {
        if let Some(channel_class) = channel_class
            && !counterparty_contact_matches_channel_class(
                &vault.store,
                &*wtxn,
                &record,
                channel_class,
            )?
        {
            continue;
        }
        targets.push(contact_id);
    }
    for contact_id in targets {
        rematerialize_contact_cache_in_txn(vault, wtxn, &contact_id, now)?;
    }
    Ok(())
}

/// Rebuilds the record a contact's `counterparty_contact.*` heads describe.
///
/// Every predicate in the family must have exactly one head that is ACTIVE and
/// not stale — approval rung is deliberately not filtered on, because a head
/// the write gate downgraded to `proposed` is still the truth the owner's
/// writer recorded, and dropping it would silently lose opt-out state. A
/// missing or doubled head is a corrupted projection and fails closed.
pub(super) fn counterparty_contact_record_from_claims_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    contact_id: &EntityId,
) -> Result<CounterpartyContactRecord> {
    let mut heads: Vec<Option<Value>> = vec![None; COUNTERPARTY_CONTACT_CLAIM_PREDICATES.len()];
    for claim_id in vault.claims_for_subject_in_txn(rtxn, contact_id)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        let Some(index) = COUNTERPARTY_CONTACT_CLAIM_PREDICATES
            .iter()
            .position(|predicate| *predicate == body.predicate)
        else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active || body.stale {
            continue;
        }
        if heads[index].is_some() {
            return Err(Error::Record(RecordError::InvalidCounterpartyContactBody(
                "counterparty contact claim family has two live heads for one predicate",
            )));
        }
        heads[index] = Some(body.value);
    }

    let mut entries = vec![(
        Value::from(KEY_SCHEMA_VERSION),
        Value::from(COUNTERPARTY_CONTACT_SCHEMA_VERSION),
    )];
    for (index, predicate) in COUNTERPARTY_CONTACT_CLAIM_PREDICATES.iter().enumerate() {
        let value = heads[index].take().ok_or(Error::Record(
            RecordError::InvalidCounterpartyContactBody(
                "counterparty contact claim family is missing a live head",
            ),
        ))?;
        entries.push((Value::from(counterparty_contact_body_key(predicate)), value));
    }
    // Straight back through the canonical decoder, so the rebuilt record clears
    // exactly the validation a stored body clears.
    decode_counterparty_contact_value(&Value::Map(entries))
}

/// OR-folds every live `comm.opt_out` head for this record's party that COVERS
/// this record's channel class into it.
///
/// Monotonic: this can only ADD suppression, never clear what the contact's own
/// head established. An unknown comm reason token falls back to the contact
/// head's reason; when NEITHER source decodes, the fold fails closed rather
/// than dropping opt-out truth on the floor.
///
/// Reason and stamp come from the newest covering head by that head's OWN
/// `occurred_at` — the whole candidate set is ranked before anything is
/// written, so which receipt the row carries is a fact about when the party
/// spoke, never about the order claims came back in.
///
/// Channel scope is the head's, applied once here (ONE-1752): a party-wide head
/// covers every contact — the party said it to the owner, not to one mailbox —
/// and a channel-scoped STOP head covers only contacts on its own class, so an
/// email STOP can never suppress a telegram contact no matter which writer
/// re-derives the row. A contact whose identity resolves to no class is UNKNOWN,
/// and unknown matches EVERY head: the same CA-01 uncertainty rule
/// [`counterparty_contact_matches_channel_class`] states, resolved restrictively.
fn fold_party_opt_out_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    record: &mut CounterpartyContactRecord,
) -> Result<()> {
    let Some(party_ref) = crate::comm::resolve_party_ref_in_txn(vault, rtxn, &record.counterparty)
        .map_err(comm_fold_error)?
    else {
        return Ok(());
    };
    // Resolved ONCE: the class comes from the record's sending identity, which
    // no head in this loop can move.
    let contact_class = counterparty_contact_channel_class(&vault.store, rtxn, record)?;
    // Newest standing source wins, ranked on each head's OWN occurrence. The
    // contact's own head is the incumbent and keeps a tie, being the more
    // specific statement about this exact contact.
    //
    // The stamp compared here is never the clamped one: the clamp below is a
    // storage invariant, not a statement about when the party spoke. Ranking
    // against an already-clamped stamp would let the FIRST covering head that
    // predates `created_at` shadow every later one — they all lose to the
    // inflated `created_at` — and the surviving reason/receipt would fall out
    // of claim iteration order rather than out of when the party spoke.
    let mut newest = record.opt_out.map(|opt_out| opt_out.recorded_at);
    let mut winner = None;
    for head in crate::comm::standing_opt_out_heads_in_txn(vault, rtxn, party_ref)
        .map_err(comm_fold_error)?
    {
        if let Some(contact_class) = contact_class.as_deref()
            && !head.matches_channel(contact_class)
        {
            continue;
        }
        if newest.is_some_and(|newest| head.occurred_at <= newest) {
            continue;
        }
        newest = Some(head.occurred_at);
        winner = Some(head);
    }
    let Some(head) = winner else {
        return Ok(());
    };
    let reason = match CounterpartyOptOutReason::from_receipt_reason(&head.reason) {
        Some(reason) => reason,
        None => match record.opt_out {
            Some(opt_out) => opt_out.reason,
            None => {
                return Err(Error::Record(RecordError::InvalidCounterpartyContactBody(
                    "comm.opt_out reason is outside the receipt vocabulary",
                )));
            }
        },
    };
    // Clamped ONCE, on the winner only, into the record's own window: the head
    // is the SOURCE of the opt-out, and the record's invariants are what a
    // stored body must satisfy (CID-7: `recorded_at >= created_at`).
    let recorded_at = head.occurred_at.max(record.created_at);
    record.opt_out = Some(CounterpartyOptOut::new(reason, recorded_at));
    record.updated_at = record.updated_at.max(recorded_at);
    Ok(())
}

/// Lowers a comm-family read failure into the contact error type. An engine
/// error travels unchanged; a comm-shaped one becomes the contact family's own
/// fail-closed class.
pub(super) fn comm_fold_error(error: crate::comm::CommError) -> Error {
    match error {
        crate::comm::CommError::Engine(error) => error,
        _ => Error::Record(RecordError::InvalidCounterpartyContactBody(
            "comm opt-out head failed to decode",
        )),
    }
}

/// Re-derives the type-132 cache row for `contact_id` from claims, in its own
/// write transaction, and returns the rebuilt record. The ops path, and the
/// proof that the cache is reproducible from claims alone.
pub fn rematerialize_contact_cache(
    vault: &Vault,
    contact_id: &EntityId,
) -> Result<CounterpartyContactRecord> {
    let mut wtxn = vault.store.env.write_txn()?;
    let now = crate::unix_seconds_now();
    rematerialize_contact_cache_in_txn(vault, &mut wtxn, contact_id, now)?;
    let record = read_counterparty_contact_in_txn(&vault.store, &wtxn, contact_id)?
        .ok_or(Error::EntityNotFound)?;
    wtxn.commit()?;
    Ok(record)
}

/// Drops the type-132 CACHE row for `contact_id` and its lookup index entries.
///
/// It touches NO claim: the contact's `counterparty_contact.*` heads and the
/// party's `comm.opt_out` heads are the truth, and they are exactly what
/// [`rematerialize_contact_cache`] rebuilds the row from afterwards. This is
/// what makes type-132 a dial rather than a wall — dropping it loses nothing.
///
/// Both index legs go with the row: leaving either pointing at a row that no
/// longer exists would make the send-time aggregate REFUSE rather than answer,
/// and the rematerializer writes both back.
///
/// So do the engine's own type and temporal index rows, removed through the
/// same primitive the delete path uses and keyed off the stamps this row was
/// PUT with. Dropping is a cache operation, and a cache operation that left
/// time-range readers pointing at a vanished row — or that let each rebuild
/// leave one more dead timestamp behind for the same contact — would make the
/// row's absence observable, which is exactly what type-132-is-cache denies.
pub fn drop_contact_cache_row(vault: &Vault, contact_id: &EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let Some(record) = read_counterparty_contact_in_txn(&vault.store, &wtxn, contact_id)? else {
        return Ok(());
    };
    let header = {
        let raw = vault
            .store
            .entities
            .get(&wtxn, contact_id.as_bytes())?
            .ok_or(Error::CorruptedIndex("counterparty contact entity row"))?;
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?
    };
    let index_key = counterparty_contact_index_key_for_record(&record)?;
    vault.store.vault_meta.delete(&mut wtxn, &index_key)?;
    if let Some(channel_class) = counterparty_contact_channel_class(&vault.store, &wtxn, &record)? {
        remove_counterparty_contact_party_channel_index(
            &vault.store,
            &mut wtxn,
            &record.counterparty,
            &channel_class,
            *contact_id,
        )?;
    }
    crate::batch::delete_entity_index_rows(
        &vault.store,
        &mut wtxn,
        contact_id,
        header.entity_type,
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        header.learned_at,
    )?;
    vault
        .store
        .entities
        .delete(&mut wtxn, contact_id.as_bytes())?;
    wtxn.commit()?;
    Ok(())
}
