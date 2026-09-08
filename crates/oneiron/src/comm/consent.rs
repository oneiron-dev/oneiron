//! Human consent gates, send overrides and standing opt-out folds.

use super::claims::{
    CommClaim, CommClaimValue, CommClearOptOutOutcome, CommError, CommResult,
    PREDICATE_COMM_OPT_OUT, PREDICATE_COMM_SEND_OVERRIDE, PREDICATE_COMM_THREAD_MEMBER,
    SendOverrideMatch, SendOverrideScope, validate_comm_claim_structure,
};
use super::parties::{
    active_comm_party_key_in_txn, resolve_or_create_party_in_txn, resolve_party,
    resolve_party_ref_in_txn,
};
use super::projection_writes::{
    build_contact_view_in_txn, count_comm_claims, matching_claims_in_txn,
    put_comm_claim_with_id_in_txn, put_engine_owned_comm_claim_in_txn, require_at_most_one,
};
use super::records::{
    CommEventKind, CommRecord, comm_records_in_txn, put_comm_record_in_txn, validate_channel_class,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimBody;
use crate::counterparty_contact::{
    CounterpartyOptOutReason, normalize_channel_class, rematerialize_contact_cache_in_txn,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::provenance::validate_actor_class;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::write_envelope::WriteActor;

/// The `comm.opt_out` reason vocabulary is the RECEIPT vocabulary
/// (`CounterpartyOptOutReason::receipt_reason`), never the `as_str()` one: the
/// landed heads carry these tokens, and swapping vocabularies would invalidate
/// them. Pinned to the enum's own const fn so the two can never drift.
pub(super) const OPT_OUT_REASON_STOP: &str = CounterpartyOptOutReason::Stop.receipt_reason();

const OPT_OUT_REASON_UNSUBSCRIBE: &str = CounterpartyOptOutReason::Unsubscribe.receipt_reason();

const OPT_OUT_REASON_BLOCK_OR_FRIEND_REMOVAL: &str =
    CounterpartyOptOutReason::BlockOrFriendRemoval.receipt_reason();

pub(super) const OPT_OUT_REASONS: [&str; 3] = [
    OPT_OUT_REASON_STOP,
    OPT_OUT_REASON_UNSUBSCRIBE,
    OPT_OUT_REASON_BLOCK_OR_FRIEND_REMOVAL,
];

/// Longest `send_ref` a one-shot override may bind.
pub(super) const MAX_SEND_REF_BYTES: usize = 256;

pub(super) const OPT_OUT_CLEAR_REASON: &str = "comm_opt_out_clear";

const OPT_OUT_CLEAR_APPROVED: &str = "comm_opt_out_clear_approved";

/// Counts active claims by the full `(predicate, party, channel_class)` key.
pub fn count_active_comm_claims(
    vault: &Vault,
    predicate: &str,
    party: &str,
    channel_class: &str,
) -> CommResult<usize> {
    count_comm_claims(vault, predicate, party, Some(channel_class), None, true)
}

/// Counts all claim history rows by the full `(predicate, party, channel_class)` key.
pub fn count_total_comm_claim_rows(
    vault: &Vault,
    predicate: &str,
    party: &str,
    channel_class: &str,
) -> CommResult<usize> {
    count_comm_claims(vault, predicate, party, Some(channel_class), None, false)
}

/// Counts active `comm.thread_member` claims by `(thread_ref, party)`.
pub fn count_active_thread_member_claims(
    vault: &Vault,
    thread_ref: &str,
    party: &str,
) -> CommResult<usize> {
    count_comm_claims(
        vault,
        PREDICATE_COMM_THREAD_MEMBER,
        party,
        None,
        Some(thread_ref),
        true,
    )
}

/// Counts all pending human-gate rows for communication widening transitions.
pub fn count_pending_comm_consent_gates(vault: &Vault) -> CommResult<usize> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(comm_records_in_txn(vault, &rtxn)?
        .into_iter()
        .filter(|(_, record)| matches!(record, CommRecord::Gate { pending: true, .. }))
        .count())
}

/// Requests human review to clear one active `comm.opt_out` claim.
pub fn request_opt_out_clear(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    created_at: u64,
) -> CommResult<CommClearOptOutOutcome> {
    validate_channel_class(channel_class).map_err(|_| CommError::InvalidRecord)?;
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Err(CommError::ActiveOptOutNotFound);
    };
    vault.try_with_write_txn(|wtxn| {
        let records = comm_records_in_txn(vault, &*wtxn)?;
        let active = matching_claims_in_txn(
            vault,
            &*wtxn,
            party_ref,
            PREDICATE_COMM_OPT_OUT,
            Some(channel_class),
            None,
            true,
        )?;
        require_at_most_one(&active)?;
        let Some((claim_ref, _)) = active.into_iter().next() else {
            return Err(CommError::ActiveOptOutNotFound);
        };
        let pending_count = records
            .iter()
            .filter(|(_, record)| {
                matches!(record, CommRecord::Gate {
                    party_ref: candidate_party,
                    channel_class: candidate_channel,
                    pending: true,
                    ..
                } if *candidate_party == party_ref && candidate_channel == channel_class)
            })
            .count();
        match pending_count {
            0 => {}
            1 => return Ok(CommClearOptOutOutcome::PendingHumanRuling),
            _ => return Err(CommError::InvalidRecord),
        }
        let gate = CommRecord::Gate {
            party_ref,
            channel_class: channel_class.to_owned(),
            claim_ref,
            created_at,
            pending: true,
        };
        put_comm_record_in_txn(vault, wtxn, EntityId::now(), &gate)?;
        Ok(CommClearOptOutOutcome::PendingHumanRuling)
    })
}

/// Applies a one-shot opt-out-clear ruling, accepting only a bound human actor.
pub fn approve_pending_opt_out_clear(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    actor: WriteActor,
    ruled_at: u64,
) -> CommResult<()> {
    enum ClearRuling {
        Cleared,
        NoActiveOptOut,
        Superseded,
    }

    let actor_ref = actor.entity_ref();
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Err(CommError::PendingGateNotFound);
    };
    let ruling = vault.try_with_write_txn(|wtxn| {
        // Authorize the approving actor from the write transaction's view so a
        // concurrent delete/recreate cannot leave the gate consumed under a
        // stale authorization decision (TOCTOU).
        let actor_entity_type = vault
            .store
            .entities
            .get(&*wtxn, actor_ref.as_bytes())?
            .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
            .ok_or(CommError::Engine(Error::EntityNotFound))?;
        validate_actor_class(actor_entity_type, actor.actor_class())?;
        if actor.actor_class() != EdgeActorClass::Human {
            return Err(CommError::HumanApprovalRequired);
        }
        let records = comm_records_in_txn(vault, &*wtxn)?;
        let mut gates = records.into_iter().filter(|(_, record)| {
            matches!(record, CommRecord::Gate {
                party_ref: candidate_party,
                channel_class: candidate_channel,
                pending: true,
                ..
            } if *candidate_party == party_ref && candidate_channel == channel_class)
        });
        let gate = gates.next();
        if gates.next().is_some() {
            return Err(CommError::InvalidRecord);
        }
        let Some((gate_id, gate)) = gate else {
            return Err(CommError::PendingGateNotFound);
        };
        let CommRecord::Gate {
            claim_ref,
            created_at,
            ..
        } = gate
        else {
            unreachable!("filtered to gate")
        };
        if ruled_at < created_at {
            return Err(CommError::RulingPredatesGate);
        }
        let active = matching_claims_in_txn(
            vault,
            &*wtxn,
            party_ref,
            PREDICATE_COMM_OPT_OUT,
            Some(channel_class),
            None,
            true,
        )?;
        require_at_most_one(&active)?;
        let live_claim = active.into_iter().next();
        // Fail-closed on a stale gate. The gate records a clear REQUEST;
        // approval authorizes that request, not the current state — a request
        // that predates the party's restrictive assertion is stale, and the
        // restriction forces a fresh request. Refuse (consume the stale gate,
        // no receipt) if the opt-out was (re-)asserted at or after the request:
        //   (a) the STOP that established the live head postdates the request
        //       (gate.created_at < head_valid_from), or
        //   (b) a later projected InboundStop re-asserted this (party, channel)
        //       past the head, at or after the request.
        // This is the approve-time half of the restrictive-wins rule the
        // projector enforces at :1013.
        if let Some((_, matched)) = &live_claim {
            let head_valid_from = matched.valid_from.unwrap_or(0);
            let superseded = created_at < head_valid_from
                || comm_records_in_txn(vault, &*wtxn)?
                    .iter()
                    .any(|(_, record)| {
                        matches!(record, CommRecord::Event {
                        kind: CommEventKind::InboundStop,
                        party_ref: event_party,
                        channel_class: Some(event_channel),
                        occurred_at,
                        projected: true,
                        ..
                    } if *event_party == party_ref
                        && event_channel == channel_class
                        && *occurred_at >= created_at
                        && *occurred_at > head_valid_from)
                    });
            if superseded {
                let consumed = CommRecord::Gate {
                    party_ref,
                    channel_class: channel_class.to_owned(),
                    claim_ref,
                    created_at,
                    pending: false,
                };
                put_comm_record_in_txn(vault, wtxn, gate_id, &consumed)?;
                // Commit the consumed gate, then refuse after the txn — returning
                // Err here would roll the consume back.
                return Ok(ClearRuling::Superseded);
            }
        }
        if let Some((live_claim_ref, matched)) = &live_claim {
            let close_at = ruled_at.max(matched.valid_from.unwrap_or(ruled_at));
            vault.retract_claim_in_txn(wtxn, live_claim_ref, close_at)?;
            // Claims moved; the cache follows in the SAME transaction
            // (ONE-1752), exactly as the STOP projector does on the way in. A
            // cleared head that left type-132 saying opted-out would make the
            // gate keep escalating on cache state the claims no longer carry —
            // cache as authority, the inversion the claims-first rule forbids.
            // The sweep is class-scoped like the head it just retracted, so it
            // re-derives every row that head could have suppressed and no
            // other; whether a REMAINING head still suppresses each of those
            // rows stays the fold's decision.
            if let Some(party_key) = active_comm_party_key_in_txn(vault, &*wtxn, party_ref)? {
                crate::counterparty_contact::rematerialize_party_contact_cache_in_txn(
                    vault,
                    wtxn,
                    &party_key,
                    Some(channel_class),
                    ruled_at,
                )?;
            }
        }
        let consumed = CommRecord::Gate {
            party_ref,
            channel_class: channel_class.to_owned(),
            claim_ref,
            created_at,
            pending: false,
        };
        put_comm_record_in_txn(vault, wtxn, gate_id, &consumed)?;
        if live_claim.is_some() {
            let receipt = CommRecord::Receipt {
                party_ref,
                channel_class: channel_class.to_owned(),
                occurred_at: ruled_at,
                outcome: OPT_OUT_CLEAR_APPROVED.to_owned(),
                actor_ref: actor.entity_ref(),
            };
            put_comm_record_in_txn(vault, wtxn, EntityId::now(), &receipt)?;
        }
        Ok(if live_claim.is_some() {
            ClearRuling::Cleared
        } else {
            ClearRuling::NoActiveOptOut
        })
    })?;
    match ruling {
        ClearRuling::Cleared => Ok(()),
        ClearRuling::NoActiveOptOut => Err(CommError::ActiveOptOutNotFound),
        ClearRuling::Superseded => Err(CommError::PendingClearSupersededByStop),
    }
}

/// Counts durable opt-out-clear approval receipts for one party.
pub fn count_opt_out_clear_receipts(vault: &Vault, party: &str) -> CommResult<usize> {
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Ok(0);
    };
    let rtxn = vault.store.env.read_txn()?;
    Ok(comm_records_in_txn(vault, &rtxn)?
        .into_iter()
        .filter(|(_, record)| {
            matches!(record, CommRecord::Receipt {
                party_ref: candidate_party,
                outcome,
                ..
            } if *candidate_party == party_ref && outcome == OPT_OUT_CLEAR_APPROVED)
        })
        .count())
}

/// Returns canonical contact-view bytes derived from live standing claims.
pub fn materialize_contact_record(vault: &Vault, party: &str) -> CommResult<Vec<u8>> {
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Ok(Vec::new());
    };
    let rtxn = vault.store.env.read_txn()?;
    build_contact_view_in_txn(vault, &rtxn, party_ref).map(|(bytes, _)| bytes)
}

/// No-op because the contact record is always derived from live claims.
pub fn drop_contact_record(_vault: &Vault, _party: &str) -> CommResult<()> {
    Ok(())
}

/// Counts contact-view entries derived from live standing claims.
pub fn count_contact_record_claim_entries(vault: &Vault, party: &str) -> CommResult<usize> {
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Ok(0);
    };
    let rtxn = vault.store.env.read_txn()?;
    let (_, entry_count) = build_contact_view_in_txn(vault, &rtxn, party_ref)?;
    usize::try_from(entry_count).map_err(|_| CommError::InvalidRecord)
}

/// One standing `comm.opt_out` head, as the restrictive folds read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StandingOptOutHead {
    /// `None` covers every channel class.
    pub(crate) channel_class: Option<String>,
    /// Receipt-vocabulary reason token.
    pub(crate) reason: String,
    /// Event time the opt-out became valid.
    pub(crate) occurred_at: u64,
}

impl StandingOptOutHead {
    /// Whether this head suppresses `channel_class`. An elided channel matches
    /// EVERY class; a named one matches only itself.
    ///
    /// Stated once, here, as the definition of what an absent class MEANS, and
    /// asked by the one reader that needs it: the type-132 rebuild folds a head
    /// into a contact only when this says the head covers that contact's class
    /// (`counterparty_contact::rematerialize_contact_cache_in_txn`). Any future
    /// channel-scoped reader must use this rather than re-derive the rule.
    #[must_use]
    pub(crate) fn matches_channel(&self, channel_class: &str) -> bool {
        self.channel_class
            .as_deref()
            .is_none_or(|stored| stored == normalize_channel_class(channel_class))
    }
}

/// Every standing `comm.opt_out` head for one party, on the caller's
/// transaction. Channel-less and channel-scoped alike: the caller decides which
/// apply, and no caller may be handed a filtered set that already dropped one.
pub(crate) fn standing_opt_out_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: EntityId,
) -> CommResult<Vec<StandingOptOutHead>> {
    let mut heads = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(rtxn, &party_ref)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_COMM_OPT_OUT {
            continue;
        }
        let claim = CommClaim::from_claim_body(&body)?;
        if !claim.is_standing() {
            continue;
        }
        if let CommClaimValue::OptOut {
            channel_class,
            reason,
            occurred_at,
            ..
        } = claim.value
        {
            heads.push(StandingOptOutHead {
                channel_class,
                reason,
                occurred_at,
            });
        }
    }
    Ok(heads)
}

/// Records the owner's decision to send to an opted-out party.
///
/// HUMAN-RULED: the actor is authorized inside the write transaction and must
/// be [`EdgeActorClass::Human`], exactly like `approve_pending_opt_out_clear`.
/// This is the verb the descriptor row describes; the generic claim doors
/// validate the body's shape but do not yet enforce the write class, which is
/// the named descriptor-registry follow-on.
///
/// It writes ONE claim and nothing else. No opt-out head is retracted, no
/// contact record is touched: an override authorizes a send THROUGH standing
/// suppression, it does not clear it.
#[expect(
    clippy::too_many_arguments,
    reason = "mint args mirror the send-override claim-body keys one-to-one (party, channel_class, scope, send_ref, issued_at, valid_to) plus vault and the human actor; the named descriptor-registry follow-on owns any reshaping"
)]
pub fn mint_send_override(
    vault: &Vault,
    party: &str,
    channel_class: Option<&str>,
    scope: SendOverrideScope,
    send_ref: Option<&str>,
    actor: WriteActor,
    issued_at: u64,
    valid_to: Option<u64>,
) -> CommResult<EntityId> {
    let actor_ref = actor.entity_ref();
    let channel_class = channel_class.map(normalize_channel_class);
    vault.try_with_write_txn(|wtxn| {
        // Authorize from the write transaction's own view, so a concurrent
        // delete/recreate cannot leave an override minted under a stale
        // authorization decision.
        let actor_entity_type = vault
            .store
            .entities
            .get(&*wtxn, actor_ref.as_bytes())?
            .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
            .ok_or(CommError::Engine(Error::EntityNotFound))?;
        validate_actor_class(actor_entity_type, actor.actor_class())?;
        if actor.actor_class() != EdgeActorClass::Human {
            return Err(CommError::HumanApprovalRequired);
        }
        let party_ref = resolve_or_create_party_in_txn(vault, wtxn, party)?;
        let value = CommClaimValue::SendOverride {
            party_ref,
            channel_class: channel_class.clone(),
            scope,
            send_ref: send_ref.map(str::to_owned),
            issued_at,
            valid_to,
        };
        // Validate BEFORE the write so a malformed ruling is refused as a
        // typed comm failure rather than as an opaque body rejection deep in
        // the claim door.
        validate_comm_claim_structure(&value.claim_body()).map_err(|_| CommError::InvalidRecord)?;
        put_comm_claim_with_id_in_txn(vault, wtxn, EntityId::now(), &value, issued_at)
    })
}

/// The override covering one send, if any. Thin transaction-opening wrapper
/// over `send_override_for_send_in_txn`.
pub fn send_override_for_send(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    send_ref: Option<&str>,
    now: u64,
) -> CommResult<Option<SendOverrideMatch>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(party_ref) = resolve_party_ref_in_txn(vault, &rtxn, party)? else {
        return Ok(None);
    };
    send_override_for_send_in_txn(
        &vault.store,
        &rtxn,
        &party_ref,
        &normalize_channel_class(channel_class),
        send_ref,
        now,
    )
}

/// The override covering one send, on the caller's transaction.
///
/// `channel_class` must already be normalized — every caller shares
/// [`normalize_channel_class`], so a stored class and a queried class can never
/// disagree over case or padding.
///
/// Three rules, and nothing else:
///
/// * a head outside its lifetime window never matches, whatever its scope:
///   neither before the owner's ruling starts (`issued_at > now`) nor after it
///   expires (`valid_to < now`). Those are the bounds
///   [`CommClaim::is_effective_at`] already carries, because a send override's
///   `issued_at` IS its claim `valid_from`;
/// * a one-shot matches only when its minted `send_ref` BYTE-equals this
///   send's, so an absent or different ref is simply no match;
/// * standing wins on overlap, because it is the wider decision the owner made.
///
/// There is NO consumption write, structurally: this reads on a read
/// transaction. Replay of the same send ref inside a one-shot's validity window
/// matches by design (Q-025.3) — mint-time binding plus mandatory expiry is the
/// lifetime bound at this interim door.
pub(crate) fn send_override_for_send_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &EntityId,
    channel_class: &str,
    send_ref: Option<&str>,
    now: u64,
) -> CommResult<Option<SendOverrideMatch>> {
    let mut matched = None;
    for claim_id in subject_claim_ids_in_txn(store, txn, party_ref)? {
        let Some(body) = claim_body_in_txn(store, txn, &claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_COMM_SEND_OVERRIDE {
            continue;
        }
        let claim = CommClaim::from_claim_body(&body)?;
        if !claim.is_standing() {
            continue;
        }
        let CommClaimValue::SendOverride {
            channel_class: head_channel,
            scope,
            send_ref: head_send_ref,
            issued_at,
            valid_to,
            ..
        } = claim.value
        else {
            continue;
        };
        if head_channel
            .as_deref()
            .is_some_and(|stored| stored != channel_class)
        {
            continue;
        }
        // A ruling dated ahead of the clock has not started: `is_standing`
        // carries no time bounds, so the lower bound is enforced here or
        // nowhere, and a future-dated override would release a held send early.
        if issued_at > now {
            continue;
        }
        if valid_to.is_some_and(|valid_to| valid_to < now) {
            continue;
        }
        match scope {
            SendOverrideScope::Standing => return Ok(Some(SendOverrideMatch::Standing)),
            SendOverrideScope::OneShot => {
                if head_send_ref.is_some() && head_send_ref.as_deref() == send_ref {
                    matched = Some(SendOverrideMatch::OneShot);
                }
            }
        }
    }
    Ok(matched)
}

/// CLAIM ids attached to `subject` through inbound `claim_of` edges, read with
/// a `Store` alone.
fn subject_claim_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> CommResult<Vec<EntityId>> {
    let prefix = crate::vault::edge_kind_prefix(subject, EdgeKind::ClaimOf);
    let mut ids = Vec::new();
    for entry in store.edges_in.prefix_iter(txn, &prefix)? {
        let (key, value) = entry?;
        ids.push(crate::vault::parse_edge_record(&key, &value)?.target);
    }
    Ok(ids)
}

/// The CLAIM body stored at `id`, or `None` when the row is absent or is not a
/// type-0 CLAIM.
fn claim_body_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> CommResult<Option<ClaimBody>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(CommError::InvalidRecord);
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    Ok(Some(crate::claim::decode_claim_body(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        true,
    )?))
}

/// Moves the party-wide `comm.opt_out` head for `party` to `reason`, inside the
/// caller's write transaction (ONE-1752).
///
/// The head carries NO channel class, so it covers every channel: a contact who
/// opted out said it to the owner, not to one mailbox. It is party-wide state
/// derived from a contact event, which is why the contact writer authors it —
/// and why it goes through the engine-owned door rather than the public ladder.
///
/// Restrictive and monotonic: an existing head is superseded only by a NEWER
/// opt-out, and nothing here ever retracts one. Clearing stays the separate,
/// human-ruled `request_opt_out_clear` / `approve_pending_opt_out_clear` path.
pub(crate) fn supersede_party_opt_out_head_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party: &str,
    reason: CounterpartyOptOutReason,
    occurred_at: u64,
) -> CommResult<()> {
    let party_ref = resolve_or_create_party_in_txn(vault, wtxn, party)?;
    let active = matching_claims_in_txn(
        vault,
        &*wtxn,
        party_ref,
        PREDICATE_COMM_OPT_OUT,
        None,
        None,
        true,
    )?;
    require_at_most_one(&active)?;
    let head = active.into_iter().next();
    if let Some((_, claim)) = &head
        && let CommClaimValue::OptOut {
            reason: head_reason,
            occurred_at: head_at,
            ..
        } = &claim.value
        && (*head_at > occurred_at
            || (*head_at == occurred_at && head_reason == reason.receipt_reason()))
    {
        return Ok(());
    }
    let value = CommClaimValue::OptOut {
        party_ref,
        channel_class: None,
        reason: reason.receipt_reason().to_owned(),
        occurred_at,
    };
    let new_id =
        put_engine_owned_comm_claim_in_txn(vault, wtxn, EntityId::now(), &value, occurred_at)?;
    if let Some((old_id, _)) = head {
        crate::counterparty_contact::supersede_family_owned_claim_in_txn(
            vault,
            wtxn,
            &new_id,
            &old_id,
            occurred_at,
        )?;
    }
    Ok(())
}

/// Re-derives the type-132 cache for every contact this party reaches on
/// `channel_class`, inside the projector's own write transaction.
///
/// Claims moved; the cache follows in the SAME transaction, so the gate's
/// type-132-fed fold can never observe the old suppression state. The
/// party-channel index (ONE-1868) names the contacts, which keeps an
/// email-scoped STOP from re-deriving a telegram contact: channel scope is
/// decided by which contacts are enumerated here.
pub(super) fn rematerialize_party_channel_contact_cache_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: EntityId,
    channel_class: &str,
    now: u64,
) -> CommResult<()> {
    let Some(party_key) = active_comm_party_key_in_txn(vault, &*wtxn, party_ref)? else {
        return Ok(());
    };
    let contacts = crate::counterparty_contact::counterparty_contacts_by_party_channel(
        &vault.store,
        &*wtxn,
        &party_key,
        &normalize_channel_class(channel_class),
    )?;
    for (contact_id, _) in contacts {
        rematerialize_contact_cache_in_txn(vault, wtxn, &contact_id, now)?;
    }
    Ok(())
}
