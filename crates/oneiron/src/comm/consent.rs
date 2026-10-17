//! Human consent gates, send overrides and standing opt-out folds.

use super::claims::{
    CommClaim, CommClaimValue, CommClearOptOutOutcome, CommError, CommResult,
    PREDICATE_COMM_OPT_OUT, PREDICATE_COMM_SEND_OVERRIDE, PREDICATE_COMM_THREAD_MEMBER,
    SendOverrideMatch, SendOverrideScope, validate_comm_claim_structure,
};
use super::opt_out_slots::{
    consume_clear_gates_in_txn, opt_out_slot_heads_in_txn, pending_clear_request_at,
};
use super::parties::{
    active_comm_party_key_in_txn, resolve_or_create_party_in_txn, resolve_party,
    resolve_party_ref_in_txn,
};
use super::projection_writes::{
    build_contact_view_in_txn, count_comm_claims, matching_claims_in_txn,
    put_engine_owned_comm_claim_in_txn, require_at_most_one,
};
use super::records::{
    CommEventKind, CommRecord, comm_records_in_txn, put_comm_record_in_txn, validate_channel_class,
};
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::ClaimBody;
use crate::counterparty_contact::{CounterpartyOptOutReason, normalize_channel_class};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;
use crate::provenance::validate_actor_class;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::write_envelope::WriteActor;
use std::collections::BTreeSet;

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
    let channel_class = normalize_channel_class(channel_class);
    let channel_class = channel_class.as_str();
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Err(CommError::ActiveOptOutNotFound);
    };
    vault.try_with_write_txn_grouped(|wtxn| {
        let records = comm_records_in_txn(vault, &*wtxn)?;
        let subjects = opt_out_subjects_in_txn(vault, &*wtxn, party_ref)?;
        // A merged shell's head holds the party's sends as the party's own
        // does, so a clear request must find it (F06 R2-F1).
        let active = opt_out_slot_heads_in_txn(vault, &*wtxn, &subjects, channel_class)?;
        let Some(claim_ref) = active.first().map(|head| head.claim_ref) else {
            return Err(CommError::ActiveOptOutNotFound);
        };
        if records
            .iter()
            .any(|(_, record)| pending_clear_request_at(record, &subjects, channel_class).is_some())
        {
            return Ok(CommClearOptOutOutcome::PendingHumanRuling);
        }
        let gate = CommRecord::Gate {
            party_ref,
            channel_class: channel_class.to_owned(),
            claim_ref,
            created_at,
            pending: true,
        };
        put_comm_record_in_txn(vault, wtxn, vault.store.clock.entity_id()?, &gate)?;
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

    validate_channel_class(channel_class).map_err(|_| CommError::InvalidRecord)?;
    let channel_class = normalize_channel_class(channel_class);
    let channel_class = channel_class.as_str();

    let actor_ref = actor.entity_ref();
    let Some(party_ref) = resolve_party(vault, party)? else {
        return Err(CommError::PendingGateNotFound);
    };
    let ruling = vault.try_with_write_txn_grouped(|wtxn| {
        // Authorize the approving actor from the write transaction's view so a
        // concurrent delete/recreate cannot leave the gate consumed under a
        // stale authorization decision (TOCTOU).
        let actor_entity_type = vault
            .store
            .port_entity_record(&*wtxn, &actor_ref)?
            .map(|row| row.encode())
            .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
            .ok_or(CommError::Engine(Error::EntityNotFound))?;
        validate_actor_class(actor_entity_type, actor.actor_class())?;
        if actor.actor_class() != EdgeActorClass::Human {
            return Err(CommError::HumanApprovalRequired);
        }
        let subjects = opt_out_subjects_in_txn(vault, &*wtxn, party_ref)?;
        let records = comm_records_in_txn(vault, &*wtxn)?;
        // Twins that each held a request before their merge leave one gate
        // per subject. The ruling answers all of them, and the OLDEST request
        // is the one judged stale, so a STOP after any of them refuses it.
        let gates: Vec<(EntityId, &CommRecord, u64)> = records
            .iter()
            .filter_map(|(gate_id, record)| {
                pending_clear_request_at(record, &subjects, channel_class)
                    .map(|requested_at| (*gate_id, record, requested_at))
            })
            .collect();
        let (Some(oldest_request), Some(newest_request)) = (
            gates.iter().map(|(_, _, at)| *at).min(),
            gates.iter().map(|(_, _, at)| *at).max(),
        ) else {
            return Err(CommError::PendingGateNotFound);
        };
        if ruled_at < newest_request {
            return Err(CommError::RulingPredatesGate);
        }
        // Every head on the slot, the merged shells' included: each holds the
        // party's sends, so a clear that left one standing would clear nothing
        // (F06 R2-F1). Each head stays on the subject it was said about.
        let heads = opt_out_slot_heads_in_txn(vault, &*wtxn, &subjects, channel_class)?;
        // Fail-closed on a stale gate. The gate records a clear REQUEST;
        // approval authorizes that request, not the current state — a request
        // that predates the party's restrictive assertion is stale, and the
        // restriction forces a fresh request. Refuse (consume the stale gates,
        // no receipt) if the opt-out was (re-)asserted at or after the request:
        //   (a) the STOP that established a live head postdates the request
        //       (gate.created_at < head_valid_from), or
        //   (b) a later projected InboundStop on any of the party's subjects
        //       re-asserted this channel past the heads, at or after the
        //       request. The event keeps its source spelling, so it is
        //       compared normalized, as the projector read it (F06 R3-F3).
        // This is the approve-time half of the restrictive-wins rule the
        // projector enforces at :1013.
        if let Some(newest_head) = heads.iter().map(|head| head.valid_from).max() {
            let superseded = heads.iter().any(|head| oldest_request < head.valid_from)
                || records.iter().any(|(_, record)| {
                    matches!(record, CommRecord::Event {
                        kind: CommEventKind::InboundStop,
                        party_ref: event_party,
                        channel_class: Some(event_channel),
                        occurred_at,
                        projected: true,
                        ..
                    } if subjects.contains(event_party)
                        && normalize_channel_class(event_channel) == channel_class
                        && *occurred_at >= oldest_request
                        && *occurred_at > newest_head)
                });
            if superseded {
                consume_clear_gates_in_txn(vault, wtxn, &gates)?;
                // Commit the consumed gates, then refuse after the txn —
                // returning Err here would roll the consume back.
                return Ok(ClearRuling::Superseded);
            }
        }
        for head in &heads {
            let close_at = ruled_at.max(head.valid_from);
            vault.retract_claim_in_txn(wtxn, &head.claim_ref, close_at)?;
        }
        // Claims moved; the cache follows in the SAME transaction
        // (ONE-1752), exactly as the STOP projector does on the way in. A
        // cleared head that left type-132 saying opted-out would make the
        // gate keep escalating on cache state the claims no longer carry —
        // cache as authority, the inversion the claims-first rule forbids.
        // The sweep is class-scoped like the heads it just retracted, so it
        // re-derives every row those heads could have suppressed and no
        // other; whether a REMAINING head still suppresses each of those
        // rows stays the fold's decision.
        let cleared: BTreeSet<EntityId> = heads.iter().map(|head| head.subject).collect();
        rematerialize_subject_contacts_in_txn(vault, wtxn, &cleared, channel_class, ruled_at)?;
        consume_clear_gates_in_txn(vault, wtxn, &gates)?;
        if heads.is_empty() {
            return Ok(ClearRuling::NoActiveOptOut);
        }
        let receipt = CommRecord::Receipt {
            party_ref,
            channel_class: channel_class.to_owned(),
            occurred_at: ruled_at,
            outcome: OPT_OUT_CLEAR_APPROVED.to_owned(),
            actor_ref: actor.entity_ref(),
        };
        put_comm_record_in_txn(vault, wtxn, vault.store.clock.entity_id()?, &receipt)?;
        Ok(ClearRuling::Cleared)
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
        self.channel_class.as_deref().is_none_or(|stored| {
            normalize_channel_class(stored) == normalize_channel_class(channel_class)
        })
    }
}

/// The subjects whose `comm.opt_out` heads stand for one party: the party and
/// every redirect shell around it.
///
/// A twin merge keeps each claim on its own subject, so the party's merged
/// shells are read through as well: a STOP that landed on a shell before the
/// merge still stands for the survivor (F06 H170). Split ancestry is read too;
/// for a restriction the wider set is the safe one. The fold, the human clear
/// and the contact refresh all take this one set, so a head that holds a send
/// is always one a clear can reach.
fn opt_out_subjects_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: EntityId,
) -> CommResult<BTreeSet<EntityId>> {
    parties_opt_out_subjects_in_txn(&vault.store, rtxn, BTreeSet::from([party_ref]))
}

/// [`opt_out_subjects_in_txn`] for several parties at once, with a `Store`.
pub(super) fn parties_opt_out_subjects_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    parties: BTreeSet<EntityId>,
) -> CommResult<BTreeSet<EntityId>> {
    let mut subjects =
        crate::identity_redirect::inbound_redirect_shells_in_txn(store, rtxn, &parties)?;
    subjects.extend(parties);
    Ok(subjects)
}

/// The standing `comm.opt_out` head one claim body is, if it is one.
pub(super) fn standing_opt_out_head(body: &ClaimBody) -> CommResult<Option<StandingOptOutHead>> {
    if body.predicate != PREDICATE_COMM_OPT_OUT {
        return Ok(None);
    }
    let claim = CommClaim::from_claim_body(body)?;
    if !claim.is_standing() {
        return Ok(None);
    }
    let CommClaimValue::OptOut {
        channel_class,
        reason,
        occurred_at,
        ..
    } = claim.value
    else {
        return Ok(None);
    };
    Ok(Some(StandingOptOutHead {
        channel_class,
        reason,
        occurred_at,
    }))
}

/// Every standing `comm.opt_out` head for one party, on the caller's
/// transaction. Channel-less and channel-scoped alike: the caller decides which
/// apply, and no caller may be handed a filtered set that already dropped one.
/// The heads are read on every subject of `opt_out_subjects_in_txn`.
pub(crate) fn standing_opt_out_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_ref: EntityId,
) -> CommResult<Vec<StandingOptOutHead>> {
    let subjects = opt_out_subjects_in_txn(vault, rtxn, party_ref)?;
    let mut heads = Vec::new();
    let claim_ids = subjects
        .iter()
        .map(|subject| vault.claims_for_subject_in_txn(rtxn, subject))
        .collect::<crate::error::Result<Vec<_>>>()?;
    for claim_id in claim_ids.into_iter().flatten() {
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
            continue;
        };
        heads.extend(standing_opt_out_head(&body)?);
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
    vault.try_with_write_txn_grouped(|wtxn| {
        // Authorize from the write transaction's own view, so a concurrent
        // delete/recreate cannot leave an override minted under a stale
        // authorization decision.
        let actor_entity_type = vault
            .store
            .port_entity_record(&*wtxn, &actor_ref)?
            .map(|row| row.encode())
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
        validate_comm_claim_structure(&value.claim_body()?)
            .map_err(|_| CommError::InvalidRecord)?;
        // The human check above IS this write's authorization, and the only
        // door the claim admission guard lets land a live override.
        put_engine_owned_comm_claim_in_txn(
            vault,
            wtxn,
            vault.store.clock.entity_id()?,
            &value,
            issued_at,
        )
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
        // An imported override is another vault's statement, never this
        // owner's ruling.
        if body.predicate != PREDICATE_COMM_SEND_OVERRIDE
            || body.source == Some(crate::claim::ClaimSource::Imported)
            || !crate::gate::claim_critical_confirm_settled_in_txn(store, txn, &claim_id)?
        {
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
        if head_channel.as_deref().is_some_and(|stored| {
            normalize_channel_class(stored) != normalize_channel_class(channel_class)
        }) {
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
pub(super) fn subject_claim_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> CommResult<Vec<EntityId>> {
    let mut ids = Vec::new();
    for entry in store.port_edges(
        txn,
        subject,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::ClaimOf),
        None,
    )? {
        let edge_row = entry?;
        ids.push(edge_row.target);
    }
    Ok(ids)
}

/// The CLAIM body stored at `id`, or `None` when the row is absent or is not a
/// type-0 CLAIM.
pub(super) fn claim_body_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> CommResult<Option<ClaimBody>> {
    let Some(raw) = store.port_entity_record(txn, id)? else {
        return Ok(None);
    };

    if raw.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    Ok(Some(crate::claim::decode_claim_body(&raw.body, true)?))
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
    let new_id = put_engine_owned_comm_claim_in_txn(
        vault,
        wtxn,
        vault.store.clock.entity_id()?,
        &value,
        occurred_at,
    )?;
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
/// type-132-fed fold can never observe the old suppression state.
pub(super) fn rematerialize_party_channel_contact_cache_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: EntityId,
    channel_class: &str,
    now: u64,
) -> CommResult<()> {
    rematerialize_subject_contacts_in_txn(
        vault,
        wtxn,
        &BTreeSet::from([party_ref]),
        channel_class,
        now,
    )
}

/// Re-derives the type-132 cache of every contact that folds a
/// `channel_class` head standing on one of `subjects`.
///
/// A contact folds the heads of the ACTIVE party its key resolves to, and that
/// party reads its shells through, so a head on a shell reaches the contacts of
/// every active party the shell points at: a twin's survivor shares its key
/// (F06 H170), and a merge of two different keys puts the survivor's contacts
/// under the shell's heads (F06 R2-F3). Those parties come from the witnesses
/// the fold's inbound walk reads, not the redirect table alone, and the walk
/// has no depth or cycle error, so a dropped table or a long chain can neither
/// narrow the refresh nor refuse the STOP (F06 R3-F1, R3-F2). A merged
/// entity's own key is skipped: no active party answers it, so a rebuild there
/// folds none of the heads it still carries and would drop its STOP (F06
/// R4-F1). That also keeps a chain at one refresh per active head (R4-F2).
/// Each key's contacts come from the full scan the send gate also uses:
/// the party-channel index (ONE-1868) cannot prove it lists every contact.
/// Channel scope stays the fold's class match, so an email STOP never
/// re-derives a telegram contact.
fn rematerialize_subject_contacts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    subjects: &BTreeSet<EntityId>,
    channel_class: &str,
    now: u64,
) -> CommResult<()> {
    let mut parties = subjects.clone();
    parties.extend(crate::identity_redirect::outbound_redirect_heads_in_txn(
        &vault.store,
        &*wtxn,
        subjects,
    )?);
    let mut party_keys = BTreeSet::new();
    for party in parties {
        party_keys.extend(active_comm_party_key_in_txn(&vault.store, &*wtxn, party)?);
    }
    let channel_class = normalize_channel_class(channel_class);
    for party_key in party_keys {
        crate::counterparty_contact::rematerialize_party_contact_cache_in_txn(
            vault,
            wtxn,
            &party_key,
            Some(&channel_class),
            now,
        )?;
    }
    Ok(())
}
