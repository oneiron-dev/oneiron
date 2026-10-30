//! Ordered idempotent projector pass and the record verbs that feed it.

use super::claims::{
    CommClaimValue, CommError, CommResult, PREDICATE_COMM_LAST_TOUCH, PREDICATE_COMM_OPT_OUT,
    PREDICATE_COMM_THREAD_MEMBER,
};
use super::consent::{OPT_OUT_REASON_STOP, rematerialize_party_channel_contact_cache_in_txn};
use super::parties::{
    reconcile_comm_party_twins, resolve_actor_party_in_txn, resolve_or_create_party_in_txn,
};
use super::projection_writes::{
    latest_claim_transition_boundary, matching_claims_in_txn, projected_comm_claim_id,
    put_projected_comm_claim_in_txn,
};
use super::records::{
    CommEventKind, CommRecord, comm_records_in_txn, decode_comm_record, next_event_sequence_in_txn,
    put_comm_record_in_txn, read_comm_record_in_txn, validate_channel_class, validate_key_string,
};
use super::stop_hold::{
    holds_pending_stop_in_txn, pending_stop_ids_in_txn, release_pending_stop_in_txn,
};
use super::thread_membership::apply_thread_membership_in_txn;
use super::{
    CommProjectorIndex, PartyChannelKey, PartyThreadKey, ProjectedCommEvent, ProjectorIndexDelta,
    ProjectorRule,
};
use crate::Vault;
use crate::counterparty_contact::normalize_channel_class;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind};
use crate::ports::{EntityStoreRead, TombstoneStore};
use crate::receipt::FIELD_TASK_REF;
use crate::registry::ENTITY_TYPE_COMM_RECORD;

#[derive(Debug, Clone, Copy)]
pub(super) enum ProjectorAction {
    UpsertLastTouch,
    SetOptOut,
    JoinThread,
    LeaveThread,
}

const PROJECTOR_RULES: [ProjectorRule; 6] = [
    ProjectorRule {
        event_kind: CommEventKind::SendSucceeded,
        predicate: PREDICATE_COMM_LAST_TOUCH,
        action: ProjectorAction::UpsertLastTouch,
    },
    ProjectorRule {
        event_kind: CommEventKind::InboundReply,
        predicate: PREDICATE_COMM_LAST_TOUCH,
        action: ProjectorAction::UpsertLastTouch,
    },
    ProjectorRule {
        event_kind: CommEventKind::TouchAsserted,
        predicate: PREDICATE_COMM_LAST_TOUCH,
        action: ProjectorAction::UpsertLastTouch,
    },
    ProjectorRule {
        event_kind: CommEventKind::InboundStop,
        predicate: PREDICATE_COMM_OPT_OUT,
        action: ProjectorAction::SetOptOut,
    },
    ProjectorRule {
        event_kind: CommEventKind::ThreadJoined,
        predicate: PREDICATE_COMM_THREAD_MEMBER,
        action: ProjectorAction::JoinThread,
    },
    ProjectorRule {
        event_kind: CommEventKind::ThreadLeft,
        predicate: PREDICATE_COMM_THREAD_MEMBER,
        action: ProjectorAction::LeaveThread,
    },
];

/// Runs one ordered, idempotent communication projector pass.
///
/// Concurrent passes are supported callers: LMDB serializes each event's write
/// transaction, and when a peer pass commits one of this pass's snapshotted
/// events first, the re-read observes that committed boundary and folds it
/// into this pass's index before any later event decides from it
/// (`project_event`). A join/leave deciding while a same-key snapshotted event
/// is still AHEAD of this pass's cursor additionally re-reads just those
/// candidate rows, so a boundary a peer committed after this pass's snapshot
/// but before this event's write transaction still bounds the decision now
/// (`CommProjectorIndex::peer_projected_thread_transition_in_txn`). Events
/// RECORDED after this pass's snapshot are not observed at all; they are the
/// next pass's business.
pub fn run_comm_projector(vault: &Vault) -> CommResult<()> {
    import_delivered_send_receipts(vault)?;
    let (records, pending_stops) = {
        let rtxn = vault.store.env.read_txn()?;
        (
            comm_records_in_txn(vault, &rtxn)?,
            pending_stop_ids_in_txn(&vault.store, &rtxn)?,
        )
    };
    let mut index = CommProjectorIndex::from_records(&records, &pending_stops);
    drop(records);
    let mut first_refusal = None;
    for event_id in index.pending_event_ids() {
        // Each event keeps its own write transaction, so a later bad event
        // cannot roll back what earlier events already projected.
        match project_event(vault, event_id, &index) {
            Ok(delta) => index.apply_committed(delta),
            Err(CommError::Engine(Error::EntityNotFound)) => {
                // A replicated event can arrive before its party row. Leave it
                // unprojected — and the index untouched — so a later pass
                // retries after the party syncs.
                continue;
            }
            Err(CommError::Engine(error)) if storage_failure(&error) => {
                return Err(CommError::Engine(error));
            }
            Err(error) => {
                index.forget_accounted_txn();
                // One event's refusal stays with that event: it keeps waiting
                // and the pass reports it, but the events behind it (a later
                // STOP for another party above all) still project (F06 H415).
                first_refusal.get_or_insert(error);
            }
        }
    }
    reconcile_comm_party_twins(vault, vault.store.clock.now_recorded_at())?;
    first_refusal.map_or(Ok(()), Err)
}

fn storage_failure(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Storage | ErrorKind::Io | ErrorKind::MapFull
    )
}

/// Folds durable connector receipts into this projector. TASK identity fixes the
/// source event; its original PERSON subject is never changed by later party
/// merges or deletion. A new delivery without an explicit counterparty is not
/// a communication fact: transport destinations can be group channels.
fn import_delivered_send_receipts(vault: &Vault) -> CommResult<()> {
    for receipt in crate::receipt::durable_send_receipts(vault)? {
        if receipt.outcome != "delivered_to_channel" {
            continue;
        }
        let channel = receipt
            .fields
            .get("channel")
            .ok_or(CommError::InvalidRecord)?;
        let verb = receipt.fields.get("verb").ok_or(CommError::InvalidRecord)?;
        if !is_delivered_message(channel, verb) {
            continue;
        }
        let Some(party) = receipt.fields.get("counterparty_ref") else {
            continue;
        };
        validate_channel_class(channel).map_err(|_| CommError::InvalidRecord)?;
        validate_key_string(party).map_err(|_| CommError::InvalidRecord)?;
        let task_ref = EntityId::from_hex(
            receipt
                .fields
                .get(FIELD_TASK_REF)
                .ok_or(CommError::InvalidRecord)?,
        )
        .map_err(|_| CommError::InvalidRecord)?;
        let event_id = EntityId::derive(
            crate::entity_id::derived_domains::COMM_CONNECTOR_SEND_EVENT,
            &[task_ref.as_bytes()],
        )
        .map_err(|_| CommError::InvalidRecord)?;
        vault.try_with_write_txn_grouped(|txn| {
            // Check the immutable source event BEFORE resolving today's party.
            // A merged shell keeps its original body, and a deleted subject has
            // no body at all. Neither should remint a PERSON or block STOPs.
            if let Some(raw) = vault.store.port_entity_record(&*txn, &event_id)? {
                if raw.entity_type != ENTITY_TYPE_COMM_RECORD {
                    return Err(CommError::InvalidRecord);
                }
                match decode_comm_record(&raw.body)? {
                    CommRecord::Event {
                        kind: CommEventKind::SendSucceeded,
                        party_ref: original_party,
                        channel_class: Some(resident_channel),
                        thread_ref: None,
                        occurred_at,
                        ..
                    } if resident_channel == *channel && occurred_at == receipt.occurred_at => {
                        // A soft delete keeps a headerful PERSON shell with
                        // scrubbed body bytes. It is not a live party to
                        // compare against the frozen receipt; the already
                        // imported event must remain replay-idempotent.
                        if !vault.port_tombstone_is_deleted(&*txn, &original_party)?
                            && let Some(original) =
                                vault.store.port_entity_record(&*txn, &original_party)?
                        {
                            if original.entity_type != crate::registry::ENTITY_TYPE_PERSON {
                                return Err(CommError::InvalidRecord);
                            }
                            let value = rmpv::decode::read_value(&mut original.body.as_slice())
                                .map_err(|_| CommError::InvalidRecord)?;
                            let key = super::records::required_string(
                                super::records::value_map(&value)
                                    .map_err(|_| CommError::InvalidRecord)?,
                                super::claims::KEY_PARTY_KEY,
                            )
                            .map_err(|_| CommError::InvalidRecord)?;
                            if key != party {
                                return Err(CommError::InvalidRecord);
                            }
                        }
                        return Ok(());
                    }
                    _ => return Err(CommError::InvalidRecord),
                }
            }
            let party_ref = resolve_or_create_party_in_txn(vault, txn, party)?;
            let sequence = next_event_sequence_in_txn(vault, txn)?;
            put_comm_record_in_txn(
                vault,
                txn,
                event_id,
                &CommRecord::Event {
                    sequence,
                    kind: CommEventKind::SendSucceeded,
                    party_ref,
                    channel_class: Some(channel.clone()),
                    thread_ref: None,
                    occurred_at: receipt.occurred_at,
                    projected: false,
                },
            )
        })?;
    }
    Ok(())
}

/// A message operation projects one delivered receipt into comm history.
/// The connector manifest declares the eligible verbs; edits, reactions,
/// invitations and presence never become touches just because they delivered.
fn is_delivered_message(channel: &str, verb: &str) -> bool {
    crate::outbound::outbound_capability_manifest(channel)
        .is_some_and(|manifest| manifest.message_verbs.iter().any(|kind| kind == verb))
}

/// Records a successful send receipt without directly writing standing-state claims.
pub fn record_comm_send_receipt(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    occurred_at: u64,
) -> CommResult<()> {
    record_event(
        vault,
        party,
        Some(channel_class),
        None,
        CommEventKind::SendSucceeded,
        occurred_at,
    )
}

/// Records a successful send to an ACTOR counterparty in the caller's write,
/// so the receipt lands with the state that confirmed the send, or not at
/// all. The party is the actor itself ([`resolve_actor_party_in_txn`]); an
/// actor with no live PERSON role records nothing.
pub(crate) fn record_comm_actor_send_receipt_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    display_name: &str,
    channel_class: &str,
    occurred_at: u64,
) -> CommResult<()> {
    validate_channel_class(channel_class).map_err(|_| CommError::InvalidRecord)?;
    let Some(party_ref) = resolve_actor_party_in_txn(vault, wtxn, actor, display_name)? else {
        return Ok(());
    };
    let sequence = next_event_sequence_in_txn(vault, wtxn)?;
    let record = CommRecord::Event {
        sequence,
        kind: CommEventKind::SendSucceeded,
        party_ref,
        channel_class: Some(normalize_channel_class(channel_class)),
        thread_ref: None,
        occurred_at,
        projected: false,
    };
    put_comm_record_in_txn(vault, wtxn, vault.store.clock.entity_id()?, &record)
}

/// Records an inbound reply receipt. Content remains in TURN/SESSION;
/// only the standing last-touch state is projected from this event.
pub fn record_comm_inbound_reply(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    occurred_at: u64,
) -> CommResult<()> {
    record_event(
        vault,
        party,
        Some(channel_class),
        None,
        CommEventKind::InboundReply,
        occurred_at,
    )
}

/// [`record_comm_inbound_reply`] in the caller's write, so the event lands
/// with the inbound admission that took the message, or not at all. The
/// channel class is normalized first. A party key or channel class the comm
/// family cannot hold records nothing: the message is admitted either way.
pub(crate) fn record_comm_inbound_reply_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party: &str,
    channel_class: &str,
    occurred_at: u64,
) -> crate::error::Result<()> {
    let channel_class = normalize_channel_class(channel_class);
    if validate_key_string(party).is_err() || validate_channel_class(&channel_class).is_err() {
        return Ok(());
    }
    resolve_or_create_party_in_txn(vault, wtxn, party)
        .and_then(|party_ref| {
            put_source_event_in_txn(
                vault,
                wtxn,
                party_ref,
                CommEventKind::InboundReply,
                Some(channel_class.as_str()),
                None,
                occurred_at,
            )
        })
        .map_err(|error| match error {
            CommError::Engine(error) => error,
            _ => Error::InvalidClaimBody("inbound reply comm record refused"),
        })
}

/// Records an inbound restrictive STOP event without directly writing claims.
pub fn record_comm_inbound_stop(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    occurred_at: u64,
) -> CommResult<()> {
    record_event(
        vault,
        party,
        Some(channel_class),
        None,
        CommEventKind::InboundStop,
        occurred_at,
    )
}

/// Records a thread join or leave event without directly writing claims.
pub fn record_comm_thread_event(
    vault: &Vault,
    thread_ref: &str,
    party: &str,
    joined: bool,
    occurred_at: u64,
) -> CommResult<()> {
    vault.try_with_write_txn_grouped(|txn| {
        record_comm_thread_event_in_txn(vault, txn, thread_ref, party, joined, occurred_at)
    })
}

pub(crate) fn record_comm_thread_event_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    thread_ref: &str,
    party: &str,
    joined: bool,
    occurred_at: u64,
) -> CommResult<()> {
    validate_key_string(thread_ref).map_err(|_| CommError::InvalidRecord)?;
    let thread = crate::thread_passport::canonical_thread_ref_in_txn(vault, txn, thread_ref)?;
    let party_ref = resolve_or_create_party_in_txn(vault, txn, party)?;
    let sequence = next_event_sequence_in_txn(vault, txn)?;
    let record = CommRecord::Event {
        sequence,
        kind: if joined {
            CommEventKind::ThreadJoined
        } else {
            CommEventKind::ThreadLeft
        },
        party_ref,
        channel_class: None,
        thread_ref: Some(thread),
        occurred_at,
        projected: false,
    };
    put_comm_record_in_txn(vault, txn, EntityId::now(), &record)
}

fn record_event(
    vault: &Vault,
    party: &str,
    channel_class: Option<&str>,
    thread_ref: Option<&str>,
    kind: CommEventKind,
    occurred_at: u64,
) -> CommResult<()> {
    if let Some(channel_class) = channel_class {
        validate_channel_class(channel_class).map_err(|_| CommError::InvalidRecord)?;
    }
    if let Some(thread_ref) = thread_ref {
        validate_key_string(thread_ref).map_err(|_| CommError::InvalidRecord)?;
    }
    vault.try_with_write_txn_grouped(|wtxn| {
        // Resolve/create the party in the SAME transaction as the event so a
        // concurrent party deletion cannot leave the event bound to a missing
        // PERSON (which the projector would then skip forever as EntityNotFound).
        let party_ref = resolve_or_create_party_in_txn(vault, wtxn, party)?;
        put_source_event_in_txn(
            vault,
            wtxn,
            party_ref,
            kind,
            channel_class,
            thread_ref,
            occurred_at,
        )
    })
}

/// Writes one unprojected source event for `party_ref` at the next event
/// sequence, in the caller's write: the channel class normalized, the thread
/// as its canonical ref. The projector's next pass projects it.
pub(super) fn put_source_event_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: EntityId,
    kind: CommEventKind,
    channel_class: Option<&str>,
    thread_ref: Option<&str>,
    occurred_at: u64,
) -> CommResult<()> {
    let thread_ref = thread_ref
        .map(|thread| crate::thread_passport::canonical_thread_ref_in_txn(vault, wtxn, thread))
        .transpose()?;
    let sequence = next_event_sequence_in_txn(vault, wtxn)?;
    let record = CommRecord::Event {
        sequence,
        kind,
        party_ref,
        channel_class: channel_class.map(normalize_channel_class),
        thread_ref,
        occurred_at,
        projected: false,
    };
    put_comm_record_in_txn(vault, wtxn, vault.store.clock.entity_id()?, &record)
}

/// Projects one source event in its own write transaction, returning the index
/// changes the commit made true. `try_with_write_txn` yields `Ok` only after the
/// commit, so the caller can never fold in a delta that was rolled back.
pub(super) fn project_event(
    vault: &Vault,
    event_id: EntityId,
    index: &CommProjectorIndex,
) -> CommResult<ProjectorIndexDelta> {
    // A write group of its own, so the index can tell its own commit from
    // any other writer's (`CommProjectorIndex::begin_event_txn`).
    vault.try_with_write_txn(|wtxn| {
        index.begin_event_txn(vault);
        let Some(raw) = vault.store.port_entity_record(&*wtxn, &event_id)? else {
            return Ok(ProjectorIndexDelta::default());
        };

        if raw.entity_type != ENTITY_TYPE_COMM_RECORD {
            return Err(CommError::InvalidRecord);
        }
        let record = decode_comm_record(&raw.body)?;
        let CommRecord::Event {
            sequence,
            kind,
            party_ref,
            channel_class,
            thread_ref,
            occurred_at,
            projected,
        } = record
        else {
            return Err(CommError::InvalidRecord);
        };
        // A STOP another replica projected still holds sends here until this
        // replica's pass finds that projection's restriction (F06).
        let pending_stop = kind == CommEventKind::InboundStop
            && holds_pending_stop_in_txn(&vault.store, &*wtxn, &event_id)?;
        if projected && !pending_stop {
            // A peer pass already committed this snapshotted event. A join or
            // leave is a durable membership boundary even when its commit
            // mutated no claim (a join while a member claim already stands, a
            // leave with nothing active), and this pass's index saw it only as
            // pending — never as a transition. Folding the live row in here
            // keeps a later same-pass join/leave deciding against exactly the
            // boundary set the pre-index in-transaction family rescan used.
            return Ok(match (kind, thread_ref) {
                (CommEventKind::ThreadJoined | CommEventKind::ThreadLeft, Some(thread_ref)) => {
                    ProjectorIndexDelta {
                        consumed_gate_ids: Vec::new(),
                        projected_thread_transition: Some((
                            PartyThreadKey {
                                party_ref,
                                thread_ref,
                            },
                            (occurred_at, kind == CommEventKind::ThreadLeft),
                        )),
                    }
                }
                _ => ProjectorIndexDelta::default(),
            });
        }
        let rule = PROJECTOR_RULES
            .iter()
            .find(|rule| rule.event_kind == kind)
            .ok_or(CommError::InvalidRecord)?;
        // Decode can read provider-spelled events already accepted by this
        // build; project their recipient class through the same rule as new
        // events, without changing the original audit event bytes.
        let recipient_class = channel_class.as_deref().map(normalize_channel_class);
        let event = ProjectedCommEvent {
            rule: *rule,
            source_event_id: event_id,
            party_ref,
            channel_class: recipient_class.as_deref(),
            thread_ref: thread_ref.as_deref(),
            occurred_at,
        };
        let delta = if projected {
            match peer_stop_projection_in_txn(vault, &*wtxn, &event)? {
                // Still in flight: the event keeps holding and waits.
                None => return Ok(ProjectorIndexDelta::default()),
                Some(true) => apply_projector_rule_in_txn(vault, wtxn, index, &event)?,
                Some(false) => ProjectorIndexDelta::default(),
            }
        } else {
            apply_projector_rule_in_txn(vault, wtxn, index, &event)?
        };
        if !projected {
            let consumed = CommRecord::Event {
                sequence,
                kind,
                party_ref,
                channel_class,
                thread_ref,
                occurred_at,
                projected: true,
            };
            put_comm_record_in_txn(vault, wtxn, event_id, &consumed)?;
        }
        if pending_stop {
            release_pending_stop_in_txn(&vault.store, wtxn, &event_id)?;
        }
        index.expect_own_commit();
        Ok(delta)
    })
}

/// What a peer's projection of a STOP left on this replica: `Some(true)`
/// when the STOP's own opt-out stands here, so the rule only consumes gates
/// and refreshes contacts; `Some(false)` when that opt-out arrived closed, or
/// a head after the STOP moved the slot; `None` until one of them arrives.
///
/// The rule never mints for a peer's STOP. Its own opt-out, or the later head
/// that answers it, arrives with the peer's state, and a copy minted here
/// first could stand against a clear the peer's human already made. An older
/// head standing here is no answer: its clear may be in flight (R1-F1).
fn peer_stop_projection_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event: &ProjectedCommEvent<'_>,
) -> CommResult<Option<bool>> {
    let channel = event.channel_class.ok_or(CommError::InvalidRecord)?;
    let own = projected_comm_claim_id(
        event.source_event_id,
        &CommClaimValue::OptOut {
            party_ref: event.party_ref,
            channel_class: Some(channel.to_owned()),
            reason: OPT_OUT_REASON_STOP.to_owned(),
            occurred_at: event.occurred_at,
        },
    )?;
    let history = matching_claims_in_txn(
        vault,
        rtxn,
        event.party_ref,
        PREDICATE_COMM_OPT_OUT,
        Some(channel),
        None,
        false,
    )?;
    if let Some((_, claim)) = history.iter().find(|(id, _)| *id == own) {
        return Ok(Some(claim.is_standing()));
    }
    let answered_later = latest_claim_transition_boundary(&history)
        .is_some_and(|boundary| event.occurred_at < boundary);
    Ok(answered_later.then_some(false))
}

fn apply_projector_rule_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    index: &CommProjectorIndex,
    event: &ProjectedCommEvent<'_>,
) -> CommResult<ProjectorIndexDelta> {
    let &ProjectedCommEvent {
        rule,
        source_event_id,
        party_ref,
        channel_class,
        thread_ref: _,
        occurred_at,
    } = event;
    match rule.action {
        ProjectorAction::UpsertLastTouch => {
            let channel = channel_class.ok_or(CommError::InvalidRecord)?;
            let active = matching_claims_in_txn(
                vault,
                &*wtxn,
                party_ref,
                rule.predicate,
                Some(channel),
                None,
                true,
            )?;
            let value = CommClaimValue::LastTouch {
                party_ref,
                channel_class: channel.to_owned(),
                occurred_at,
            };
            let (new_id, minted) =
                put_projected_comm_claim_in_txn(vault, wtxn, source_event_id, &value, occurred_at)?;
            if !minted {
                return Ok(ProjectorIndexDelta::default());
            }
            // Provider spellings normalize to one slot, so the slot can hold
            // more than one live head (F06 H415). The newest touch stays live
            // and supersedes every other; this touch wins a tie, and among
            // older heads the lowest id does.
            let mut older: Vec<(EntityId, u64)> = active
                .into_iter()
                .filter(|(id, _)| *id != new_id)
                .map(|(id, head)| (id, head.valid_from.unwrap_or(occurred_at)))
                .collect();
            older.sort_unstable_by_key(|(id, _)| *id);
            let mut heads = vec![(new_id, occurred_at)];
            heads.extend(older);
            let (winner, close_at) = heads
                .iter()
                .copied()
                .reduce(|best, head| if head.1 > best.1 { head } else { best })
                .unwrap_or((new_id, occurred_at));
            for (id, _) in heads {
                if id != winner {
                    vault.supersede_claim_in_txn(wtxn, &winner, &id, close_at)?;
                }
            }
            Ok(ProjectorIndexDelta::default())
        }
        ProjectorAction::SetOptOut => {
            let channel = channel_class.ok_or(CommError::InvalidRecord)?;
            let active = matching_claims_in_txn(
                vault,
                &*wtxn,
                party_ref,
                rule.predicate,
                Some(channel),
                None,
                true,
            )?;
            // Any live head on the normalized slot is a standing opt-out; two
            // provider-spelled heads are restrictive OR, not a conflict
            // (F06 H415).
            if active.is_empty() {
                let history = matching_claims_in_txn(
                    vault,
                    &*wtxn,
                    party_ref,
                    rule.predicate,
                    Some(channel),
                    None,
                    false,
                )?;
                let latest_transition = latest_claim_transition_boundary(&history);
                let value = CommClaimValue::OptOut {
                    party_ref,
                    channel_class: Some(channel.to_owned()),
                    reason: OPT_OUT_REASON_STOP.to_owned(),
                    occurred_at,
                };
                let (claim_id, minted) = put_projected_comm_claim_in_txn(
                    vault,
                    wtxn,
                    source_event_id,
                    &value,
                    occurred_at,
                )?;
                if minted
                    && let Some(boundary) =
                        latest_transition.filter(|boundary| occurred_at < *boundary)
                {
                    vault.retract_claim_in_txn(wtxn, &claim_id, boundary)?;
                }
                rematerialize_party_channel_contact_cache_in_txn(
                    vault,
                    wtxn,
                    party_ref,
                    channel,
                    occurred_at,
                )?;
                Ok(ProjectorIndexDelta::default())
            } else {
                // The pass index only NARROWS the candidates for this slot; the
                // decision to consume is made from the resident row read back
                // here, inside this event's own write transaction. A snapshot
                // gate that has since been deleted, consumed, re-keyed, or
                // re-pointed at a different claim is left alone for the next
                // pass — and a clear gate that outlives this STOP still fails
                // closed at approval time, which rechecks projected STOP
                // history against the live head.
                let key = PartyChannelKey {
                    party_ref,
                    channel_class: channel.to_owned(),
                };
                let mut consumed_gate_ids = Vec::new();
                for candidate in index.eligible_gates(&key, occurred_at) {
                    let Some(CommRecord::Gate {
                        party_ref: gate_party_ref,
                        channel_class: gate_channel,
                        claim_ref,
                        created_at,
                        pending,
                    }) = read_comm_record_in_txn(vault, &*wtxn, candidate.id)?
                    else {
                        continue;
                    };
                    if !pending
                        || gate_party_ref != party_ref
                        || normalize_channel_class(&gate_channel)
                            != normalize_channel_class(channel)
                        || claim_ref != candidate.claim_ref
                        || created_at > occurred_at
                    {
                        continue;
                    }
                    let consumed = CommRecord::Gate {
                        party_ref,
                        channel_class: channel.to_owned(),
                        claim_ref,
                        created_at,
                        pending: false,
                    };
                    put_comm_record_in_txn(vault, wtxn, candidate.id, &consumed)?;
                    consumed_gate_ids.push((key.clone(), candidate.id));
                }
                // The heads may have landed without the cache (replicated,
                // or written beside the projector), so a STOP on a standing
                // slot still leaves the contact row saying opted out.
                rematerialize_party_channel_contact_cache_in_txn(
                    vault,
                    wtxn,
                    party_ref,
                    channel,
                    occurred_at,
                )?;
                Ok(ProjectorIndexDelta {
                    consumed_gate_ids,
                    projected_thread_transition: None,
                })
            }
        }
        ProjectorAction::JoinThread | ProjectorAction::LeaveThread => {
            apply_thread_membership_in_txn(vault, wtxn, index, event)
        }
    }
}
