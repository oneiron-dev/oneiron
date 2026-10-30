//! Ordered idempotent projector pass and the record verbs that feed it.

use std::collections::BTreeSet;

use super::claims::{
    CommClaimValue, CommError, CommResult, PREDICATE_COMM_LAST_TOUCH, PREDICATE_COMM_OPT_OUT,
    PREDICATE_COMM_THREAD_MEMBER,
};
use super::consent::{OPT_OUT_REASON_STOP, rematerialize_party_channel_contact_cache_in_txn};
use super::parties::{
    reconcile_comm_party_twins, resolve_actor_party_in_txn, resolve_or_create_party_in_txn,
};
use super::projection_writes::{
    latest_claim_transition_boundary, matching_claims_in_txn, put_projected_comm_claim_in_txn,
};
use super::receipt_import::import_delivered_send_receipts;
use super::records::{
    CommEventKind, CommRecord, comm_records_in_txn, decode_comm_record, next_event_sequence_in_txn,
    put_comm_record_in_txn, read_comm_record_in_txn, validate_channel_class, validate_key_string,
};
use super::stop_hold::{
    holds_pending_stop_in_txn, peer_stop_projection_in_txn, pending_stop_ids_in_txn,
    release_pending_stop_in_txn,
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
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_COMM_RECORD;

pub(crate) use super::inbound_events::{
    record_comm_inbound_reply_in_txn, record_comm_inbound_stop_in_txn,
};

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
    run_comm_projector_capped(vault, usize::MAX)
}

/// The most new delivered receipts one housekeeping pass imports, and the
/// most pending events it projects; the rest wait for the next pass.
const HOUSEKEEPING_PROJECTOR_BATCH: usize = 256;

/// The housekeeping pass's projector step: one [`run_comm_projector`] pass
/// capped at [`HOUSEKEEPING_PROJECTOR_BATCH`], so messages no connector reply
/// job follows (inbound mail, provider sends, thread events) still project.
/// A pass with no new receipt and no pending event opens no write. A failed
/// pass is logged and never fails the caller; the next pass retries what it
/// left.
pub(crate) fn run_comm_projector_housekeeping_step(vault: &Vault) {
    if let Err(error) = run_comm_projector_capped(vault, HOUSEKEEPING_PROJECTOR_BATCH) {
        tracing::warn!(
            %error,
            "housekeeping: communication projector pass failed; it is retried on the next pass"
        );
    }
}

/// [`run_comm_projector`] importing at most `max_writes` new delivered
/// receipts and projecting at most `max_writes` pending events, in sequence
/// order; the rest wait for the next pass.
fn run_comm_projector_capped(vault: &Vault, max_writes: usize) -> CommResult<()> {
    import_delivered_send_receipts(vault, max_writes)?;
    let mut index = {
        let rtxn = vault.store.env.read_txn()?;
        projector_index_in_txn(vault, &rtxn)?
    };
    let mut first_refusal = None;
    for event_id in index.pending_event_ids().into_iter().take(max_writes) {
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

/// The pass index over `txn`'s snapshot of the COMM_RECORD family and the
/// STOPs this replica has not released.
fn projector_index_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> CommResult<CommProjectorIndex> {
    let records = comm_records_in_txn(vault, txn)?;
    let pending_stops = pending_stop_ids_in_txn(&vault.store, txn)?;
    Ok(CommProjectorIndex::from_records(&records, &pending_stops))
}

/// The projector's step for source events a caller's write records, run in
/// that write, so the head each one authors stands when the write commits.
/// The events share one pass index over the write's own snapshot, built
/// when the first event whose rule reads it projects.
#[derive(Default)]
pub(super) struct RecordedEventProjection {
    index: Option<CommProjectorIndex>,
    /// The source events projected so far and the rows their steps wrote:
    /// the heads and the gates they consumed.
    written: BTreeSet<EntityId>,
}

impl RecordedEventProjection {
    /// Projects `event_id`, a `kind` source event this write recorded,
    /// through the pass's own step in a savepoint of `wtxn`, and notes the
    /// event and the rows its step writes. An event the pass leaves waiting
    /// (its party not here yet, or a refusal) rolls the savepoint back and
    /// stays pending for the housekeeping pass; a storage failure fails the
    /// write.
    pub(super) fn project_in_txn(
        &mut self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        event_id: EntityId,
        kind: CommEventKind,
    ) -> CommResult<()> {
        self.written.insert(event_id);
        let rows = if rule_reads_index(kind) {
            let mut index = match self.index.take() {
                Some(index) => index,
                None => projector_index_in_txn(vault, &*wtxn)?,
            };
            let projected = project_in_savepoint(vault, wtxn, event_id, &mut index);
            self.index = Some(index);
            projected?
        } else {
            let mut unread = CommProjectorIndex::default();
            project_in_savepoint(vault, wtxn, event_id, &mut unread)?
        };
        self.written.extend(rows);
        Ok(())
    }

    /// The source events projected and the rows their steps wrote.
    pub(super) fn into_written(self) -> BTreeSet<EntityId> {
        self.written
    }
}

/// Whether the rule `kind` fires reads the pass index: a touch's never does.
fn rule_reads_index(kind: CommEventKind) -> bool {
    PROJECTOR_RULES
        .iter()
        .find(|rule| rule.event_kind == kind)
        .is_none_or(|rule| !matches!(rule.action, ProjectorAction::UpsertLastTouch))
}

fn project_in_savepoint(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_id: EntityId,
    index: &mut CommProjectorIndex,
) -> CommResult<BTreeSet<EntityId>> {
    let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
    match project_event_in_txn(vault, &mut savepoint, event_id, index) {
        Ok(delta) => {
            savepoint.commit()?;
            let rows = delta.written_rows(event_id);
            index.apply_committed(delta);
            Ok(rows)
        }
        Err(CommError::Engine(error)) if storage_failure(&error) => Err(CommError::Engine(error)),
        Err(_) => {
            index.forget_accounted_txn();
            Ok(BTreeSet::new())
        }
    }
}

pub(super) fn storage_failure(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Storage | ErrorKind::Io | ErrorKind::MapFull
    )
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
        )?;
        Ok(())
    })
}

/// Writes one unprojected source event for `party_ref` at the next event
/// sequence, in the caller's write: the channel class normalized, the thread
/// as its canonical ref. Returns the event's id; the projector's next pass
/// projects it.
pub(super) fn put_source_event_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party_ref: EntityId,
    kind: CommEventKind,
    channel_class: Option<&str>,
    thread_ref: Option<&str>,
    occurred_at: u64,
) -> CommResult<EntityId> {
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
    let id = vault.store.clock.entity_id()?;
    put_comm_record_in_txn(vault, wtxn, id, &record)?;
    Ok(id)
}

/// Projects one source event in its own write transaction, returning the index
/// changes the commit made true. `try_with_write_txn` yields `Ok` only after the
/// commit, so the caller can never fold in a delta that was rolled back. The
/// rows the step wrote go to the live-window mirror when the write commits.
pub(super) fn project_event(
    vault: &Vault,
    event_id: EntityId,
    index: &CommProjectorIndex,
) -> CommResult<ProjectorIndexDelta> {
    // A write group of its own, so the index can tell its own commit from
    // any other writer's (`CommProjectorIndex::begin_event_txn`).
    vault.try_with_write_txn(|wtxn| {
        let delta = project_event_in_txn(vault, wtxn, event_id, index)?;
        #[cfg(feature = "sync")]
        crate::batch::queue_committed_rows(vault, wtxn, delta.written_rows(event_id));
        Ok(delta)
    })
}

/// [`project_event`]'s step in `wtxn`: the pass and the in-write projection
/// of a recorded event ([`RecordedEventProjection`]) both run it.
fn project_event_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_id: EntityId,
    index: &CommProjectorIndex,
) -> CommResult<ProjectorIndexDelta> {
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
                    heads: Vec::new(),
                    source_stamped: false,
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
    let mut delta = if projected {
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
        delta.source_stamped = true;
    }
    if pending_stop {
        release_pending_stop_in_txn(&vault.store, wtxn, &event_id)?;
    }
    index.expect_own_commit();
    Ok(delta)
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
            for &(id, _) in &heads {
                if id != winner {
                    vault.supersede_claim_in_txn(wtxn, &winner, &id, close_at)?;
                }
            }
            // Each head on the slot was written: minted, superseded, or the
            // winner its supersessions point from.
            Ok(ProjectorIndexDelta {
                heads: heads.into_iter().map(|(id, _)| id).collect(),
                ..ProjectorIndexDelta::default()
            })
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
                Ok(ProjectorIndexDelta {
                    heads: minted.then_some(claim_id).into_iter().collect(),
                    ..ProjectorIndexDelta::default()
                })
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
                    heads: Vec::new(),
                    source_stamped: false,
                })
            }
        }
        ProjectorAction::JoinThread | ProjectorAction::LeaveThread => {
            apply_thread_membership_in_txn(vault, wtxn, index, event)
        }
    }
}
