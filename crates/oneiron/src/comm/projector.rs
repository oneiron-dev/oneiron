//! Ordered idempotent projector pass and the record verbs that feed it.

use super::claims::{
    CommClaimValue, CommError, CommResult, PREDICATE_COMM_LAST_TOUCH, PREDICATE_COMM_OPT_OUT,
    PREDICATE_COMM_THREAD_MEMBER,
};
use super::consent::{OPT_OUT_REASON_STOP, rematerialize_party_channel_contact_cache_in_txn};
use super::parties::{reconcile_comm_party_twins, resolve_or_create_party_in_txn};
use super::projection_writes::{
    latest_claim_transition_boundary, matching_claims_in_txn, put_projected_comm_claim_in_txn,
    require_at_most_one,
};
use super::records::{
    CommEventKind, CommRecord, comm_records_in_txn, decode_comm_record, next_event_sequence_in_txn,
    put_comm_record_in_txn, read_comm_record_in_txn, validate_channel_class, validate_key_string,
};
use super::thread_membership::apply_thread_membership_in_txn;
use super::{
    CommProjectorIndex, PartyChannelKey, PartyThreadKey, ProjectedCommEvent, ProjectorIndexDelta,
    ProjectorRule,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::registry::ENTITY_TYPE_COMM_RECORD;

#[derive(Debug, Clone, Copy)]
pub(super) enum ProjectorAction {
    UpsertLastTouch,
    SetOptOut,
    JoinThread,
    LeaveThread,
}

const PROJECTOR_RULES: [ProjectorRule; 4] = [
    ProjectorRule {
        event_kind: CommEventKind::SendSucceeded,
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
    let records = {
        let rtxn = vault.store.env.read_txn()?;
        comm_records_in_txn(vault, &rtxn)?
    };
    let mut index = CommProjectorIndex::from_records(&records);
    drop(records);
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
            Err(error) => return Err(error),
        }
    }
    reconcile_comm_party_twins(vault, crate::unix_seconds_now())?;
    Ok(())
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
    record_event(
        vault,
        party,
        None,
        Some(thread_ref),
        if joined {
            CommEventKind::ThreadJoined
        } else {
            CommEventKind::ThreadLeft
        },
        occurred_at,
    )
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
    vault.try_with_write_txn(|wtxn| {
        // Resolve/create the party in the SAME transaction as the event so a
        // concurrent party deletion cannot leave the event bound to a missing
        // PERSON (which the projector would then skip forever as EntityNotFound).
        let thread_ref = thread_ref
            .map(|thread| crate::thread_passport::canonical_thread_ref_in_txn(vault, wtxn, thread))
            .transpose()?;
        let party_ref = resolve_or_create_party_in_txn(vault, wtxn, party)?;
        let sequence = next_event_sequence_in_txn(vault, wtxn)?;
        let record = CommRecord::Event {
            sequence,
            kind,
            party_ref,
            channel_class: channel_class.map(str::to_owned),
            thread_ref,
            occurred_at,
            projected: false,
        };
        put_comm_record_in_txn(vault, wtxn, EntityId::now(), &record)
    })
}

/// Projects one source event in its own write transaction, returning the index
/// changes the commit made true. `try_with_write_txn` yields `Ok` only after the
/// commit, so the caller can never fold in a delta that was rolled back.
pub(super) fn project_event(
    vault: &Vault,
    event_id: EntityId,
    index: &CommProjectorIndex,
) -> CommResult<ProjectorIndexDelta> {
    vault.try_with_write_txn(|wtxn| {
        let Some(raw) = vault.store.entities.get(&*wtxn, event_id.as_bytes())? else {
            return Ok(ProjectorIndexDelta::default());
        };
        let header = EntityMetadataHeader::parse(&raw).ok_or(CommError::InvalidRecord)?;
        if header.entity_type != ENTITY_TYPE_COMM_RECORD {
            return Err(CommError::InvalidRecord);
        }
        let record = decode_comm_record(&raw[ENTITY_METADATA_HEADER_LEN..])?;
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
        if projected {
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
        let delta = apply_projector_rule_in_txn(
            vault,
            wtxn,
            index,
            &ProjectedCommEvent {
                rule: *rule,
                source_event_id: event_id,
                party_ref,
                channel_class: channel_class.as_deref(),
                thread_ref: thread_ref.as_deref(),
                occurred_at,
            },
        )?;
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
        Ok(delta)
    })
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
            require_at_most_one(&active)?;
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
            if let Some((old_head_id, old_head)) = active.into_iter().find(|(id, _)| *id != new_id)
            {
                let head_at = old_head.valid_from.unwrap_or(occurred_at);
                let close_at = occurred_at.max(head_at);
                if occurred_at >= head_at {
                    vault.supersede_claim_in_txn(wtxn, &new_id, &old_head_id, close_at)?;
                } else {
                    vault.supersede_claim_in_txn(wtxn, &old_head_id, &new_id, close_at)?;
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
            require_at_most_one(&active)?;
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
                        || gate_channel != channel
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
