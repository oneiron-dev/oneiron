//! Communication standing-state claims and the ARCH-0035 projector.
//!
//! Directory module. `claims` holds the `comm.*` claim family; `records` the
//! COMM_RECORD storage and codec; `parties` the party identity doors;
//! `projector` the ordered projector pass; `projection_writes` the
//! deterministic claim writes; `consent` the human gates, send overrides and
//! standing opt-out folds; `thread_membership` the alias-aware membership
//! reads. This file keeps the seam (module declarations and the re-exports
//! that preserve every `crate::comm::` path), the projector's pass index,
//! and the test-only scan counters.

mod claims;
mod consent;
mod parties;
mod projection_writes;
mod projector;
mod records;
mod thread_membership;

#[cfg(test)]
mod tests;

pub(crate) use self::claims::validate_comm_claim_structure;
pub use self::claims::{
    COMM_CLAIM_PREDICATES, COMM_SCHEMA_VERSION, ClaimClassDescriptorRow, CommClaim, CommClaimValue,
    CommClearOptOutOutcome, CommError, CommResult, PREDICATE_COMM_LAST_TOUCH,
    PREDICATE_COMM_OPT_OUT, PREDICATE_COMM_REACHABLE_VIA, PREDICATE_COMM_SEND_OVERRIDE,
    PREDICATE_COMM_THREAD_MEMBER, SendOverrideMatch, SendOverrideScope, claim_class_descriptors,
    is_comm_claim_predicate,
};
pub use self::consent::{
    approve_pending_opt_out_clear, count_active_comm_claims, count_active_thread_member_claims,
    count_contact_record_claim_entries, count_opt_out_clear_receipts,
    count_pending_comm_consent_gates, count_total_comm_claim_rows, drop_contact_record,
    materialize_contact_record, mint_send_override, request_opt_out_clear, send_override_for_send,
};
pub(crate) use self::consent::{
    send_override_for_send_in_txn, standing_opt_out_heads_in_txn,
    supersede_party_opt_out_head_in_txn,
};
pub use self::parties::resolve_or_create_comm_party;
pub(crate) use self::parties::{resolve_party_ref_from_store_in_txn, resolve_party_ref_in_txn};
pub use self::projector::{
    record_comm_inbound_stop, record_comm_send_receipt, record_comm_thread_event,
    run_comm_projector,
};
pub(crate) use self::records::validate_comm_record_body_bytes;

use std::collections::{BTreeMap, HashMap, HashSet};

use self::projector::ProjectorAction;
use self::records::{CommEventKind, CommRecord, read_comm_record_in_txn};
use self::thread_membership::{canonical_member_ref, equivalent_thread_keys};
use crate::Vault;
use crate::entity_id::EntityId;

// The pass index lives here, not in `projector`, because its private fields
// and private methods are used by `thread_membership`, `projector` and the
// tests alike: a child module sees its parent's private items, a sibling
// does not.
#[derive(Debug, Clone, Copy)]
struct ProjectorRule {
    event_kind: CommEventKind,
    predicate: &'static str,
    action: ProjectorAction,
}

/// One `(party, channel_class)` standing-state slot — the key an opt-out clear
/// gate is filed under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PartyChannelKey {
    party_ref: EntityId,
    channel_class: String,
}

/// One `(party, thread_ref)` membership slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PartyThreadKey {
    party_ref: EntityId,
    thread_ref: String,
}

/// A pending clear gate as the pass snapshot saw it. Every field is snapshot
/// data: nothing here is written back without re-reading the resident row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedGate {
    id: EntityId,
    claim_ref: EntityId,
    created_at: u64,
}

/// Pass-local index over one decoded COMM_RECORD snapshot.
///
/// The projector used to re-walk the whole type-136 family for every pending
/// event — candidate clear gates for a `STOP`, the latest projected thread
/// boundary for a join/leave — which made one pass O(P·R) in P pending events
/// and R records. One snapshot answers all of those lookups instead, at
/// O(R + P log P) plus the rows actually mutated.
///
/// This is a snapshot, never a source of truth and never persisted: every id it
/// hands out is re-read and revalidated inside the event's own write
/// transaction before anything is mutated, and the index advances only from
/// deltas returned by transactions that already committed. Records written
/// after the snapshot are simply picked up by the next pass.
#[derive(Debug, Default)]
struct CommProjectorIndex {
    /// Unprojected source events as `(sequence, id)`, sequence ascending.
    pending_events: Vec<(u64, EntityId)>,
    pending_gates: HashMap<PartyChannelKey, Vec<IndexedGate>>,
    latest_projected_thread_transition: HashMap<PartyThreadKey, (u64, bool)>,
    /// Snapshotted pending join/leave event ids by membership slot. A
    /// join/leave deciding before this pass's cursor reaches a same-key entry
    /// re-reads only these rows, so a peer pass's already-committed transition
    /// still bounds the decision instead of being folded too late, after an
    /// earlier retried join already minted standing membership.
    pending_thread_events: HashMap<PartyThreadKey, Vec<EntityId>>,
}

impl CommProjectorIndex {
    fn from_records(records: &[(EntityId, CommRecord)]) -> Self {
        let mut index = Self::default();
        for (id, record) in records {
            match record {
                CommRecord::Event {
                    sequence,
                    kind,
                    party_ref,
                    thread_ref,
                    projected: false,
                    ..
                } => {
                    index.pending_events.push((*sequence, *id));
                    if matches!(
                        kind,
                        CommEventKind::ThreadJoined | CommEventKind::ThreadLeft
                    ) && let Some(thread_ref) = thread_ref
                    {
                        index
                            .pending_thread_events
                            .entry(PartyThreadKey {
                                party_ref: *party_ref,
                                thread_ref: thread_ref.clone(),
                            })
                            .or_default()
                            .push(*id);
                    }
                }
                CommRecord::Event {
                    kind: kind @ (CommEventKind::ThreadJoined | CommEventKind::ThreadLeft),
                    party_ref,
                    thread_ref: Some(thread_ref),
                    occurred_at,
                    projected: true,
                    ..
                } => index.note_thread_transition(
                    PartyThreadKey {
                        party_ref: *party_ref,
                        thread_ref: thread_ref.clone(),
                    },
                    (*occurred_at, *kind == CommEventKind::ThreadLeft),
                ),
                CommRecord::Gate {
                    party_ref,
                    channel_class,
                    claim_ref,
                    created_at,
                    pending: true,
                } => index
                    .pending_gates
                    .entry(PartyChannelKey {
                        party_ref: *party_ref,
                        channel_class: channel_class.clone(),
                    })
                    .or_default()
                    .push(IndexedGate {
                        id: *id,
                        claim_ref: *claim_ref,
                        created_at: *created_at,
                    }),
                _ => {}
            }
        }
        // Stable, so records that somehow share a sequence keep the family
        // scan's id order rather than an arbitrary one.
        index.pending_events.sort_by_key(|(sequence, _)| *sequence);
        index
    }

    /// Pending source events in this pass's projection order.
    fn pending_event_ids(&self) -> Vec<EntityId> {
        self.pending_events.iter().map(|(_, id)| *id).collect()
    }

    /// Clear gates that a `STOP` at `stop_at` may consume, as candidates only.
    fn eligible_gates(&self, key: &PartyChannelKey, stop_at: u64) -> Vec<IndexedGate> {
        let Some(gates) = self.pending_gates.get(key) else {
            return Vec::new();
        };
        gates
            .iter()
            .copied()
            .filter(|gate| gate.created_at <= stop_at)
            .collect()
    }

    /// Newest already-projected join/leave boundary for one membership slot.
    fn latest_thread_transition(
        &self,
        key: &PartyThreadKey,
        aliases: &BTreeMap<String, String>,
    ) -> Option<u64> {
        self.latest_thread_boundary(key, aliases).map(|(at, _)| at)
    }

    fn latest_thread_boundary(
        &self,
        key: &PartyThreadKey,
        aliases: &BTreeMap<String, String>,
    ) -> Option<(u64, bool)> {
        equivalent_thread_keys(key, aliases)
            .iter()
            .filter_map(|candidate| {
                self.latest_projected_thread_transition
                    .get(candidate)
                    .copied()
            })
            .max()
    }

    fn note_thread_transition(&mut self, key: PartyThreadKey, boundary: (u64, bool)) {
        self.latest_projected_thread_transition
            .entry(key)
            .and_modify(|latest| *latest = (*latest).max(boundary))
            .or_insert(boundary);
    }

    /// Latest membership boundary from snapshotted same-key join/leave events
    /// that a peer pass has already committed — including entries still AHEAD
    /// of this pass's cursor, which neither the snapshot nor `apply_committed`
    /// can have folded yet. This restores exactly what the pre-index
    /// in-transaction family rescan observed for the slot at decision time,
    /// by re-reading only the snapshotted candidate rows: O(pending same-key),
    /// never a COMM_RECORD family scan. Rows still pending (or failed soft)
    /// are not boundaries and skip themselves; the deciding event's own row is
    /// excluded, since it cannot be projected before its rule runs inside this
    /// event's write transaction.
    fn peer_projected_thread_transition_in_txn(
        &self,
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        key: &PartyThreadKey,
        source_event_id: EntityId,
    ) -> CommResult<Option<(u64, bool)>> {
        let mut latest = None;
        let aliases = crate::thread_passport::thread_aliases_in_txn(vault, rtxn)?;
        let keys = equivalent_thread_keys(key, &aliases);
        let candidates = keys
            .iter()
            .filter_map(|candidate| self.pending_thread_events.get(candidate))
            .flatten();
        for candidate_id in candidates {
            if *candidate_id == source_event_id {
                continue;
            }
            let Some(CommRecord::Event {
                kind: kind @ (CommEventKind::ThreadJoined | CommEventKind::ThreadLeft),
                party_ref,
                thread_ref: Some(thread_ref),
                occurred_at,
                projected: true,
                ..
            }) = read_comm_record_in_txn(vault, rtxn, *candidate_id)?
            else {
                continue;
            };
            if party_ref == key.party_ref
                && canonical_member_ref(&aliases, &thread_ref)
                    == canonical_member_ref(&aliases, &key.thread_ref)
            {
                latest = latest.max(Some((occurred_at, kind == CommEventKind::ThreadLeft)));
            }
        }
        Ok(latest)
    }

    /// Folds in the effects of one event whose transaction HAS COMMITTED.
    /// Applying a delta before the commit would let a rolled-back event poison
    /// every later lookup in the pass.
    fn apply_committed(&mut self, delta: ProjectorIndexDelta) {
        let mut consumed_by_key: HashMap<PartyChannelKey, HashSet<EntityId>> = HashMap::new();
        for (key, gate_id) in delta.consumed_gate_ids {
            consumed_by_key.entry(key).or_default().insert(gate_id);
        }
        for (key, consumed_ids) in consumed_by_key {
            let Some(gates) = self.pending_gates.get_mut(&key) else {
                continue;
            };
            note_pending_gate_retain();
            gates.retain(|gate| !consumed_ids.contains(&gate.id));
            if gates.is_empty() {
                self.pending_gates.remove(&key);
            }
        }
        if let Some((key, occurred_at)) = delta.projected_thread_transition {
            self.note_thread_transition(key, occurred_at);
        }
    }
}

/// Index changes one committed event authorizes. Empty for events that mutate
/// no indexed row.
#[derive(Debug, Default)]
struct ProjectorIndexDelta {
    consumed_gate_ids: Vec<(PartyChannelKey, EntityId)>,
    projected_thread_transition: Option<(PartyThreadKey, (u64, bool))>,
}

/// One source COMM_RECORD event, resolved to the projector rule it fires.
/// Bundled so the deterministic id's source event travels with the inputs it is
/// derived from rather than as one more positional argument.
#[derive(Debug, Clone, Copy)]
struct ProjectedCommEvent<'a> {
    rule: ProjectorRule,
    source_event_id: EntityId,
    party_ref: EntityId,
    channel_class: Option<&'a str>,
    thread_ref: Option<&'a str>,
    occurred_at: u64,
}

// Test-only tally of full COMM_RECORD family scans, per thread so parallel
// tests cannot see each other's scans. The projector's pass index exists to
// keep this count at one per pass however many events the pass projects.
#[cfg(test)]
thread_local! {
    static COMM_RECORD_FAMILY_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_comm_record_family_scan() {
    COMM_RECORD_FAMILY_SCANS.with(|scans| scans.set(scans.get().saturating_add(1)));
}

#[cfg(test)]
thread_local! {
    static PENDING_GATE_RETAINS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_pending_gate_retain() {
    PENDING_GATE_RETAINS.with(|retains| retains.set(retains.get().saturating_add(1)));
}

#[cfg(not(test))]
const fn note_pending_gate_retain() {}

#[cfg(not(test))]
const fn note_comm_record_family_scan() {}

// The flat comm.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every comm-internal item the tests name bare. After the directory split the
// seam re-imports both so `tests.rs` (and its `#[path]` child
// `thread_alias_tests.rs`) resolve exactly as they did before.
#[cfg(test)]
use self::{claims::*, consent::*, parties::*, projection_writes::*, projector::*, records::*};
#[cfg(test)]
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, apply_ops};
#[cfg(test)]
use crate::claim::ClaimSource;
#[cfg(test)]
use crate::edge::{EdgeActorClass, EdgeKind};
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::vault::entity_id_from_type_index_key;
#[cfg(test)]
use crate::write_envelope::WriteActor;
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::collections::BTreeSet;
