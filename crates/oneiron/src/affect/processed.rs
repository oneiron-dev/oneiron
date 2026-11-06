//! Processed marks on memories: the `affect.processed` state claim the
//! engine writes once a memory is worked through, and the admitted read the
//! unprocessed selection filters by.

use crate::ports::EdgeDirection;
use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;
use std::collections::BTreeSet;

use rmpv::Value;

use super::Vad;
use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, ScopedRead,
    decode_claim_body, encode_claim_body,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::scan_check::{EngineScan, ScanCount};
use crate::temporal::TimeRange;
use crate::vault::{CLAIM_OF_DEFAULT_WEIGHT, SUPERSEDES_DEFAULT_WEIGHT};

pub const AFFECT_PROCESSED_PREDICATE: &str = "affect.processed";
const PROCESSED_KEY_PROCESSED_AT: &str = "processed_at";
const PROCESSED_KEY_RESOLUTION_STATUS: &str = "resolution_status";

struct StoredProcessedState {
    id: EntityId,
    header: EntityMetadataHeader,
    body: ClaimBody,
}

impl Vault {
    /// Marks `subject` processed: writes an Active `affect.processed` state
    /// claim over it and supersedes every prior Active mark, in one write
    /// transaction. The subject must be a stored CLAIM; the mark stands on
    /// the subject's own audience axes, never wider (FIX 9553 shape).
    /// Engine writer only; no door calls it yet (FIX 9449).
    pub fn mark_memory_processed(
        &self,
        subject: EntityId,
        resolution_status: Option<&str>,
        now: u64,
    ) -> Result<EntityId> {
        let mut wtxn = self.store.env.write_txn()?;
        let subject_body = {
            let raw = self
                .store
                .port_entity_record(&wtxn, &subject)?
                .map(|row| row.encode())
                .ok_or(Error::EntityNotFound)?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
            }
            crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?
        };
        let active_states = self.active_processed_states_in_txn(&wtxn, &subject)?;
        let state_claim_id = self.store.clock.entity_id()?;
        let mut body = ClaimBody::new(
            AFFECT_PROCESSED_PREDICATE,
            ClaimSubject::Entity(subject),
            processed_value(now, resolution_status),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        body.source = Some(ClaimSource::Inferred);
        super::consolidation::copy_claim_axes(&mut body, &subject_body);
        body.valid_from = Some(now);
        let data = encode_claim_body(&body)?;
        let mut ops = Vec::new();
        ops.push(BatchOp::Put {
            id: state_claim_id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: now,
                end: u64::MAX,
            },
            learned_at: now,
            row_version: None,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        });
        ops.push(BatchOp::Edge {
            src: state_claim_id,
            kind: EdgeKind::ClaimOf,
            tgt: subject,
            weight: CLAIM_OF_DEFAULT_WEIGHT,
            vad: Vad::NEUTRAL,
        });
        Self::close_processed_states(&mut ops, active_states, now, Some(state_claim_id))?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(state_claim_id)
    }

    fn close_processed_states(
        ops: &mut Vec<BatchOp>,
        active_states: Vec<StoredProcessedState>,
        now: u64,
        successor: Option<EntityId>,
    ) -> Result<Vec<EntityId>> {
        let mut superseded_claim_ids = Vec::with_capacity(active_states.len());
        for state in active_states {
            let mut closed = state.body;
            closed.lifecycle = ClaimLifecycleStatus::Superseded;
            closed.valid_to = Some(now);
            let closed_data = encode_claim_body(&closed)?;
            ops.push(BatchOp::Put {
                id: state.id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: state.header.occurred_start,
                    end: now,
                },
                learned_at: state.header.learned_at,
                row_version: None,
                data: closed_data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
            if let Some(successor) = successor {
                ops.push(BatchOp::EdgeWithCreatedAt {
                    src: successor,
                    kind: EdgeKind::Supersedes,
                    tgt: state.id,
                    weight: SUPERSEDES_DEFAULT_WEIGHT,
                    created_at: now,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                });
            }
            superseded_claim_ids.push(state.id);
        }
        Ok(superseded_claim_ids)
    }

    fn active_processed_states_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        subject: &EntityId,
    ) -> Result<Vec<StoredProcessedState>> {
        let mut states = Vec::new();
        let kind = EdgeKind::ClaimOf;
        let scope = [
            &[EdgeDirection::In as u8][..],
            subject.as_bytes(),
            &[kind as u8][..],
        ]
        .concat();
        let mut count = ScanCount::start(&self.store, txn, EngineScan::EdgePeerRows, &scope)?;
        for entry in self
            .store
            .port_edges(txn, subject, EdgeDirection::In, Some(kind), None)?
        {
            count.row();
            let edge_row = entry?;
            let state_id = edge_row.target;
            let Some(raw) = self
                .store
                .port_entity_record(txn, &state_id)?
                .map(|row| row.encode())
            else {
                continue;
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                continue;
            }
            let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if body.predicate == AFFECT_PROCESSED_PREDICATE
                && body.subject == ClaimSubject::Entity(*subject)
                && body.lifecycle == ClaimLifecycleStatus::Active
            {
                states.push(StoredProcessedState {
                    id: state_id,
                    header,
                    body,
                });
            }
        }
        count.finish(self);
        states.sort_by_key(|state| state.id);
        Ok(states)
    }
}

/// The subjects of `subjects` carrying an admitted Active `affect.processed`
/// state: each subject's inbound `claim_of` ids, admitted through the
/// caller's read, so a mark the read withholds counts as absent (fail open).
pub(crate) fn processed_subjects(
    read: &ScopedRead<'_>,
    subjects: &[EntityId],
) -> Result<BTreeSet<EntityId>> {
    let mut pairs = Vec::new();
    for subject in subjects {
        for claim_id in read.vault().claims_for_subject(subject)? {
            pairs.push((claim_id, *subject));
        }
    }
    let mut processed = BTreeSet::new();
    if pairs.is_empty() {
        return Ok(processed);
    }
    let ids: Vec<EntityId> = pairs.iter().map(|(id, _)| *id).collect();
    let admitted = read.get_entities_parts_with_receipt(&ids, None)?.value;
    for ((_, subject), parts) in pairs.into_iter().zip(admitted) {
        let Some((entity_type, _, body)) = parts else {
            continue;
        };
        if entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        let Ok(claim) = decode_claim_body(&body, true) else {
            continue;
        };
        if claim.predicate == AFFECT_PROCESSED_PREDICATE
            && claim.subject == ClaimSubject::Entity(subject)
            && claim.lifecycle == ClaimLifecycleStatus::Active
        {
            processed.insert(subject);
        }
    }
    Ok(processed)
}

/// An `affect.processed` state value: when the mark landed, plus the
/// resolution status when the writer names one.
fn processed_value(processed_at: u64, resolution_status: Option<&str>) -> Value {
    let mut entries = vec![(
        Value::from(PROCESSED_KEY_PROCESSED_AT),
        Value::from(processed_at),
    )];
    if let Some(status) = resolution_status {
        entries.push((
            Value::from(PROCESSED_KEY_RESOLUTION_STATUS),
            Value::from(status),
        ));
    }
    Value::Map(entries)
}
