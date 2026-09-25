//! In-memory transactional conformance adapter. Commit is explicit; drop rolls back.
mod auxiliary;
mod query;
use super::*;
use crate::attempt_queue::*;
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::deletion::TombstoneValueV2;
use crate::edge::EdgeInfo;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::registry::*;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};
use crate::{EdgeKind, EntityId, TimeRange};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};
#[derive(Clone, Default)]
pub(super) struct Snapshot {
    entities: BTreeMap<EntityId, EntityRecord>,
    sessions: BTreeMap<EntityId, EntityId>,
    edges: BTreeMap<(EntityId, u8, EntityId), Vec<u8>>,
    vectors: BTreeMap<EntityId, Vec<f32>>,
    texts: BTreeMap<EntityId, String>,
    phonetic: BTreeMap<String, BTreeSet<EntityId>>,
    shorts: BTreeMap<EntityId, (String, u8)>,
    counters: BTreeMap<u8, u64>,
    tombstones: BTreeMap<EntityId, TombstoneValueV2>,
    stale: BTreeSet<EntityId>,
    stale_revision: BTreeMap<EntityId, u64>,
    dependencies: BTreeMap<SourceSpan, BTreeSet<EntityId>>,
    changes: BTreeMap<[u8; 16], ChangeLogRecord>,
    blobs: BTreeMap<[u8; 32], (Vec<u8>, BTreeSet<EntityId>)>,
    jobs: BTreeMap<[u8; 16], AttemptRecord>,
}
pub(super) struct MemoryWrite(Snapshot);
impl Deref for MemoryWrite {
    type Target = Snapshot;
    fn deref(&self) -> &Snapshot {
        &self.0
    }
}
impl DerefMut for MemoryWrite {
    fn deref_mut(&mut self) -> &mut Snapshot {
        &mut self.0
    }
}
pub(super) struct Memory {
    committed: RefCell<Snapshot>,
    pub(super) clock: StoreClock,
}
impl Memory {
    fn audit_mutation(
        &self,
        txn: &mut MemoryWrite,
        entity: EntityId,
        op: ChangeOp,
        occurred_at: u64,
        input: &[u8],
    ) -> Result<()> {
        self.port_changelog_append(
            txn,
            &ChangeLogRecord {
                id: self.clock.ulid()?,
                entity,
                op,
                actor_principal: super::mutation::storage_service_principal()?,
                actor_person: None,
                occurred_at,
                recorded_at: self.clock.now_recorded_at(),
                input_hash: *blake3::hash(input).as_bytes(),
                patch: None,
                reason: None,
            },
        )
    }
    pub(super) fn new(clock: StoreClock) -> Self {
        Self {
            committed: RefCell::new(Snapshot::default()),
            clock,
        }
    }
    pub(super) fn record_turn_session(
        &self,
        txn: &mut MemoryWrite,
        turn: EntityId,
        session: EntityId,
    ) {
        txn.sessions.entry(turn).or_insert(session);
    }
    pub(super) fn read(&self) -> Snapshot {
        self.committed.borrow().clone()
    }
    pub(super) fn write(&self) -> MemoryWrite {
        MemoryWrite(self.read())
    }
    pub(super) fn commit(&self, txn: MemoryWrite) {
        self.committed.replace(txn.0);
    }
}
impl Transactions for Memory {
    type Read<'a> = Snapshot;
    type Write<'a> = MemoryWrite;
}
impl EntityStore for Memory {
    fn port_entity_get(&self, txn: &Snapshot, id: &EntityId) -> Result<Option<EntityRecord>> {
        if txn.stale.contains(id) || txn.tombstones.contains_key(id) {
            return Ok(None);
        }
        let row = txn.entities.get(id);
        if row.is_some_and(|r| r.entity_type == ENTITY_TYPE_SECRET_CUSTODY) {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }
        Ok(row
            .filter(|row| !super::safe_read::body_is_stale(&row.body))
            .cloned())
    }
    fn port_entity_put(
        &self,
        txn: &mut MemoryWrite,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<()> {
        if let Some(old) = txn.entities.get(id)
            && old.entity_type != row.entity_type
        {
            return Err(Error::Registry(
                crate::error::RegistryError::EntityTypeImmutable {
                    id: *id,
                    existing: old.entity_type,
                    attempted: row.entity_type,
                },
            ));
        }
        if txn.entities.get(id) != Some(row) {
            let op = if txn.entities.contains_key(id) {
                ChangeOp::Update
            } else {
                ChangeOp::Create
            };
            self.audit_mutation(txn, *id, op, row.occurred.start, &row.body)?;
        }
        txn.entities.insert(*id, row.clone());
        if crate::registry::short_id_prefix(row.entity_type).is_ok() {
            self.port_short_id_get_or_create(txn, id)?;
        }
        Ok(())
    }
    fn port_entity_delete(&self, txn: &mut MemoryWrite, id: &EntityId) -> Result<bool> {
        let deps: BTreeSet<_> = txn
            .dependencies
            .iter()
            .filter(|(source, _)| source.document == *id)
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();
        for dependent in deps {
            self.port_retrieval_mark_stale(txn, &dependent)?;
            self.port_job_enqueue(
                txn,
                EnqueueAttempt {
                    kind: "derived.regenerate".into(),
                    payload: [id.as_bytes().as_slice(), dependent.as_bytes()].concat(),
                    dedupe_key: Some(format!("{}:{}", id.to_hex(), dependent.to_hex())),
                    run_id: None,
                    now: 0,
                },
            )?;
        }
        txn.edges.retain(|(s, _, d), _| s != id && d != id);
        txn.shorts.remove(id);
        txn.vectors.remove(id);
        txn.texts.remove(id);
        let existed = txn.entities.remove(id).is_some();
        if existed {
            self.audit_mutation(
                txn,
                *id,
                ChangeOp::Delete,
                self.clock.now_recorded_at(),
                id.as_bytes(),
            )?;
        }
        Ok(existed)
    }
    fn port_list_turns_by_session(
        &self,
        txn: &Snapshot,
        session: &EntityId,
    ) -> Result<Vec<EntityId>> {
        Ok(txn
            .sessions
            .iter()
            .filter(|(_, value)| *value == session)
            .map(|(id, _)| *id)
            .filter(|id| {
                txn.entities
                    .get(id)
                    .is_some_and(|row| row.entity_type == ENTITY_TYPE_TURN)
                    && !txn.stale.contains(id)
                    && !txn.tombstones.contains_key(id)
            })
            .collect())
    }
    fn port_list_sessions_by_relationship(
        &self,
        txn: &Snapshot,
        relationship: &EntityId,
    ) -> Result<Vec<EntityId>> {
        memory_related(self, txn, ENTITY_TYPE_SESSION, "rel", relationship)
    }
    fn port_list_summaries_by_level(&self, txn: &Snapshot, level: u64) -> Result<Vec<EntityId>> {
        memory_matching(self, txn, ENTITY_TYPE_SUMMARY, |v| {
            super::lmdb_entity::field(v, "level").and_then(rmpv::Value::as_u64) == Some(level)
        })
    }
    fn port_list_assets_by_relationship(
        &self,
        txn: &Snapshot,
        relationship: &EntityId,
    ) -> Result<Vec<EntityId>> {
        memory_related(self, txn, ENTITY_TYPE_ASSET, "rel", relationship)
    }
}
fn memory_matching(
    memory: &Memory,
    txn: &Snapshot,
    kind: u8,
    predicate: impl Fn(&rmpv::Value) -> bool,
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for (id, row) in &txn.entities {
        if row.entity_type != kind || memory.port_entity_get(txn, id)?.is_none() {
            continue;
        }
        if ids.len() >= 100_000 {
            return Err(Error::IndexOverflow("port type index"));
        }
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&row.body))
            .map_err(|_| Error::CorruptedIndex("named entity query body"))?;
        if predicate(&value) {
            ids.push(*id);
        }
    }
    Ok(ids)
}
fn memory_related(
    memory: &Memory,
    txn: &Snapshot,
    kind: u8,
    field: &str,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    memory_matching(
        memory,
        txn,
        kind,
        |v| matches!(super::lmdb_entity::field(v,field),Some(rmpv::Value::Binary(bytes)) if bytes.as_slice()==id.as_bytes()),
    )
}
impl EdgeStore for Memory {
    fn port_edge_upsert(
        &self,
        txn: &mut MemoryWrite,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
        weight: f32,
    ) -> Result<()> {
        crate::edge::validate_public_edge_creation_kind(kind)?;
        let bytes = crate::edge::encode_edge_value(
            kind,
            weight,
            self.clock.now_recorded_at(),
            crate::affect::Vad::NEUTRAL,
            None,
        )?;
        if kind == EdgeKind::DerivedFrom {
            let row = txn.entities.get(dst).ok_or(Error::EntityNotFound)?;
            let source = SourceSpan {
                document: *dst,
                frontier: row.learned_at,
            };
            self.port_dependency_put(txn, source, src)?;
        }
        txn.edges.insert((*src, kind as u8, *dst), bytes);
        Ok(())
    }
    fn port_edge_mark_stale(
        &self,
        txn: &mut MemoryWrite,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
    ) -> Result<bool> {
        self.port_edge_delete(txn, src, kind, dst)
    }
    fn port_edge_delete(
        &self,
        txn: &mut MemoryWrite,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
    ) -> Result<bool> {
        crate::edge::validate_public_edge_kind(kind)?;
        Ok(txn.edges.remove(&(*src, kind as u8, *dst)).is_some())
    }
    fn port_edge_neighbors(
        &self,
        txn: &Snapshot,
        id: &EntityId,
        direction: EdgeDirection,
        kind: Option<EdgeKind>,
        limit: usize,
    ) -> Result<Vec<EdgeInfo>> {
        let mut out = Vec::new();
        for d in [EdgeDirection::Out, EdgeDirection::In] {
            if direction != EdgeDirection::Both && direction != d {
                continue;
            }
            for ((src, k, dst), value) in &txn.edges {
                let (owner, peer) = if d == EdgeDirection::Out {
                    (src, dst)
                } else {
                    (dst, src)
                };
                if owner != id || kind.is_some_and(|kind| kind as u8 != *k) {
                    continue;
                }
                if out.len() >= limit {
                    return Ok(out);
                }
                let key = [owner.as_bytes().as_slice(), &[*k], peer.as_bytes()].concat();
                out.push(crate::edge::parse_strict_edge_record(&key, value)?.into_edge_info());
            }
        }
        Ok(out)
    }
    fn port_edge_list_by_dst(
        &self,
        txn: &Snapshot,
        id: &EntityId,
        kind: Option<EdgeKind>,
        after: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        let mut ids = self
            .port_edge_neighbors(txn, id, EdgeDirection::In, kind, 100_000)?
            .into_iter()
            .map(|e| e.target)
            .filter(|id| after.is_none_or(|a| id > a))
            .collect::<Vec<_>>();
        ids.sort();
        ids.dedup();
        ids.truncate(limit);
        Ok(ids)
    }
}
impl PlaceStore for Memory {
    fn port_place_get(&self, txn: &Snapshot, id: &EntityId) -> Result<Option<EntityRecord>> {
        let row = self.port_entity_get(txn, id)?;
        if row
            .as_ref()
            .is_some_and(|r| r.entity_type != ENTITY_TYPE_PLACE)
        {
            return Err(Error::CorruptedIndex("place type"));
        }
        Ok(row)
    }
    fn port_place_put(
        &self,
        txn: &mut MemoryWrite,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<()> {
        if row.entity_type != ENTITY_TYPE_PLACE {
            return Err(Error::InvalidConfig("place type".into()));
        }
        self.port_entity_put(txn, id, row)
    }
    fn port_place_find_by_provider_id(
        &self,
        txn: &Snapshot,
        provider: &str,
        provider_id: &str,
    ) -> Result<Vec<EntityId>> {
        memory_matching(self, txn, ENTITY_TYPE_PLACE, |v| {
            super::lmdb_entity::field(v, "provider").and_then(rmpv::Value::as_str) == Some(provider)
                && super::lmdb_entity::field(v, "providerId").and_then(rmpv::Value::as_str)
                    == Some(provider_id)
        })
    }
    fn port_place_find_by_name(&self, txn: &Snapshot, name: &str) -> Result<Vec<EntityId>> {
        memory_matching(self, txn, ENTITY_TYPE_PLACE, |v| {
            super::lmdb_entity::field(v, "name").and_then(rmpv::Value::as_str) == Some(name)
        })
    }
    fn port_place_list_children(&self, txn: &Snapshot, id: &EntityId) -> Result<Vec<EntityId>> {
        let mut ids = Vec::new();
        for child in self.port_edge_list_by_dst(txn, id, Some(EdgeKind::ChildOf), None, 100_000)? {
            if self
                .port_entity_get(txn, &child)?
                .is_some_and(|r| r.entity_type == ENTITY_TYPE_PLACE)
            {
                ids.push(child);
            }
        }
        Ok(ids)
    }
}
impl ClaimStore for Memory {
    fn port_claim_get(&self, txn: &Snapshot, id: &EntityId) -> Result<Option<ClaimBody>> {
        let Some(row) = txn.entities.get(id) else {
            return Ok(None);
        };
        if row.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        crate::claim::decode_claim_body(&row.body, true).map(Some)
    }
    fn port_claim_put(
        &self,
        txn: &mut MemoryWrite,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let body = candidate.into_claim_body(
            envelope,
            crate::claim::substrate_facet_id(envelope.actor().entity_ref()),
        );
        let bytes = crate::claim::encode_claim_body(&body)?;
        crate::claim::validate_claim_body_bytes(&bytes, false)?;
        if let ClaimSubject::Entity(subject) = body.subject {
            if !txn.entities.contains_key(&subject) {
                return Err(Error::EntityNotFound);
            }
            self.port_entity_put(
                txn,
                id,
                &EntityRecord {
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred,
                    learned_at,
                    body: bytes,
                },
            )?;
            self.port_edge_upsert(txn, id, EdgeKind::ClaimOf, &subject, 1.0)?;
        } else {
            self.port_entity_put(
                txn,
                id,
                &EntityRecord {
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred,
                    learned_at,
                    body: bytes,
                },
            )?;
        }
        Ok(())
    }
    fn port_claim_list(&self, txn: &Snapshot, subject: &EntityId) -> Result<Vec<EntityId>> {
        self.port_edge_list_by_dst(txn, subject, Some(EdgeKind::ClaimOf), None, 100_000)
    }
    fn port_claim_list_by_predicate(
        &self,
        txn: &Snapshot,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let mut rows = Vec::new();
        for (id, row) in &txn.entities {
            if row.entity_type == ENTITY_TYPE_CLAIM {
                let body = self.port_claim_get(txn, id)?.ok_or(Error::EntityNotFound)?;
                if body.predicate == predicate {
                    rows.push((*id, body));
                }
            }
        }
        Ok(rows)
    }
    fn port_claim_get_active(
        &self,
        txn: &Snapshot,
        subject: &EntityId,
        predicate: &str,
    ) -> Result<Option<(EntityId, ClaimBody)>> {
        Ok(self
            .port_claim_predicate_history(txn, subject, predicate)?
            .into_iter()
            .rev()
            .find(|(id, body)| {
                body.lifecycle == ClaimLifecycleStatus::Active
                    && !body.stale
                    && !txn.stale.contains(id)
                    && !txn.tombstones.contains_key(id)
            }))
    }
    fn port_claim_supersede_chain(&self, txn: &Snapshot, id: &EntityId) -> Result<Vec<EntityId>> {
        let mut rows = Vec::new();
        let mut current = *id;
        loop {
            if rows.contains(&current) {
                return Err(Error::CorruptedIndex("claim supersede cycle"));
            }
            if rows.len() >= 10_000 {
                return Err(Error::IndexOverflow("claim supersede chain"));
            }
            rows.push(current);
            let next =
                self.port_edge_list_by_dst(txn, &current, Some(EdgeKind::Supersedes), None, 2)?;
            match next.as_slice() {
                [] => break,
                [id] => current = *id,
                _ => return Err(Error::CorruptedIndex("forked supersede chain")),
            }
        }
        Ok(rows)
    }
    fn port_claim_predicate_history(
        &self,
        txn: &Snapshot,
        subject: &EntityId,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let mut rows = Vec::new();
        for id in self.port_claim_list(txn, subject)? {
            if let Some(body) = self.port_claim_get(txn, &id)?
                && body.predicate == predicate
            {
                rows.push((id, body));
            }
        }
        rows.sort_by_key(|(id, _)| (txn.entities[id].learned_at, *id));
        Ok(rows)
    }
    fn port_claim_find_conflicting(
        &self,
        txn: &Snapshot,
        subject: &EntityId,
        predicate: &str,
    ) -> Result<Option<(EntityId, ClaimBody)>> {
        self.port_claim_get_active(txn, subject, predicate)
    }
}
