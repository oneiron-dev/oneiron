//! Pinned cohort reads and per-destination source admission.
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use oneiron::claim::{PointRead, decode_claim_body};
use oneiron::memory::ReadMode;
use oneiron::rerank::RerankCandidate;
use oneiron::retrieval_depth::narrow_to_session_scope;
use oneiron::settings::{ReadDestination, ReleaseHold};
use oneiron::{EntityId, LlmRequest};
use serde_json::Value;

use super::super::read_rows::{ReadRequests, ReadRows};
use super::{Backend, invalid};
use crate::models::{SourceAdmission, SourceOffer};

#[derive(Clone)]
pub(super) struct Pin {
    pub(super) id: EntityId,
    pub(super) revision: oneiron::memory::RevisionRef,
    pub(super) body_hash: [u8; 32],
    pub(super) text: String,
}

pub(super) struct PinCohort {
    // Pins and their text drop before their memory charge.
    rows: Vec<Pin>,
    memory: oneiron::host_memory::MemoryLease,
}

impl PinCohort {
    pub(super) fn with_capacity(
        memory: &oneiron::host_memory::MachineMemory,
        capacity: usize,
    ) -> Self {
        let mut cohort = Self {
            rows: Vec::with_capacity(capacity),
            memory: memory.empty_lease(),
        };
        cohort
            .memory
            .materialized(0, pin_backing_bytes(cohort.rows.capacity()));
        cohort
    }

    pub(super) fn push(&mut self, pin: Pin) {
        let text = pin.text.capacity() as u64;
        let previous_capacity = self.rows.capacity();
        self.rows.push(pin);
        let backing = pin_backing_bytes(self.rows.capacity() - previous_capacity);
        self.memory.materialized(0, backing.saturating_add(text));
    }

    pub(super) fn as_slice(&self) -> &[Pin] {
        &self.rows
    }
}

fn pin_backing_bytes(capacity: usize) -> u64 {
    (capacity as u64).saturating_mul(std::mem::size_of::<Pin>() as u64)
}

pub(super) fn rerank_pins(
    backend: &Backend,
    candidates: &[RerankCandidate<'_>],
) -> oneiron::Result<PinCohort> {
    if candidates.is_empty() {
        return Ok(PinCohort::with_capacity(&backend.server.memory, 0));
    }
    let mut revisions = Vec::with_capacity(candidates.len());
    let mut refs = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let Some(revision) = candidate.revision else {
            return Err(invalid("memory reason rerank candidate has no revision"));
        };
        revisions.push(revision);
        refs.push(PointRead::id(candidate.id).at(ReadMode::Pinned(revision)));
    }
    let scoped = crate::api::scoped_read_for_core_auth(&backend.server.vault, &backend.auth)
        .map_err(|_| invalid("memory reason pinned read failed"))?;
    let refs = ReadRequests::new(&backend.server.memory, refs);
    let read = scoped.read(refs.as_slice(), None)?;
    drop(refs);
    let oneiron::claim::ScopedReadResult {
        value: rows,
        receipt,
    } = read;
    let mut rows = ReadRows::new(&backend.server.memory, rows);
    backend
        .reads
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(receipt);
    if rows.len() != candidates.len() {
        return Err(invalid("memory reason rerank pin is not readable"));
    }
    let mut pins = PinCohort::with_capacity(&backend.server.memory, candidates.len());
    for ((candidate, revision), row) in candidates.iter().zip(revisions).zip(rows.drain()) {
        let Some(oneiron::claim::ReadRow {
            entity_type,
            learned_at,
            body: Some(body),
            ..
        }) = row
        else {
            return Err(invalid("memory reason rerank pin is not readable"));
        };
        let body_hash = *blake3::hash(&body).as_bytes();
        if let Some(admitted) = candidate.claim {
            if entity_type != oneiron::registry::ENTITY_TYPE_CLAIM {
                return Err(invalid("memory reason rerank claim has the wrong kind"));
            }
            let expected = format!(
                "{}: {}",
                admitted.predicate,
                oneiron::serialize::msgpack_value_to_json(&admitted.value)
            );
            let decoded = decode_claim_body(&body, true)?;
            if decoded.predicate != admitted.predicate
                || oneiron::serialize::msgpack_value_to_json(&decoded.value)
                    != oneiron::serialize::msgpack_value_to_json(&admitted.value)
            {
                return Err(invalid("memory reason rerank claim changed"));
            }
            let actual = format!(
                "{}: {}",
                decoded.predicate,
                oneiron::serialize::msgpack_value_to_json(&decoded.value)
            );
            if actual != expected {
                return Err(invalid("memory reason rerank claim changed"));
            }
        }
        let Value::Object(fields) = crate::projection::project_entity_parts(
            &backend.server.vault,
            &candidate.id,
            entity_type,
            learned_at,
            &body,
            crate::projection::View::Full,
        ) else {
            return Err(invalid("memory reason rerank pin projection failed"));
        };
        let text = match (candidate.claim, fields.get("pred"), fields.get("val")) {
            (Some(_), Some(Value::String(predicate)), Some(value)) => {
                format!("{predicate}: {value}")
            }
            _ => super::super::evidence_text(&fields),
        };
        pins.push(Pin {
            id: candidate.id,
            revision,
            body_hash,
            text,
        });
    }
    drop(rows);
    Ok(pins)
}

pub(super) fn compose_pins(
    backend: &Backend,
    evidence: &[super::super::MemoryReasonEvidence],
) -> oneiron::Result<PinCohort> {
    if evidence.is_empty() {
        return Ok(PinCohort::with_capacity(&backend.server.memory, 0));
    }
    let refs: Vec<_> = evidence
        .iter()
        .map(|row| PointRead::id(row.id).at(ReadMode::Pinned(row.revision)))
        .collect();
    let scoped = crate::api::scoped_read_for_core_auth(&backend.server.vault, &backend.auth)
        .map_err(|_| invalid("memory reason pinned read failed"))?;
    let refs = ReadRequests::new(&backend.server.memory, refs);
    let read = scoped.read(refs.as_slice(), None)?;
    drop(refs);
    let oneiron::claim::ScopedReadResult {
        value: rows,
        receipt,
    } = read;
    let mut rows = ReadRows::new(&backend.server.memory, rows);
    backend
        .reads
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(receipt);
    if rows.len() != evidence.len() {
        return Err(invalid("memory reason compose pin is not readable"));
    }
    let mut pins = PinCohort::with_capacity(&backend.server.memory, evidence.len());
    for (expected, row) in evidence.iter().zip(rows.drain()) {
        let Some(oneiron::claim::ReadRow {
            entity_type,
            learned_at,
            body: Some(body),
            ..
        }) = row
        else {
            return Err(invalid("memory reason compose pin is not readable"));
        };
        let body_hash = *blake3::hash(&body).as_bytes();
        let Value::Object(fields) = crate::projection::project_entity_parts(
            &backend.server.vault,
            &expected.id,
            entity_type,
            learned_at,
            &body,
            crate::projection::View::Full,
        ) else {
            return Err(invalid("memory reason compose pin projection failed"));
        };
        let text = super::super::evidence_text(&fields);
        if text != expected.text {
            return Err(invalid("memory reason compose evidence changed"));
        }
        pins.push(Pin {
            id: expected.id,
            revision: expected.revision,
            body_hash,
            text,
        });
    }
    drop(rows);
    Ok(pins)
}

pub(super) struct Sources<'a> {
    backend: &'a Backend,
    pins: &'a [Pin],
    sent: Mutex<Option<Sent>>,
}

#[derive(Clone)]
struct Sent {
    destination: ReadDestination,
    hashes: Vec<[u8; 32]>,
}

impl<'a> Sources<'a> {
    pub(super) fn new(backend: &'a Backend, pins: &'a [Pin]) -> Self {
        Self {
            backend,
            pins,
            sent: Mutex::new(None),
        }
    }

    fn read_for(&self, destination: &ReadDestination) -> Result<Vec<[u8; 32]>, &'static str> {
        if !self
            .backend
            .auth
            .credential_is_live(&self.backend.server.vault)
        {
            return Err(ReleaseHold::Placement.reason());
        }
        let ids: Vec<EntityId> = self.pins.iter().map(|pin| pin.id).collect();
        let base =
            crate::api::scoped_read_for_core_auth(&self.backend.server.vault, &self.backend.auth)
                .map_err(|_| ReleaseHold::Placement.reason())?;
        let reader = self
            .backend
            .server
            .vault
            .scoped_read(base.actor_key().clone().for_destination(destination));
        let refs: Vec<_> = self
            .pins
            .iter()
            .map(|pin| PointRead::id(pin.id).at(ReadMode::Pinned(pin.revision)))
            .collect();
        let refs = ReadRequests::new(&self.backend.server.memory, refs);
        let read = reader
            .read(refs.as_slice(), None)
            .map_err(|_| ReleaseHold::Placement.reason())?;
        drop(refs);
        let oneiron::claim::ScopedReadResult {
            value: rows,
            receipt,
        } = read;
        let mut rows = ReadRows::new(&self.backend.server.memory, rows);
        self.backend
            .reads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(receipt);
        if rows.len() != self.pins.len() {
            return Err(hold_reason(&self.backend.server.vault, &ids, destination));
        }
        let mut hashes = Vec::with_capacity(self.pins.len());
        for (pin, row) in self.pins.iter().zip(rows.drain()) {
            let Some(oneiron::claim::ReadRow {
                body: Some(body), ..
            }) = row
            else {
                return Err(hold_reason(&self.backend.server.vault, &ids, destination));
            };
            let hash = *blake3::hash(&body).as_bytes();
            if hash != pin.body_hash {
                return Err(hold_reason(&self.backend.server.vault, &ids, destination));
            }
            hashes.push(hash);
        }
        drop(rows);
        let hits: Vec<oneiron::ScoredEntity> = self
            .pins
            .iter()
            .map(|pin| oneiron::ScoredEntity {
                id: pin.id,
                score: 0.0,
            })
            .collect();
        let mut revisions = HashMap::with_capacity(self.pins.len());
        for pin in self.pins {
            revisions.insert(pin.id, pin.revision);
        }
        let mut scope_receipts = Vec::new();
        let kept = match narrow_to_session_scope(
            &reader,
            hits,
            &revisions,
            &self.backend.scope,
            &mut scope_receipts,
        ) {
            Ok(kept) => {
                self.backend
                    .reads
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend(scope_receipts);
                kept
            }
            Err(_) => {
                self.backend
                    .reads
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend(scope_receipts);
                return Err(ReleaseHold::Placement.reason());
            }
        };
        if kept.len() != self.pins.len() {
            return Err(hold_reason(&self.backend.server.vault, &ids, destination));
        }
        match self
            .backend
            .server
            .vault
            .release_hold_for(&ids, destination)
        {
            Ok(Some(hold)) => Err(hold.reason()),
            Ok(None) => Ok(hashes),
            Err(_) => Err(ReleaseHold::Placement.reason()),
        }
    }
}

impl SourceAdmission for Sources<'_> {
    fn offer(&self, request: &LlmRequest, destination: &ReadDestination) -> SourceOffer {
        let hashes = match self.read_for(destination) {
            Ok(hashes) => hashes,
            Err(reason) => return SourceOffer::Held(reason),
        };
        *self.sent.lock().unwrap_or_else(PoisonError::into_inner) = Some(Sent {
            destination: destination.clone(),
            hashes,
        });
        SourceOffer::Send(request.clone())
    }

    fn recheck(&self, destination: &ReadDestination) -> Option<&'static str> {
        let sent = self
            .sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(sent) = sent.filter(|kept| kept.destination == *destination) else {
            return Some(ReleaseHold::Placement.reason());
        };
        let hashes = match self.read_for(destination) {
            Ok(hashes) => hashes,
            Err(reason) => return Some(reason),
        };
        if hashes != sent.hashes {
            let ids: Vec<EntityId> = self.pins.iter().map(|pin| pin.id).collect();
            return Some(hold_reason(&self.backend.server.vault, &ids, destination));
        }
        None
    }
}

fn hold_reason(
    vault: &oneiron::Vault,
    ids: &[EntityId],
    destination: &ReadDestination,
) -> &'static str {
    match vault.release_hold_for(ids, destination) {
        Ok(Some(hold)) => hold.reason(),
        _ => ReleaseHold::Placement.reason(),
    }
}
