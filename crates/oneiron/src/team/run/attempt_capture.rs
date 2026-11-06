//! Scoped publication of a newly enqueued member's own dispatch output.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::type_source::CapturedTeamType;
use super::{CapturePosition, SelectedTeamType, capture_claim_in_txn};
use crate::agent_dispatch::{AgentDispatchStatus, decode_agent_dispatch_input};
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::batch::VadPostcommitScope;
use crate::claim::{ClaimLifecycleStatus, PointRead, ReadRow, ScopedRead, ScopedReadActorKey};
use crate::store::dreamer_attempt_payload::{
    KEY_PRODUCER_SOURCE, decode_dreamer_attempt_payload, decode_value,
    encode_dreamer_attempt_payload, encode_value,
};
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::claim_body::encode_claim_body;
use crate::{EntityId, Error, Result, Vault};

const ATTEMPT_PREDICATE: &str = "team.member.dispatch";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchProjection {
    attempt: AttemptId,
    created_at: u64,
    team: crate::agent_dispatch::TeamRunStamp,
}

impl DispatchProjection {
    fn of(record: &AttemptRecord) -> Result<Self> {
        let payload = decode_dreamer_attempt_payload(&record.payload)?;
        let input = decode_agent_dispatch_input(&payload.input)?;
        Ok(Self {
            attempt: record.id,
            created_at: record.created_at,
            team: input.team.ok_or_else(unavailable)?,
        })
    }
}

/// One physical attempt value an original host or depth-fold read observed.
/// A hash or an absent value records provenance only, never native permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TeamParentRead {
    attempt: AttemptId,
    value_hash: Option<[u8; 32]>,
}

impl TeamParentRead {
    pub(crate) fn observed(attempt: AttemptId, value: Option<&[u8]>) -> Self {
        Self {
            attempt,
            value_hash: value.map(|value| *blake3::hash(value).as_bytes()),
        }
    }
}

/// The native pointer and complete immutable input binding, never a read grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TeamAttemptSource {
    claim: EntityId,
    claim_hash: [u8; 32],
    native_attempt: AttemptId,
    birth_hash: [u8; 32],
    type_source: Option<CapturedTeamType>,
    depth_parent_reads: Vec<TeamParentRead>,
    host_parent_read: TeamParentRead,
}

impl TeamAttemptSource {
    pub(crate) fn claim(&self) -> EntityId {
        self.claim
    }

    pub(crate) fn of(record: &AttemptRecord) -> Option<Self> {
        // The normal decoder validates the complete envelope, including duplicates.
        decode_dreamer_attempt_payload(&record.payload).ok()?;
        let Value::Map(entries) = decode_value(&record.payload).ok()? else {
            return None;
        };
        let bytes = entries.into_iter().find_map(|(key, value)| {
            (key.as_str() == Some(KEY_PRODUCER_SOURCE)).then_some(value)
        })?;
        let Value::Binary(bytes) = bytes else {
            return None;
        };
        let source: Self = rmp_serde::from_slice(&bytes).ok()?;
        (source.native_attempt == record.id && birth_hash(record).ok() == Some(source.birth_hash))
            .then_some(source)
    }

    fn admitted_projection(&self, row: Option<ReadRow>) -> Option<DispatchProjection> {
        let row = row?;
        if row.id != self.claim || row.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return None;
        }
        let body = crate::claim::decode_claim_body(row.body.as_deref()?, true).ok()?;
        if body.predicate != ATTEMPT_PREDICATE
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.stale
            || *blake3::hash(&encode_claim_body(&body).ok()?).as_bytes() != self.claim_hash
        {
            return None;
        }
        serde_json::from_str(body.value.as_str()?).ok()
    }

    pub(crate) fn admitted_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        row: Option<ReadRow>,
    ) -> Option<EntityId> {
        // Admit the published output before looking up the private native row.
        let projection = self.admitted_projection(row)?;
        let native = crate::attempt_queue::AttemptQueue::new(vault)
            .get_in_txn(txn, self.native_attempt)
            .ok()??;
        if Self::of(&native).as_ref() != Some(self)
            || DispatchProjection::of(&native).ok()? != projection
        {
            return None;
        }
        Some(self.claim)
    }

    pub(crate) fn admitted_sources_in_txn(
        &self,
        reader: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        row: Option<ReadRow>,
    ) -> Option<Vec<EntityId>> {
        let mut sources = vec![self.admitted_in_txn(reader.vault(), txn, row)?];
        if let Some(type_source) = &self.type_source {
            sources.extend(type_source.admitted_in_txn(reader, txn)?);
        }
        Some(sources)
    }
}

/// The actual live caller, borrowed for this one enqueue. Nothing is serialized
/// into a replacement caller, owner key, or native-row permission.
pub(crate) struct TeamAttemptCapture {
    key: ScopedReadActorKey,
    position: CapturePosition,
    envelope: WriteEnvelope,
    team: crate::agent_dispatch::TeamRunStamp,
    host_parent_read: TeamParentRead,
    _body_pins: Option<crate::store::result_body_pins::ResultBodyPin>,
}

impl TeamAttemptCapture {
    pub(crate) fn new(
        vault: &Vault,
        selected: &crate::memory::ClaimScope,
        envelope: WriteEnvelope,
        key: ScopedReadActorKey,
        team: &crate::agent_dispatch::TeamRunStamp,
        host_parent_read: &TeamParentRead,
    ) -> Option<Self> {
        let position = CapturePosition::resolve(vault, selected)?;
        vault.scoped_read(key.clone()).persist_grant_clock().ok()?;
        Some(Self {
            key,
            position,
            envelope,
            team: team.clone(),
            host_parent_read: host_parent_read.clone(),
            _body_pins: crate::store::ASSET_FILE_PLANE.then(|| vault.pin_all_result_bodies()),
        })
    }

    /// Called only by the new-enqueue arm, after its original native writes.
    /// Any capture failure discards only this optional publication.
    pub(crate) fn capture_in_txn(
        &self,
        vault: &Vault,
        parent: &mut heed::RwTxn<'_>,
        status: &AgentDispatchStatus,
        type_selection: Option<&SelectedTeamType>,
        depth_parent_reads: &[TeamParentRead],
        now: u64,
    ) -> Option<AttemptRecord> {
        self.capture(
            vault,
            parent,
            &status.attempt,
            type_selection,
            depth_parent_reads,
            now,
        )
        .ok()
    }

    fn capture(
        &self,
        vault: &Vault,
        parent: &mut heed::RwTxn<'_>,
        record: &AttemptRecord,
        type_selection: Option<&SelectedTeamType>,
        depth_parent_reads: &[TeamParentRead],
        now: u64,
    ) -> Result<AttemptRecord> {
        let projection = DispatchProjection {
            attempt: record.id,
            created_at: record.created_at,
            team: self.team.clone(),
        };
        if DispatchProjection::of(record)? != projection {
            return Err(unavailable());
        }
        let mut child = vault.store.env.nested_write_txn(parent)?;
        let postcommit = VadPostcommitScope::new(vault, &child);
        let (claim, body) = capture_claim_in_txn(
            vault,
            &mut child,
            ATTEMPT_PREDICATE,
            serde_json::to_string(&projection).map_err(|_| unavailable())?,
            &self.position,
            &self.envelope,
            now,
        )?;
        let reader = vault.scoped_read(self.key.clone());
        let input =
            decode_agent_dispatch_input(&decode_dreamer_attempt_payload(&record.payload)?.input)?;
        let type_source = type_selection
            .filter(|selected| {
                input.project_ref == Some(selected.project)
                    && input.type_ref == selected.placed_type
            })
            .and_then(|selected| CapturedTeamType::capture(&reader, &child, selected));
        let source = TeamAttemptSource {
            claim,
            claim_hash: *blake3::hash(&encode_claim_body(&body)?).as_bytes(),
            native_attempt: record.id,
            birth_hash: birth_hash(record)?,
            type_source,
            depth_parent_reads: depth_parent_reads.to_vec(),
            host_parent_read: self.host_parent_read.clone(),
        };
        let admitted =
            reader.read_projected_in_txn(&child, &[PointRead::id(claim)], None, |_, rows| {
                Ok::<_, Error>(rows)
            })?;
        if source.admitted_projection(admitted.value.into_iter().next().flatten())
            != Some(projection)
        {
            return Err(unavailable());
        }
        let mut record = record.clone();
        let Value::Map(mut entries) = decode_value(&record.payload)? else {
            return Err(unavailable());
        };
        // New native rows carry no previous pointer. Typed rewrites omit it,
        // and a retry's different id cannot match this birth binding.
        if entries
            .iter()
            .any(|(key, _)| key.as_str() == Some(KEY_PRODUCER_SOURCE))
        {
            return Err(unavailable());
        }
        entries.push((
            Value::from(KEY_PRODUCER_SOURCE),
            Value::Binary(rmp_serde::to_vec_named(&source).map_err(|_| unavailable())?),
        ));
        record.payload = encode_value(&Value::Map(entries), "team attempt source encode failed")?;
        let encoded = crate::store::attempt_record_codec::encode_record(&record)?;
        vault
            .store
            .attempt_records
            .put(&mut child, record.id.as_bytes(), &encoded)?;
        child.commit()?;
        postcommit.merge_into(vault, parent);
        Ok(record)
    }
}

fn birth_hash(record: &AttemptRecord) -> Result<[u8; 32]> {
    // All original payload fields, including private input and parent, but no
    // source metadata. Mutable lease/state/manifest fields are separate cohorts.
    let payload =
        encode_dreamer_attempt_payload(&decode_dreamer_attempt_payload(&record.payload)?)?;
    let bytes = rmp_serde::to_vec_named(&(record.id, &record.kind, record.created_at, payload))
        .map_err(|_| unavailable())?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn unavailable() -> Error {
    Error::InvariantViolation("team attempt source unavailable")
}
