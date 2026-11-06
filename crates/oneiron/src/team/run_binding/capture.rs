//! Explicitly published projections of newly authored native team starts.

use serde::{Deserialize, Serialize};

use super::{StoredTeamRunBinding, TEAM_RUN, TeamRunBinding, prepare_team_start_in_txn, run_key};
use crate::batch::VadPostcommitScope;
use crate::claim::{
    ClaimBody, ClaimLifecycleStatus, PointRead, ReadRow, ScopedRead, ScopedReadActorKey,
    decode_claim_body,
};
use crate::team::run::{CapturePosition, capture_claim_in_txn};
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::claim_body::encode_claim_body;
use crate::{EntityId, Error, Result, Vault};

const START_PREDICATE: &str = "team.start.membership";

/// Only the start's newly authored output, never the leader's private TASK or payload.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartProjection {
    stamp: crate::agent_dispatch::TeamRunStamp,
    leader: crate::attempt_queue::AttemptId,
    started_at: u64,
    members: Vec<crate::attempt_queue::AttemptId>,
    proposals: Vec<String>,
}

impl From<&TeamRunBinding> for StartProjection {
    fn from(run: &TeamRunBinding) -> Self {
        Self {
            stamp: run.stamp.clone(),
            leader: run.leader,
            started_at: run.started_at,
            members: run.members.clone(),
            proposals: run.proposals.clone(),
        }
    }
}

/// A body binding, not a grant to read the private native row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TeamStartSource {
    claim: EntityId,
    claim_hash: [u8; 32],
    native_key: String,
    native_run_hash: [u8; 32],
}

impl TeamStartSource {
    pub(super) fn matches_native(&self, key: &str, run: &TeamRunBinding) -> bool {
        self.native_key == key
            && run_key(run.leader, &run.stamp.team_ref) == key
            && native_run_hash(run).ok() == Some(self.native_run_hash)
    }

    pub(crate) fn claim(&self) -> EntityId {
        self.claim
    }

    fn admitted_projection(&self, row: Option<ReadRow>, team_ref: &str) -> Option<StartProjection> {
        let row = row?;
        if row.id != self.claim || row.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return None;
        }
        let body = decode_claim_body(row.body.as_deref()?, true).ok()?;
        if body.predicate != START_PREDICATE
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.stale
            || claim_hash(&body).ok()? != self.claim_hash
        {
            return None;
        }
        let projection: StartProjection = serde_json::from_str(body.value.as_str()?).ok()?;
        (projection.stamp.team_ref == team_ref).then_some(projection)
    }

    pub(crate) fn admitted_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        row: Option<ReadRow>,
        team_ref: &str,
    ) -> Option<EntityId> {
        // The protected projection is admitted before any private native lookup.
        let projection = self.admitted_projection(row, team_ref)?;
        let native = TEAM_RUN.get(&vault.store, txn, &self.native_key).ok()??;
        // A deletion/recreation or a displaced source cannot revive an old witness.
        if native.projection_source.as_ref() != Some(self)
            || !self.matches_native(&self.native_key, &native.run)
            || projection != StartProjection::from(&native.run)
        {
            return None;
        }
        Some(self.claim)
    }
}

/// The ordinary start writer with optional publication of its own new projection.
/// Replays and capture failures keep the original native write.
pub(crate) fn record_team_start_captured(
    vault: &Vault,
    run: &TeamRunBinding,
    source_rows: Option<Vec<EntityId>>,
    selected: &crate::memory::ClaimScope,
    envelope: &WriteEnvelope,
    read_key: ScopedReadActorKey,
    now: u64,
) -> Result<()> {
    let position = CapturePosition::resolve(vault, selected);
    let reader = vault.scoped_read(read_key);
    let ready = position.is_some() && reader.persist_grant_clock().is_ok();
    vault.with_write_txn_grouped(|txn| {
        let (key, mut row, fresh) = prepare_team_start_in_txn(vault, txn, run, source_rows)?;
        if fresh && ready {
            row.projection_source = position.as_ref().and_then(|position| {
                capture_in_savepoint(vault, txn, &reader, &key, &row, position, envelope, now).ok()
            });
        }
        TEAM_RUN.put(&vault.store, txn, &key, &row)
    })
}

fn capture_in_savepoint(
    vault: &Vault,
    parent: &mut heed::RwTxn<'_>,
    reader: &ScopedRead<'_>,
    key: &str,
    row: &StoredTeamRunBinding,
    position: &CapturePosition,
    envelope: &WriteEnvelope,
    now: u64,
) -> Result<TeamStartSource> {
    let mut child = vault.store.env.nested_write_txn(parent)?;
    let postcommit = VadPostcommitScope::new(vault, &child);
    let projection = StartProjection::from(&row.run);
    let original = serde_json::to_string(&projection).map_err(|_| unavailable())?;
    let (claim, body) = capture_claim_in_txn(
        vault,
        &mut child,
        START_PREDICATE,
        original,
        position,
        envelope,
        now,
    )?;
    let source = TeamStartSource {
        claim,
        claim_hash: claim_hash(&body)?,
        native_key: key.to_owned(),
        native_run_hash: native_run_hash(&row.run)?,
    };
    let admitted =
        reader.read_projected_in_txn(&child, &[PointRead::id(claim)], None, |_, rows| {
            Ok::<_, Error>(rows)
        })?;
    if source.admitted_projection(
        admitted.value.into_iter().next().flatten(),
        &row.run.stamp.team_ref,
    ) != Some(projection)
    {
        return Err(unavailable());
    }
    child.commit()?;
    postcommit.merge_into(vault, parent);
    Ok(source)
}

fn claim_hash(body: &ClaimBody) -> Result<[u8; 32]> {
    Ok(*blake3::hash(&encode_claim_body(body)?).as_bytes())
}

// Canonical bytes of every native run field, including the private TASK binding.
// Source metadata is separate, avoiding a self-referential hash.
fn native_run_hash(run: &TeamRunBinding) -> Result<[u8; 32]> {
    let body = rmp_serde::to_vec_named(run).map_err(|_| unavailable())?;
    Ok(*blake3::hash(&body).as_bytes())
}

fn unavailable() -> Error {
    Error::InvariantViolation("team start capture unavailable")
}
