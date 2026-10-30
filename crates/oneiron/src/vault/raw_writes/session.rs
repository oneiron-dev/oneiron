//! A bound raw handle inside the off-record session it names (FIX 8119,
//! 8603), and the verified caller's envelope on its claim puts (FIX 8118).
//!
//! The raw native handles (N-API's bound `NapiVault`, the C ABI's bound
//! `OneironVault`, JNI's `NativeVault`) write and read through these doors
//! as their bound caller. One that names a session goes through the room the
//! registry holds for it, judged at each call, never at bind:
//!
//! - While the room is off record, a put, a batch of puts, an edge or a
//!   vector stages in the room's overlay as one segment, every op or none,
//!   after the refusals its base write meets: the public raw-put and edge
//!   checks, the actor's proof, the caller's write lane over stored rows,
//!   an agent definition's owner-only widening, a claim's gate on base
//!   policy, whose decision the room does not keep, and, under a read lane,
//!   a claim's typed record refs resolved over the room (FIX 11062). It rides no turn of the room, so close drops it with the room;
//!   nothing reaches base unless the vault comes to hold it.
//! - While the room is on record, the write is ordinary memory and lands in
//!   base as an unbound session's does. An anonymous room keeps nothing: its
//!   talk-only refusal. A room that closed or was never entered, and a
//!   caller no longer on its roster, are refused as every session door
//!   refuses them.
//! - Reads compose the room's overlay with base while the room is live and
//!   the caller is in it; otherwise they read base, as before. Its searches,
//!   builder runs, type scans and ChildOf walks do too (`composed_reads`).
//!
//! A delete is the owner's own act and runs the `vault.delete` row on base,
//! as before. Authority and policy always read base.

use heed::RoTxn;

use super::RawEntityPut;
use crate::Vault;
use crate::affect::Vad;
use crate::batch::BatchBuilder;
use crate::batch::BatchOp;
use crate::claim::ClaimSource;
use crate::core_write::CoreWriteLane;
use crate::edge::{EdgeInfo, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, OffRecordError};
use crate::memory::{Memory, MemoryResult};
use crate::off_record::OffRecordSession;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, TombstoneStoreRead};
use crate::session_overlay::{JournalEntry, JournalRole, JournalScope, RouteTarget};
use crate::store::SessionStoreView;
use crate::temporal::TimeRange;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};

mod composed_reads;

/// One raw write as its room stages it.
pub(super) enum RawOp<'a> {
    /// An entity blob.
    Put(RawEntityPut<'a>),
    /// A directed edge.
    Edge {
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
        weight: f32,
    },
    /// An entity's vector.
    Vector { id: EntityId, vector: &'a [f32] },
}

impl Memory<'_> {
    /// The live room this surface's raw calls run in, for its actor; `None`
    /// when it names no session.
    fn raw_session(&self) -> crate::Result<Option<OffRecordSession<'_>>> {
        let Some((session_ref, _)) = self.off_record_binding() else {
            return Ok(None);
        };
        let session = self.vault().off_record_session_vault().bind(session_ref)?;
        session.for_participant(self.actor()).map(Some)
    }

    /// Runs `read` on the room this surface's session names, bound to its
    /// caller, while the room is live and the caller is in it. `None` when
    /// the read belongs on base, as a read did before: no session, a ref no
    /// room can carry, or a room that is gone, closing or closed, or that
    /// this caller has left, at bind or during the read.
    fn raw_session_read<R>(
        &self,
        read: impl FnOnce(&OffRecordSession<'_>) -> crate::Result<R>,
    ) -> MemoryResult<Option<R>> {
        let Some((session_ref, _)) = self.off_record_binding() else {
            return Ok(None);
        };
        let session = match self.vault().off_record_session_vault().bind(session_ref) {
            Ok(session) => session,
            // Bind's one config refusal: a ref no room can carry.
            Err(Error::InvalidConfig(_)) => return Ok(None),
            Err(error) => return read_on_base(error),
        };
        match session
            .for_participant(self.actor())
            .and_then(|session| read(&session))
        {
            Ok(value) => Ok(Some(value)),
            Err(error) => read_on_base(error),
        }
    }

    /// Runs `read` over the composed view of the room this surface's
    /// session names, in one snapshot, as [`Self::raw_session_read`] runs
    /// it.
    fn raw_composed_read<R>(
        &self,
        read: impl FnOnce(&Vault, &SessionStoreView<'_>, &RoTxn<'_>) -> crate::Result<R>,
    ) -> MemoryResult<Option<R>> {
        self.raw_session_read(|session| session.read_composed_in_vault(read))
    }

    /// Stages `ops` in the room this surface's session names while it is
    /// off record, and answers `true`; `false` when they land in base (no
    /// session, or a room on record).
    ///
    /// # Errors
    ///
    /// The room's own refusals (anonymous, closing, gone, a caller off its
    /// roster, a full overlay), the refusals the same write meets on base,
    /// and the session apply's.
    pub(super) fn raw_write_in_session(&self, ops: &[RawOp<'_>]) -> MemoryResult<bool> {
        let Some(session) = self.raw_session()? else {
            return Ok(false);
        };
        let route = session.write_route()?;
        // An anonymous room keeps nothing: its talk-only refusal.
        route.require_recording(session.session_ref())?;
        if route.target() != RouteTarget::Overlay {
            return Ok(false);
        }
        let conversation = session.overlay_conversation_shell()?;
        let now = self.vault().store.clock.now_recorded_at();
        let at = TimeRange {
            start: now,
            end: now,
        };
        // FIX 3103: each op keeps the run whose envelope wrote it.
        let source_run = crate::skill_attribution::current_run_write_token();
        let mut entries = Vec::with_capacity(ops.len());
        let mut agent_puts = Vec::new();
        for op in ops {
            let (row, occurred, learned_at, op) = match *op {
                RawOp::Put(put) => {
                    self.admit_staged_put(&session, put)?;
                    if put.entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF {
                        agent_puts.push(put);
                    }
                    let op = BatchOp::Put {
                        id: put.id,
                        entity_type: put.entity_type,
                        occurred: put.occurred,
                        learned_at: put.learned_at,
                        data: put.data.to_vec(),
                        allow_maintenance: false,
                        allow_reserved_predicate: false,
                        hub_sync_imported: false,
                    };
                    (put.id, put.occurred, put.learned_at, op)
                }
                RawOp::Edge {
                    src,
                    kind,
                    tgt,
                    weight,
                } => {
                    crate::edge::validate_public_edge_creation_kind(kind)?;
                    let op = BatchOp::Edge {
                        src,
                        kind,
                        tgt,
                        weight,
                        vad: Vad::NEUTRAL,
                    };
                    (src, at, now, op)
                }
                RawOp::Vector { id, vector } => {
                    if let Some(error) = Error::invalid_vector_component(vector) {
                        return Err(error.into());
                    }
                    let op = BatchOp::Vector {
                        id,
                        vector: vector.to_vec(),
                        pending_embedding_token: None,
                        provenance: None,
                    };
                    (id, at, now, op)
                }
            };
            // Its own row is its scope's turn: no turn of the room has it,
            // so no promote or save replays it; close drops it.
            entries.push(JournalEntry {
                scope: JournalScope::new(conversation, row),
                role: JournalRole::TurnOwnedArtifact,
                learned_at,
                occurred,
                op,
                source_run: source_run.clone(),
            });
        }
        // The caller's write lane, as on base (FIX 6068): a put over a stored
        // row it does not read refuses as missing.
        let lane = self.core_write_lane()?;
        // Under a read lane, each CLAIM's typed record refs must resolve for
        // it over the room once the ops are staged (FIX 1223, 11062), as the
        // base batch judges them over its own staged rows.
        let claims = match &lane {
            CoreWriteLane::Read(_) => staged_claims(ops)?,
            CoreWriteLane::Target(_) | CoreWriteLane::Unbound => Vec::new(),
        };
        let put_ids: Vec<EntityId> = ops
            .iter()
            .filter_map(|op| match op {
                RawOp::Put(put) => Some(put.id),
                RawOp::Edge { .. } | RawOp::Vector { .. } => None,
            })
            .collect();
        let mut refusal = None;
        let staged = session.overlay_write_routed(&route, |wtxn, apply| {
            let proven = self
                .verify_actor_write_in_txn(wtxn)
                .and_then(|()| self.refuse_owner_widening_in_txn(wtxn, &agent_puts));
            if let Err(error) = proven {
                refusal = Some(error);
                return Err(Error::InvariantViolation("a bound raw write was refused"));
            }
            if !lane.admits_puts_in(wtxn, &put_ids)? {
                return Err(Error::EntityNotFound);
            }
            for entry in entries {
                apply(wtxn, entry)?;
            }
            if let CoreWriteLane::Read(reader) = &lane
                && !claims.is_empty()
            {
                let view = session.read_view()?;
                let room = self
                    .vault()
                    .scoped_read_in_session(reader.actor_key().clone(), &view);
                for body in &claims {
                    if crate::gate::unresolved_claim_reference(&room, wtxn, body)?.is_some() {
                        return Err(unresolved_reference());
                    }
                }
            }
            Ok(())
        });
        staged.map_err(|error| refusal.take().unwrap_or_else(|| error.into()))?;
        Ok(true)
    }

    /// Refuses, as a write below owner grade on base is refused, a put of
    /// `puts` that turns an agent definition back on or widens its models.
    fn refuse_owner_widening_in_txn(
        &self,
        txn: &RoTxn<'_>,
        puts: &[RawEntityPut<'_>],
    ) -> MemoryResult<()> {
        for put in puts {
            if crate::agent_def::agent_definition_put_widens_in_txn(
                &self.vault().store,
                txn,
                &put.id,
                put.data,
            )? {
                return Err(owner_only_widening().into());
            }
        }
        Ok(())
    }

    /// The refusals a put meets on base before its room stages it: the
    /// public raw-put door's, and a claim's gate on base policy under its
    /// caller's envelope, whose decision is not kept.
    fn admit_staged_put(
        &self,
        session: &OffRecordSession<'_>,
        put: RawEntityPut<'_>,
    ) -> MemoryResult<()> {
        crate::batch::validate_staged_raw_put(put.entity_type, put.data, put.learned_at)?;
        if put.entity_type == crate::registry::ENTITY_TYPE_CLAIM
            && let Some(envelope) = self.raw_claim_envelope(put.data)?
        {
            let body = crate::claim::validate_claim_body_and_decode(put.data, false)?;
            session.session_gate_check(put.id, &body, &envelope)?;
        }
        Ok(())
    }

    /// `put` on `batch`, its claim under its verified caller's envelope.
    pub(super) fn raw_put_on<'b>(
        &self,
        batch: BatchBuilder<'b>,
        put: &RawEntityPut<'_>,
    ) -> MemoryResult<BatchBuilder<'b>> {
        let batch = batch.put(
            &put.id,
            put.entity_type,
            put.occurred,
            put.learned_at,
            put.data,
        );
        if put.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Ok(batch);
        }
        Ok(match self.raw_claim_envelope(put.data)? {
            Some(envelope) => batch.caller_envelope(&put.id, envelope),
            None => batch,
        })
    }

    /// The verified caller's envelope a raw CLAIM put is gated and applied
    /// under (FIX 8118): the origin its host bound, else, for a surface
    /// bound to a session, its actor over the body's own approval and
    /// source (`RAW_CLAIM_SOURCE` when the body names none). `None` for a
    /// body that does not decode, which the put's own check refuses, and
    /// for an actor no session binds: no verified caller, so the put keeps
    /// the local write's gate, as an unbound host write does.
    fn raw_claim_envelope(&self, data: &[u8]) -> crate::Result<Option<WriteEnvelope>> {
        let Ok(body) = crate::claim::decode_claim_body(data, false) else {
            return Ok(None);
        };
        if let Some(envelope) = self.host_envelope(body.approval)? {
            return Ok(Some(envelope));
        }
        if self.off_record_binding().is_none() {
            return Ok(None);
        }
        let provenance = rmpv::Value::Map(vec![
            (rmpv::Value::from("surface"), rmpv::Value::from("raw")),
            (rmpv::Value::from("door"), rmpv::Value::from("put")),
        ]);
        Ok(Some(WriteEnvelope::new(
            WriteActor::new(self.actor(), self.actor_class()),
            body.source.unwrap_or(RAW_CLAIM_SOURCE),
            WriteProvenance::new(provenance)?,
            body.approval,
        )))
    }

    /// Reads `id`'s body as [`Vault::get`] does, the room's overlay over
    /// base while this surface's session is live (FIX 8119).
    ///
    /// # Errors
    ///
    /// As [`Vault::get`].
    pub fn raw_get_entity(&self, id: &EntityId) -> MemoryResult<Option<Vec<u8>>> {
        match self.raw_composed_read(|vault, view, txn| body_in(vault, view, txn, id))? {
            Some(body) => Ok(body),
            None => Ok(self.vault().get(id)?),
        }
    }

    /// Whether `id` is stored, the room's rows counted while this surface's
    /// session is live.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn raw_entity_exists(&self, id: &EntityId) -> MemoryResult<bool> {
        Ok(self.raw_entity_type(id)?.is_some())
    }

    /// `id`'s stored type byte, the room's rows read while this surface's
    /// session is live.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn raw_entity_type(&self, id: &EntityId) -> MemoryResult<Option<u8>> {
        let composed = self.raw_composed_read(|_, view, txn| {
            Ok(view.port_entity_record(txn, id)?.map(|row| row.entity_type))
        })?;
        match composed {
            Some(entity_type) => Ok(entity_type),
            None => Ok(self.vault().get_entity_type(id)?),
        }
    }

    /// `src`'s outbound edges, the room's among them while this surface's
    /// session is live.
    ///
    /// # Errors
    ///
    /// As [`Vault::edges_out`].
    pub fn raw_edges_out(&self, src: &EntityId) -> MemoryResult<Vec<EdgeInfo>> {
        self.raw_edges(src, EdgeDirection::Out)
    }

    /// `tgt`'s inbound edges, the room's among them while this surface's
    /// session is live.
    ///
    /// # Errors
    ///
    /// As [`Vault::edges_in`].
    pub fn raw_edges_in(&self, tgt: &EntityId) -> MemoryResult<Vec<EdgeInfo>> {
        self.raw_edges(tgt, EdgeDirection::In)
    }

    fn raw_edges(
        &self,
        center: &EntityId,
        direction: EdgeDirection,
    ) -> MemoryResult<Vec<EdgeInfo>> {
        let composed = self.raw_composed_read(|_, view, txn| {
            let mut edges = Vec::new();
            for (scanned, row) in view
                .port_edges(txn, center, direction, None, None)?
                .enumerate()
            {
                if scanned >= crate::vault::MAX_EDGE_QUERY_RESULTS {
                    return Err(Error::IndexOverflow("edge neighbors"));
                }
                edges.push(row?);
            }
            Ok(edges)
        })?;
        if let Some(edges) = composed {
            return Ok(edges);
        }
        Ok(match direction {
            EdgeDirection::In => self.vault().edges_in(center)?,
            _ => self.vault().edges_out(center)?,
        })
    }

    /// [`Vault::targets`], the room's edges and rows among them while this
    /// surface's session is live.
    ///
    /// # Errors
    ///
    /// As [`Vault::targets`].
    pub fn raw_targets(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        target_type: Option<u8>,
    ) -> MemoryResult<Vec<EntityId>> {
        let composed = self.raw_composed_read(|_, view, txn| {
            super::super::edges::filtered_edge_peers_in(
                view,
                txn,
                EdgeDirection::Out,
                src,
                kind,
                target_type,
            )
        })?;
        match composed {
            Some(peers) => Ok(peers),
            None => Ok(self.vault().targets(src, kind, target_type)?),
        }
    }

    /// [`Vault::sources`], the room's edges and rows among them while this
    /// surface's session is live.
    ///
    /// # Errors
    ///
    /// As [`Vault::sources`].
    pub fn raw_sources(
        &self,
        tgt: &EntityId,
        kind: EdgeKind,
        source_type: Option<u8>,
    ) -> MemoryResult<Vec<EntityId>> {
        let composed = self.raw_composed_read(|_, view, txn| {
            super::super::edges::filtered_edge_peers_in(
                view,
                txn,
                EdgeDirection::In,
                tgt,
                kind,
                source_type,
            )
        })?;
        match composed {
            Some(peers) => Ok(peers),
            None => Ok(self.vault().sources(tgt, kind, source_type)?),
        }
    }
}

/// `None`, for a base read, when `error` says the room is gone, closing or
/// closed, or that its caller has left it; any other error stands.
fn read_on_base<R>(error: Error) -> MemoryResult<Option<R>> {
    match error {
        Error::OffRecord(
            OffRecordError::OffRecordSessionNotFound { .. }
            | OffRecordError::OffRecordSessionClosing { .. }
            | OffRecordError::OffRecordNotInRoom { .. }
            | OffRecordError::OffRecordOverlayLeaseClosed { .. },
        ) => Ok(None),
        error => Err(error.into()),
    }
}

/// The CLAIM bodies `ops` put, in op order, as their room stages them.
fn staged_claims(ops: &[RawOp<'_>]) -> crate::Result<Vec<crate::claim::ClaimBody>> {
    let mut claims = Vec::new();
    for op in ops {
        if let RawOp::Put(put) = op
            && put.entity_type == crate::registry::ENTITY_TYPE_CLAIM
        {
            claims.push(crate::claim::validate_claim_body_and_decode(put.data, false)?);
        }
    }
    Ok(claims)
}

/// The claim gate's unresolved-record-reference refusal, as the base batch
/// words it; the room keeps no gate decision, so none is receipted.
fn unresolved_reference() -> Error {
    Error::Gate(GateError::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec![crate::gate::GateReasonCode::DenyUnresolvedRecordReference.as_str()],
    })
}

/// The below-owner refusal of an agent definition's widening, as the base
/// batch words it (`BatchBuilder::commit_below_owner`).
const OWNER_ONLY_WIDENING: &str =
    "only the vault owner turns an agent definition back on or changes its models";

fn owner_only_widening() -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(OWNER_ONLY_WIDENING))
}

/// Hook (CALLS "raw claim envelope source", open): the source a raw CLAIM
/// put's envelope carries when its body names none. It asks for no
/// explicit auto permit, so the gate reads the put as the body says, and
/// the envelope only names the caller who wrote it (FIX 8118).
const RAW_CLAIM_SOURCE: ClaimSource = ClaimSource::Inferred;

/// `id`'s body as [`Vault::get`] reads it, through `view`: its live words,
/// or, for a soft-erased shell, empty bytes; never words awaiting scrub.
fn body_in(
    vault: &Vault,
    view: &SessionStoreView<'_>,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> crate::Result<Option<Vec<u8>>> {
    let visibility = view.port_deletion_state(txn, id)?;
    if !visibility.deleted {
        return Ok(vault.live_entity_in_txn(view, txn, id)?.map(|row| row.body));
    }
    let Some(row) = view.port_entity_record(txn, id)? else {
        return Ok(None);
    };
    Ok((row.body.is_empty() && !visibility.archived && !visibility.stale).then(Vec::new))
}
