//! Session-bound NOTE and claim writes (DOOR-127; Engine ruling 10-18 on
//! ARCH-0052 D1/D2): a row written through a live session's handle while
//! the room is off record stages in the room's overlay, under the room's
//! byte budget, and close drops it with the rest of the room. Nothing here
//! reaches base: every write stages under an `Overlay` route, and a room on
//! record or anonymous never gets this far.
//!
//! A staged row belongs to no turn of the room: its journal scope names the
//! row itself, so neither a promote nor a whole-talk save replays it, and it
//! evaporates at close ([`SESSION_WRITES_RIDE_NO_TURN`]). Rows a write keeps
//! beside its row, a room step's response version (FIX 4818), ride that
//! row's scope, and each is placed as the row is, once every op of the
//! write is staged. A writer that stages several rows in one segment prepares
//! each, gate included, before the segment opens. A claim's gate is judged
//! against base policy, as every gate is (authority stays on base), and its
//! decision follows the content it judged (ARCH-0052, FIX 9967): it stages
//! beside the claim, in the claim's segment, never in base, and evaporates
//! with the room.

use crate::batch::BatchOp;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::CreateNoteRequest;
use crate::memory::{HostWriteOrigin, MemoryError, MemoryResult, SessionReadContext};
use crate::ports::EntityStoreRead;
use crate::session_overlay::{JournalEntry, JournalRole, JournalScope, SessionWriteRoute};
use crate::store::RoomGateDecision;
use crate::task_verb::sdk::AgentVerb;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope};
use oneiron_contracts::affect::Vad;

use super::room_births::RoomRowAttachments;
use super::session::OffRecordSession;

/// Whether a session write rides no turn of the room, so that only close
/// ends it: a promote or a save replays turns, and these rows belong to
/// none. Canon is silent on saving a room's NOTEs and claims (Engine call,
/// DOOR-127); a later ruling that saves them scopes them to a turn here.
const SESSION_WRITES_RIDE_NO_TURN: bool = true;

/// One room row's writes, judged and prepared before a write segment opens
/// (FIX 4818): the row, its staging stamps, the rows it needs, its ops and
/// what stages beside it.
pub(crate) struct PreparedSessionRows {
    row: EntityId,
    occurred: TimeRange,
    learned_at: u64,
    needs: Vec<EntityId>,
    ops: Vec<BatchOp>,
    attachments: RoomRowAttachments,
}

impl OffRecordSession<'_> {
    /// Stages `ops`, the writes of the one row `row`, into the room's overlay
    /// under `route`, each op on a fresh view of the room so it reads the
    /// ones before it, then `attachments` beside it (its birth, and a NOTE's
    /// document birth: FIX 4280, 4281), and answers the room's short id for
    /// `row`. Each of `needs` must be a row the room reads (overlay or base)
    /// in the transaction that stages them.
    ///
    /// # Errors
    ///
    /// The route's own refusal once the room flipped, went anonymous or is
    /// closing; [`Error::EntityNotFound`] for a missing row of `needs`; the
    /// room's [`OffRecordOverlayFull`](crate::error::OffRecordError::OffRecordOverlayFull)
    /// once its budget is spent; any refusal of the session apply.
    #[expect(
        clippy::too_many_arguments,
        reason = "the route, then the one row's own staging axes and what stages beside it"
    )]
    pub(crate) fn stage_session_rows(
        &self,
        route: &SessionWriteRoute,
        row: EntityId,
        occurred: TimeRange,
        learned_at: u64,
        needs: &[EntityId],
        ops: Vec<BatchOp>,
        attachments: &RoomRowAttachments,
    ) -> Result<String> {
        route.require_recording(&self.session_ref)?;
        let conversation = self.overlay_conversation_shell()?;
        self.overlay_write_routed(route, |wtxn, apply| {
            self.stage_session_rows_in_txn(
                wtxn,
                apply,
                conversation,
                row,
                occurred,
                learned_at,
                needs,
                ops,
                attachments,
            )
        })
    }

    /// [`Self::stage_session_rows`]'s staging, inside a segment its writer
    /// opened on its own captured route ([`Self::overlay_write_routed`]), so
    /// the writer keeps what it keeps beside the rows in the same segment (a
    /// run's write receipt, WILL L11-01 S01-2a). `conversation` is the
    /// room's shell, read before the segment opened; `apply` is the
    /// segment's own.
    ///
    /// # Errors
    ///
    /// As [`Self::stage_session_rows`], with nothing staged.
    #[expect(
        clippy::too_many_arguments,
        reason = "the segment's transaction and apply, the room's shell, then the one row's own staging axes"
    )]
    pub(crate) fn stage_session_rows_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        apply: &dyn Fn(&mut heed::RwTxn<'_>, JournalEntry) -> Result<()>,
        conversation: EntityId,
        row: EntityId,
        occurred: TimeRange,
        learned_at: u64,
        needs: &[EntityId],
        ops: Vec<BatchOp>,
        attachments: &RoomRowAttachments,
    ) -> Result<String> {
        self.stage_session_support_ops_in_txn(
            wtxn,
            apply,
            conversation,
            row,
            occurred,
            learned_at,
            needs,
            ops,
        )?;
        // The row's birth, and a NOTE's document birth, in the same segment
        // and transaction: bookkeeping past the room's budget (FIX 4280,
        // 4281; Engine 10-22).
        self.stage_row_attachments(wtxn, row, attachments)?;
        let (short, _) = self
            .overlay()
            .alloc_session_short_id(&row, row.as_bytes())?;
        Ok(short)
    }

    /// Stages `ops` through the segment's `apply` in `owner`'s journal
    /// scope, once each of `needs` reads in the room, then the position of
    /// each row they put: the writes of `owner`'s row, or rows a room write
    /// keeps beside it with no birth or short id of their own (FIX 4818: a
    /// room step's response artifact, its ASSET body and its version claim).
    /// They ride no turn of the room, as `owner` does, so neither a promote
    /// nor a save replays them apart.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for a missing row of `needs`; any refusal of
    /// the session apply, the room's budget refusal included.
    #[expect(
        clippy::too_many_arguments,
        reason = "the segment's transaction and apply, the room's shell, then the ops' own staging axes"
    )]
    pub(crate) fn stage_session_support_ops_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        apply: &dyn Fn(&mut heed::RwTxn<'_>, JournalEntry) -> Result<()>,
        conversation: EntityId,
        owner: EntityId,
        occurred: TimeRange,
        learned_at: u64,
        needs: &[EntityId],
        ops: Vec<BatchOp>,
    ) -> Result<()> {
        // The owner's id is its scope's turn: no TURN of the room has it,
        // so no promote or save plans it (`SESSION_WRITES_RIDE_NO_TURN`).
        let turn = if SESSION_WRITES_RIDE_NO_TURN {
            owner
        } else {
            conversation
        };
        {
            let view = self.read_view()?;
            for id in needs {
                if view.port_entity_record(&*wtxn, id)?.is_none() {
                    return Err(Error::EntityNotFound);
                }
            }
        }
        // FIX 3103: each op keeps the run whose envelope wrote it.
        let source_run = crate::skill_attribution::current_run_write_token();
        // Each put row's position is staged once every op is: a NOTE's or an
        // ASSET's follows the birth facet a later op writes (FIX 4818).
        let mut puts = Vec::new();
        for op in ops {
            if let BatchOp::Put {
                id,
                entity_type,
                data,
                ..
            } = &op
            {
                puts.push((*id, *entity_type, data.clone()));
            }
            apply(
                wtxn,
                JournalEntry {
                    scope: JournalScope::new(conversation, turn),
                    role: JournalRole::TurnOwnedArtifact,
                    learned_at,
                    occurred,
                    op,
                    source_run: source_run.clone(),
                },
            )?;
        }
        // Atomically beside the rows, under the same route and budget
        // (WILL L11-01): no authority row, nothing a save replays.
        for (id, kind, data) in &puts {
            crate::federation::record_scope::stage_session_position(
                &self.read_view()?,
                wtxn,
                *id,
                *kind,
                data,
            )?;
        }
        Ok(())
    }

    /// Judges `body`'s write against base policy, as the write door would,
    /// and answers the decision it judged, for the room to stage beside the
    /// claim (FIX 9967); `None` when no policy verdict was reached. The
    /// transaction it reads in is never committed, so base keeps no row.
    ///
    /// # Errors
    ///
    /// The gate's refusal, typed as the write door raises it.
    pub(crate) fn session_gate_decision(
        &self,
        id: EntityId,
        body: &ClaimBody,
        envelope: &WriteEnvelope,
    ) -> Result<Option<RoomGateDecision>> {
        let vault = self.vault;
        let mut wtxn = vault.store.env.write_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?;
        let judged = crate::gate::capture_claim_policy_for_write(
            &vault.store,
            &mut wtxn,
            &id,
            crate::gate::ClaimGateWrite::plain(body, Some(envelope)),
            &policy,
            crate::gate::GateWriteMode {
                record_decision: false,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent: false,
                include_source_in_gate_input: true,
            },
        );
        // Dropped uncommitted: base keeps no decision row.
        drop(wtxn);
        judged
    }

    /// [`Self::session_gate_decision`] as a check alone, for a run's precheck
    /// before the write that judges again and stages its decision.
    ///
    /// # Errors
    ///
    /// The gate's refusal, typed as the write door raises it.
    pub(crate) fn session_gate_check(
        &self,
        id: EntityId,
        body: &ClaimBody,
        envelope: &WriteEnvelope,
    ) -> Result<()> {
        self.session_gate_decision(id, body, envelope).map(|_| ())
    }

    /// Stages one claim candidate as the CLAIM row `id`, with its `claim_of`
    /// edge to an entity subject and the decision its gate judged
    /// (`session_gate_decision`).
    /// The body is the one base would store for a new row, at the vault's
    /// default facet unless the candidate stamps one.
    ///
    /// # Errors
    ///
    /// A family that owns its own supersession chain; a body the claim codec
    /// refuses; the gate's refusal; otherwise as
    /// [`Self::stage_session_rows`].
    pub(crate) fn stage_session_claim(
        &self,
        route: &SessionWriteRoute,
        id: EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<String> {
        crate::batch::reject_family_owned_candidate(&candidate)?;
        let body = candidate.into_claim_body(envelope, self.vault.default_facet()?)?;
        let decision = self.session_gate_decision(id, &body, envelope)?;
        let data = crate::claim::encode_claim_body(&body)?;
        let mut ops = vec![BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            row_version: None,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        let mut needs = Vec::new();
        if let ClaimSubject::Entity(subject) = body.subject {
            needs.push(subject);
            ops.push(BatchOp::Edge {
                src: id,
                kind: EdgeKind::ClaimOf,
                tgt: subject,
                weight: crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
                vad: Vad::NEUTRAL,
            });
        }
        let attachments =
            RoomRowAttachments::staged_claim(envelope, learned_at).with_gate_decision(decision);
        self.stage_session_rows(route, id, occurred, learned_at, &needs, ops, &attachments)
    }

    /// The rows of [`Self::stage_session_claim`]'s claim, the row derived
    /// from each of `sources` (FIX 5977): one `DerivedFrom` edge to each,
    /// staged in the same write as the row, under the same gate and
    /// encoding. Each source must be a row the room reads when the rows
    /// stage, so the claim never lands without its lineage. The gate judges
    /// the claim here, before a write segment opens, as its own base writer
    /// cannot open inside a segment's; the writer then stages the rows with
    /// whatever else it stages in its segment (FIX 4818).
    ///
    /// # Errors
    ///
    /// As [`Self::stage_session_claim`] before it stages: nothing is staged.
    pub(crate) fn prepare_session_derived_claim(
        &self,
        id: EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
        sources: &[EntityId],
    ) -> Result<PreparedSessionRows> {
        crate::batch::reject_family_owned_candidate(&candidate)?;
        let body = candidate.into_claim_body(envelope, self.vault.default_facet()?)?;
        let decision = self.session_gate_decision(id, &body, envelope)?;
        let data = crate::claim::encode_claim_body(&body)?;
        let mut ops = vec![BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            row_version: None,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        let mut needs = Vec::new();
        if let ClaimSubject::Entity(subject) = body.subject {
            needs.push(subject);
            ops.push(BatchOp::Edge {
                src: id,
                kind: EdgeKind::ClaimOf,
                tgt: subject,
                weight: crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
                vad: Vad::NEUTRAL,
            });
        }
        for source in sources {
            needs.push(*source);
            ops.push(BatchOp::Edge {
                src: id,
                kind: EdgeKind::DerivedFrom,
                tgt: *source,
                weight: 1.0,
                vad: Vad::NEUTRAL,
            });
        }
        Ok(PreparedSessionRows {
            row: id,
            occurred,
            learned_at,
            needs,
            ops,
            attachments: RoomRowAttachments::derived_claim(envelope, sources, learned_at)
                .with_gate_decision(decision),
        })
    }

    /// Stages `rows`, prepared before the segment opened, inside a segment
    /// its writer opened on its own captured route
    /// ([`Self::overlay_write_routed`]); `conversation` is the room's shell
    /// and `apply` the segment's own. Answers the row's short id.
    ///
    /// # Errors
    ///
    /// As [`Self::stage_session_rows_in_txn`]; [`Error::EntityNotFound`] for
    /// a source the room does not read.
    pub(crate) fn stage_prepared_rows_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        apply: &dyn Fn(&mut heed::RwTxn<'_>, JournalEntry) -> Result<()>,
        conversation: EntityId,
        rows: PreparedSessionRows,
    ) -> Result<String> {
        self.stage_session_rows_in_txn(
            wtxn,
            apply,
            conversation,
            rows.row,
            rows.occurred,
            rows.learned_at,
            &rows.needs,
            rows.ops,
            &rows.attachments,
        )
    }

    /// Whether a run bound to a session writes `verb` into its room
    /// ([`Self::prepare_session_write`]): `vault.notes.create` and
    /// `vault.claims.upsert`.
    pub(crate) fn writes_verb(verb: AgentVerb) -> bool {
        matches!(verb.as_str(), "vault.notes.create" | "vault.claims.upsert")
    }

    /// A code-mode verb call of a run bound to this session, prepared to
    /// stage in its room: `vault.notes.create` or `vault.claims.upsert`,
    /// written through `actor`'s handle under the run's `origin`, on `route`,
    /// the run's captured route, never a fresh one (WILL L11-01, S01-2a).
    /// `reader` is the room's view the run's door opened for its caller,
    /// when the run binds a door: a claim's subject resolves in it. The
    /// answer stages the write's rows inside a segment its writer opened on
    /// `route`, and gives the verb's answer, encoded. `None` for every other
    /// verb: those forward through the canonical vault, outside the
    /// session's route and its saver.
    pub(crate) fn prepare_session_write(
        &self,
        route: &SessionWriteRoute,
        actor: WriteActor,
        origin: HostWriteOrigin,
        verb: AgentVerb,
        input: &serde_json::Value,
        reader: Option<&SessionReadContext<'_>>,
    ) -> Option<MemoryResult<SessionWriteStage<'_>>> {
        let memory = self
            .vault
            .memory(actor.entity_ref(), actor.actor_class())
            .with_host_origin(origin);
        let decode =
            |what: &str| MemoryError::bad_request(format!("{} input is not {what}", verb.as_str()));
        Some(match verb.as_str() {
            "vault.notes.create" => serde_json::from_value::<CreateNoteRequest>(input.clone())
                .map_err(|_| decode("a NOTE"))
                .and_then(|note| {
                    // A code run's NOTE names no evidence (FIX 4281, P2).
                    memory.prepare_note_in_session(self, route, &note.kind, &note.markdown, &[])
                })
                .map(|prepared| {
                    staged(move |wtxn, apply| encoded(&prepared.stage_in_txn(self, wtxn, apply)?))
                }),
            "vault.claims.upsert" => {
                serde_json::from_value::<crate::memory::ScopedClaimInput>(input.clone())
                    .map_err(|_| decode("a claim"))
                    .and_then(|claim| memory.prepare_claim_in_session(self, route, reader, &claim))
                    .map(|prepared| {
                        staged(move |wtxn, apply| {
                            encoded(&prepared.stage_in_txn(self, wtxn, apply)?)
                        })
                    })
            }
            _ => return None,
        })
    }
}

/// The staging step of a prepared room write: inside the segment its writer
/// opened, on the segment's transaction and apply, it stages the write's
/// rows and answers the verb's answer, encoded.
pub(crate) type SessionWriteStage<'s> = Box<
    dyn FnOnce(
            &mut heed::RwTxn<'_>,
            &dyn Fn(&mut heed::RwTxn<'_>, JournalEntry) -> Result<()>,
        ) -> Result<serde_json::Value>
        + 's,
>;

/// `stage` as a prepared room write's [`SessionWriteStage`].
fn staged<'s>(
    stage: impl FnOnce(
        &mut heed::RwTxn<'_>,
        &dyn Fn(&mut heed::RwTxn<'_>, JournalEntry) -> Result<()>,
    ) -> Result<serde_json::Value>
    + 's,
) -> SessionWriteStage<'s> {
    Box::new(stage)
}

/// A staged room write's receipt, as its verb answers it.
fn encoded(receipt: &impl serde::Serialize) -> Result<serde_json::Value> {
    serde_json::to_value(receipt)
        .map_err(|_| Error::InvariantViolation("a room write's answer did not encode"))
}
