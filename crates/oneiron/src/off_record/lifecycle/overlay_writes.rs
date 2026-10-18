//! Session-bound NOTE and claim writes (DOOR-127; Engine ruling 10-18 on
//! ARCH-0052 D1/D2): a row written through a live session's handle while
//! the room is off record stages in the room's overlay, under the room's
//! byte budget, and close drops it with the rest of the room. Nothing here
//! reaches base: every write stages under an `Overlay` route, and a room on
//! record or anonymous never gets this far.
//!
//! A staged row belongs to no turn of the room: its journal scope names the
//! row itself, so neither a promote nor a whole-talk save replays it, and it
//! evaporates at close ([`SESSION_WRITES_RIDE_NO_TURN`]). Its gate is judged
//! against base policy, as every gate is (authority stays on base), and the
//! decision is not kept: a decision about evaporating content follows that
//! content, and the room keeps no decision rows of its own.

use crate::affect::Vad;
use crate::batch::BatchOp;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{HostWriteOrigin, MemoryError, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::session_overlay::{
    JournalEntry, JournalRole, JournalScope, RouteTarget, SessionWriteRoute,
};
use crate::task_verb::sdk::{AgentVerb, CreateNoteRequest};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope};

use super::session::OffRecordSession;

/// Whether a session write rides no turn of the room, so that only close
/// ends it: a promote or a save replays turns, and these rows belong to
/// none. Canon is silent on saving a room's NOTEs and claims (Engine call,
/// DOOR-127); a later ruling that saves them scopes them to a turn here.
const SESSION_WRITES_RIDE_NO_TURN: bool = true;

impl OffRecordSession<'_> {
    /// Stages `ops`, the writes of the one row `row`, into the room's overlay
    /// under `route`, each op on a fresh view of the room so it reads the
    /// ones before it, and answers the room's short id for `row`. Each of
    /// `needs` must be a row the room reads (overlay or base) in the
    /// transaction that stages them.
    ///
    /// # Errors
    ///
    /// The route's own refusal once the room flipped, went anonymous or is
    /// closing; [`Error::EntityNotFound`] for a missing row of `needs`; the
    /// room's [`OffRecordOverlayFull`](crate::error::OffRecordError::OffRecordOverlayFull)
    /// once its budget is spent; any refusal of the session apply.
    pub(crate) fn stage_session_rows(
        &self,
        route: &SessionWriteRoute,
        row: EntityId,
        occurred: TimeRange,
        learned_at: u64,
        needs: &[EntityId],
        ops: Vec<BatchOp>,
    ) -> Result<String> {
        route.require_recording(&self.session_ref)?;
        let conversation = self.overlay_conversation_shell()?;
        // The row's own id is its scope's turn: no TURN of the room has it,
        // so no promote or save plans it (`SESSION_WRITES_RIDE_NO_TURN`).
        let turn = if SESSION_WRITES_RIDE_NO_TURN {
            row
        } else {
            conversation
        };
        self.overlay_write_routed(route, |wtxn, apply| {
            {
                let view = self.read_view()?;
                for id in needs {
                    if view.port_entity_record(&*wtxn, id)?.is_none() {
                        return Err(Error::EntityNotFound);
                    }
                }
            }
            for op in ops {
                apply(
                    wtxn,
                    JournalEntry {
                        scope: JournalScope::new(conversation, turn),
                        role: JournalRole::TurnOwnedArtifact,
                        learned_at,
                        occurred,
                        op,
                    },
                )?;
            }
            let (short, _) = self.overlay().alloc_session_short_id(&row, row.as_bytes())?;
            Ok(short)
        })
    }

    /// Judges `body`'s write against base policy, as the write door would,
    /// and keeps no decision: the transaction it reads in is never
    /// committed.
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
        let vault = self.vault;
        let mut wtxn = vault.store.env.write_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?;
        let judged = crate::gate::check_claim_policy_for_write(
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
            false,
        );
        // Dropped uncommitted: the room keeps no decision row, and base none.
        drop(wtxn);
        judged
    }

    /// Stages one claim candidate as the CLAIM row `id`, with its `claim_of`
    /// edge to an entity subject, after its gate (`session_gate_check`).
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
        self.session_gate_check(id, &body, envelope)?;
        let data = crate::claim::encode_claim_body(&body)?;
        let mut ops = vec![BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
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
        self.stage_session_rows(route, id, occurred, learned_at, &needs, ops)
    }

    /// Whether a run bound to a session writes `verb` into its room
    /// ([`Self::forward_session_write`]): `vault.notes.create` and
    /// `vault.claims.upsert`.
    pub(crate) fn writes_verb(verb: AgentVerb) -> bool {
        matches!(verb.as_str(), "vault.notes.create" | "vault.claims.upsert")
    }

    /// A code-mode verb call of a run bound to this session, when it is one
    /// the room keeps: `vault.notes.create` or `vault.claims.upsert`, while
    /// the room is off record. Each writes through `actor`'s handle, under
    /// the run's `origin`, into the overlay. `None` for every other verb and
    /// for any verb once the room is on record: those forward through the
    /// canonical vault, outside the session's route and its saver.
    pub(crate) fn forward_session_write(
        &self,
        actor: WriteActor,
        origin: HostWriteOrigin,
        verb: AgentVerb,
        input: &serde_json::Value,
    ) -> Option<MemoryResult<serde_json::Value>> {
        let off_record = self
            .write_route()
            .is_ok_and(|route| route.target() == RouteTarget::Overlay);
        if !off_record {
            return None;
        }
        let memory = self
            .vault
            .memory(actor.entity_ref(), actor.actor_class())
            .with_host_origin(origin);
        let encode = |value: Result<serde_json::Value, serde_json::Error>| {
            value.map_err(|_| MemoryError::bad_request(format!("{} answer encoding failed", verb.as_str())))
        };
        let decode = |what: &str| MemoryError::bad_request(format!("{} input is not {what}", verb.as_str()));
        Some(match verb.as_str() {
            "vault.notes.create" => serde_json::from_value::<CreateNoteRequest>(input.clone())
                .map_err(|_| decode("a NOTE"))
                .and_then(|note| memory.create_note_in_session(self, &note.kind, &note.markdown))
                .and_then(|receipt| encode(serde_json::to_value(receipt))),
            "vault.claims.upsert" => {
                serde_json::from_value::<crate::memory::ScopedClaimInput>(input.clone())
                    .map_err(|_| decode("a claim"))
                    .and_then(|claim| memory.claim_upsert_in_session(self, &claim))
                    .and_then(|receipt| encode(serde_json::to_value(receipt)))
            }
            _ => return None,
        })
    }
}
