//! Base witness landing: container resolve, K7 door, batch write, text ops, session bump.

use super::super::structural::*;
use super::super::support::*;
use super::super::*;
use super::program::{
    AdmittedTurn, ImportedTurnStamp, WitnessAdmission, WitnessDoor, WitnessPlan, WitnessTarget,
};
use super::session::Admit;

mod stage;

use std::sync::atomic::Ordering;

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::session_overlay::SessionWriteRoute;
use crate::workspace_roster::RoomRegenerationPermit;

/// Tags an importer holds for the turn it lands, and the cell the program
/// leaves what they did to the turn's tagging marker in. They are settled in
/// the turn's own write, after its marker is committed (ARCH-0036: an import
/// that already holds tags completes its marker without a tagger call).
#[derive(Clone, Copy)]
pub(super) struct HeldTags<'a> {
    pub(super) tags: &'a crate::memory::extraction::EncoderOutput,
    pub(super) outcome: &'a std::cell::Cell<Option<crate::tagging::HeldTagsOutcome>>,
}

/// What the base guards proved inside the write transaction.
pub(super) enum BaseGuards {
    /// An id this call creates carries a local hard-delete marker.
    HardDeleted(EntityId),
    Clear {
        /// The conversation row is absent from this snapshot, so the landing
        /// mints it.
        mint_conversation: bool,
        /// The actor, when it is stored as a PERSON: the TURN's byline.
        person_author: Option<EntityId>,
        /// The project whose leader chat admitted this witness; its records
        /// are settled after the landing's effect.
        leader_project: Option<EntityId>,
        /// The reply topology the room guard fixed for a TURN this write
        /// mints with quotes (OF-460, FIX 2027, FIX 2028); the quotes
        /// themselves are proven, pinned and kept by citing MESSAGE there.
        quoted: Option<crate::conversation_dag::QuotedReply>,
        /// The thread binding the room guard proved (FIX 2951): a minted
        /// TURN is born with it; a stored one already holds it.
        thread: Option<crate::store::conversation_body::ThreadBinding>,
    },
}

/// A base landing's pre-write state.
pub(super) struct BaseSink<'a> {
    /// The session route this base write rides under, if any (K10).
    pub(super) route: Option<&'a SessionWriteRoute>,
    text_index_trusted: bool,
}

impl Memory<'_> {
    // ── write verbs ─────────────────────────────────────────────────────

    /// Witnesses one turn: create-or-get CONVERSATION/TURN, MESSAGE puts,
    /// `PartOf`/`BelongsTo`/`AuthoredBy` edges, and BM25 `content`
    /// indexing — all in ONE atomic batch.
    ///
    /// Every MESSAGE passes the approval-ceiling door
    /// (`gate::witness_message`) inside that batch's transaction, before any
    /// row stages. The door binds the FULL envelope — author, type, content,
    /// metadata, visibility, order — to the authenticated actor and the policy
    /// ceiling resolved in the same snapshot, so a caller cannot smuggle an
    /// unattributed `system` row, a metadata side channel or an ordering
    /// signal through a path that only stamps `AuthoredBy`. A refusal on any
    /// message rolls the whole turn back.
    pub fn witness(&self, turn: &WitnessTurn) -> MemoryResult<WitnessReceipt> {
        self.run_witness(
            turn,
            WitnessTarget::Base {
                route: None,
                mint_conversation_body: None,
                phone_birth: None,
            },
            WitnessDoor::Guest,
            || {},
            |_| Ok(()),
            |_| Ok(()),
        )
    }

    /// [`Self::witness`] for a turn whose tags the caller already holds: an
    /// import or a backfill that tagged it elsewhere. On a vault with a
    /// tagger, the tags are checked against the turn's text, saved, and the
    /// turn's tagging marker settles, all in the turn's own write, so no
    /// worker ever calls the tagger for it.
    ///
    /// A span's `message` indexes `turn.messages` as sent, in the order sent
    /// and whatever their `order`; its offsets are bytes of that message's
    /// `content`. In the write, each span moves by message id onto the text
    /// the turn shows, which is what the tagger reads: its visible, non-empty
    /// messages in `order`. Tags settle the turn only when they read all of
    /// that text. So they are refused when a span names a message sent hidden
    /// or empty, which the turn does not show, and when the turn shows a
    /// message not sent with them: an append to a turn that already held
    /// text, which the tagger then reads whole. Tags that break the contract
    /// or are refused leave the marker to the tagger; the turn lands either
    /// way. The outcome says which.
    pub fn witness_with_held_tags(
        &self,
        turn: &WitnessTurn,
        tags: &crate::memory::extraction::EncoderOutput,
    ) -> MemoryResult<(WitnessReceipt, crate::tagging::HeldTagsOutcome)> {
        let outcome = std::cell::Cell::new(None);
        let receipt = self.run_witness(
            turn,
            WitnessTarget::Held {
                held: HeldTags {
                    tags,
                    outcome: &outcome,
                },
            },
            WitnessDoor::Guest,
            || {},
            |_| Ok(()),
            |_| Ok(()),
        )?;
        Ok((
            receipt,
            outcome
                .take()
                .unwrap_or(crate::tagging::HeldTagsOutcome::NoMarker),
        ))
    }

    /// [`Self::witness`] under a session write route: the base landing a
    /// session's on-record continuation takes, with the route revalidated
    /// inside the write transaction.
    #[cfg(test)]
    pub(in crate::memory) fn witness_with_route(
        &self,
        turn: &WitnessTurn,
        session_route: Option<&SessionWriteRoute>,
    ) -> MemoryResult<WitnessReceipt> {
        self.witness_with_route_and_before_txn(turn, session_route, || {})
    }

    /// [`Self::witness_with_route`], running `before_txn` in the window
    /// between the ADVISORY container create-or-get and the write
    /// transaction, so a test can move that race deliberately.
    #[cfg(test)]
    pub(in crate::memory) fn witness_with_route_and_before_txn(
        &self,
        turn: &WitnessTurn,
        session_route: Option<&SessionWriteRoute>,
        before_txn: impl FnOnce(),
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness(
            turn,
            WitnessTarget::Base {
                route: session_route,
                mint_conversation_body: None,
                phone_birth: None,
            },
            WitnessDoor::Guest,
            before_txn,
            |_| Ok(()),
            |_| Ok(()),
        )
    }

    /// The executor's own door. `effect` shares the landing transaction: a
    /// result MESSAGE publishes its hold on the body there (FIX 365).
    pub(crate) fn witness_host_executor(
        &self,
        turn: &WitnessTurn,
        session_route: Option<&SessionWriteRoute>,
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness(
            turn,
            WitnessTarget::Base {
                route: session_route,
                mint_conversation_body: None,
                phone_birth: None,
            },
            WitnessDoor::HostExecutor,
            || {},
            |_| Ok(()),
            effect,
        )
    }

    /// Stream terminal sidecars and EntityDoc birth share the canonical witness
    /// transaction. An error rolls back row, indexes, receipt and seed deletion.
    /// `callback` names the write door: an `effect` that runs host code is
    /// [`crate::store::Callback::Opaque`]. `prepare` runs in that transaction
    /// before the room admits the witness: a Retry's terminal lands its TURN
    /// there, or proves its room regeneration permit (FIX 3152, 3149).
    pub(crate) fn witness_with_route_prepare_and_txn_effect(
        &self,
        turn: &WitnessTurn,
        session_route: Option<&SessionWriteRoute>,
        callback: crate::store::Callback,
        before_txn: impl FnOnce(),
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<Option<RoomRegenerationPermit>>,
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness_as(
            callback,
            turn,
            WitnessTarget::Base {
                route: session_route,
                mint_conversation_body: None,
                phone_birth: None,
            },
            WitnessDoor::Guest,
            before_txn,
            prepare,
            |txn, _| effect(txn),
        )
    }

    /// [`Self::witness_with_route_prepare_and_txn_effect`] for the phone keep
    /// under its proof `birth`: a base landing mints the conversation, when
    /// it mints one, with the line agent's mark alone; an existing
    /// conversation's body is never rewritten by the landing. The same path
    /// stamps the TURN it mints and every MESSAGE it puts with the thread
    /// (VOICE-PHONE-AGENT-REACH R1 fix), and puts the thread's rows through
    /// the phone keep's door (R2 review F1).
    pub(crate) fn witness_with_minted_conversation_body_and_txn_effect(
        &self,
        turn: &WitnessTurn,
        birth: crate::voice_call::PhoneThreadBirth,
        callback: crate::store::Callback,
        before_txn: impl FnOnce(),
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<Option<RoomRegenerationPermit>>,
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        let minted_conversation_body = crate::voice_call::phone_thread_mark_body(birth.agent())?;
        self.run_witness_as(
            callback,
            turn,
            WitnessTarget::Base {
                route: None,
                mint_conversation_body: Some(minted_conversation_body),
                phone_birth: Some(birth),
            },
            WitnessDoor::Guest,
            before_txn,
            prepare,
            |txn, _| effect(txn),
        )
    }

    /// [`Self::witness_with_route_prepare_and_txn_effect`] with nothing to
    /// prepare.
    #[cfg(test)]
    pub(crate) fn witness_with_route_and_txn_effect(
        &self,
        turn: &WitnessTurn,
        session_route: Option<&SessionWriteRoute>,
        callback: crate::store::Callback,
        before_txn: impl FnOnce(),
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        self.witness_with_route_prepare_and_txn_effect(
            turn,
            session_route,
            callback,
            before_txn,
            |_| Ok(None),
            effect,
        )
    }

    /// Lands one turn of an imported transcript (ARCH-0027) through the same
    /// program and ceiling door as [`Self::witness`], with `effect` (the import
    /// ledger) in its transaction. See [`ImportedTurnStamp`] for what differs.
    pub(crate) fn witness_imported(
        &self,
        turn: &WitnessTurn,
        stamp: &ImportedTurnStamp,
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness(
            turn,
            WitnessTarget::Imported { stamp },
            WitnessDoor::Guest,
            || {},
            |_| Ok(()),
            effect,
        )
    }

    /// Assemble a room before the witness gate inside its own transaction.
    /// This is used by project birth so the first witnessed trunk message,
    /// room, project, skill forks and owner Grant all commit together.
    pub(crate) fn witness_with_room_birth(
        &self,
        turn: &WitnessTurn,
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness(
            turn,
            WitnessTarget::Base {
                route: None,
                mint_conversation_body: None,
                phone_birth: None,
            },
            WitnessDoor::Guest,
            || {},
            prepare,
            |_| Ok(()),
        )
    }

    // ── the base landing ────────────────────────────────────────────────

    /// The conversation and TURN a base landing writes, each with its
    /// pre-transaction "not stored yet" answer. `continuation` is the session's
    /// on-record shell, which replaces the caller's conversation ref. A
    /// session door's `admit` runs first in each probe's read.
    pub(super) fn resolve_base_containers(
        &self,
        turn: &WitnessTurn,
        continuation: Option<EntityId>,
        door: WitnessDoor,
        admit: Option<Admit<'_>>,
    ) -> MemoryResult<((EntityId, bool), (EntityId, bool))> {
        let probe = |reference: &str, expected_type| {
            self.resolve_or_new_container(reference, expected_type, admit)
        };
        let conversation = match continuation {
            Some(shell) => probe(&shell.to_hex(), ENTITY_TYPE_CONVERSATION)?,
            None => probe(&turn.conversation_ref, ENTITY_TYPE_CONVERSATION)?,
        };
        // K7 witness-door ownership backstop (ARCH-0052 D2 backstop (a)). A
        // conversation owned by a live session overlay is witnessed through the
        // SESSION handle only; the canonical door refuses here, after container
        // resolution and before any write. This lands IN ADDITION to the K4
        // taint guard: the guard sees the ops, this sees the door.
        //
        // Reachable by 32-hex ref only. A non-hex ref to a session-local
        // conversation fails base resolution with not-found before reaching
        // this point, which is accepted: the refusal there is already correct
        // (base cannot resolve a room it cannot see) and leaks strictly less.
        if let Some(session_ref) = self
            .vault
            .store
            .off_record_sessions
            .owning_session_ref(&conversation.0)?
        {
            return Err(
                Error::OffRecord(OffRecordError::OffRecordWitnessDoorRejected {
                    session_ref,
                    conversation_ref: conversation.0.to_hex(),
                })
                .into(),
            );
        }
        let turn = match (door, &turn.turn_ref) {
            (WitnessDoor::HostTurn(id), _) => probe(&id.to_hex(), ENTITY_TYPE_TURN)?,
            (_, Some(reference)) => probe(reference, ENTITY_TYPE_TURN)?,
            (_, None) => (self.vault.store.clock.entity_id()?, true),
        };
        Ok((conversation, turn))
    }

    pub(super) fn base_sink<'a>(
        &self,
        plan: &WitnessPlan<'_>,
        route: Option<&'a SessionWriteRoute>,
    ) -> MemoryResult<BaseSink<'a>> {
        let has_text_ops = plan
            .messages
            .iter()
            .any(|planned| !planned.message.content.is_empty());
        let text_index_trusted = if has_text_ops {
            self.vault.ensure_text_index_trusted()?;
            true
        } else {
            self.vault.text_index_trusted.load(Ordering::Acquire)
        };
        Ok(BaseSink {
            route,
            text_index_trusted,
        })
    }

    /// The base landing's guards, ahead of the shared door: ids this call
    /// creates must be marker-free (checked INSIDE the write transaction so a
    /// concurrent hard delete cannot land between check and commit, A1),
    /// `prepare` runs, the conversation is re-read as a live room, an erased
    /// PERSON is refused, and the room admits the witness, under the room
    /// regeneration permit `prepare` proved, if any (FIX 3149). `quote_key`,
    /// taken before the writer opened, is the read each message's quote
    /// selection passes (FIX 2027).
    pub(super) fn base_guards_in_txn(
        &self,
        plan: &WitnessPlan<'_>,
        wtxn: &mut heed::RwTxn<'_>,
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<Option<RoomRegenerationPermit>>,
        quote_key: Option<&crate::claim::ScopedReadActorKey>,
    ) -> MemoryResult<BaseGuards> {
        let message_ids = plan.message_ids();
        let created_ids = message_ids
            .iter()
            .copied()
            .chain(plan.conversation_is_new.then_some(plan.conversation_id))
            .chain(plan.turn_is_new.then_some(plan.turn_id));
        for id in created_ids {
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(wtxn, &id)?
            {
                return Ok(BaseGuards::HardDeleted(id));
            }
        }
        let regeneration = prepare(wtxn)?;
        // Container resolution before the writer was advisory. A concurrent
        // writer may have claimed this ID, or a prepared project birth may
        // have created its home room. Never attach a turn to a non-room or
        // to an erased/hidden room just because an entity now exists here.
        let current_conversation = self
            .vault
            .store
            .port_entity_raw(wtxn, &plan.conversation_id)?;
        match current_conversation.as_deref() {
            Some(raw) => {
                let header = EntityMetadataHeader::parse(raw)
                    .ok_or(Error::CorruptedIndex("conversation header"))?;
                if header.entity_type != ENTITY_TYPE_CONVERSATION {
                    return Err(MemoryError::bad_request(
                        "the witnessed conversation ref resolves to a non-CONVERSATION entity",
                    ));
                }
                let visibility = self
                    .vault
                    .store
                    .port_deletion_state(wtxn, &plan.conversation_id)?;
                if raw.len() == ENTITY_METADATA_HEADER_LEN || visibility.deleted || visibility.stale
                {
                    return Err(MemoryError::not_found(
                        "the witnessed conversation is no longer live",
                    ));
                }
            }
            None if !plan.conversation_is_new => {
                return Err(MemoryError::not_found(
                    "the witnessed conversation no longer exists",
                ));
            }
            None => {}
        }
        let person_author = super::person_author_in_txn(self.vault, wtxn, self.actor)?;
        super::reject_erased_person_in_txn(self.vault, wtxn, plan.conversation_id, person_author)?;
        let witnessed = crate::workspace_roster::admit_room_witness(
            self.vault,
            wtxn,
            self.actor,
            self.actor_class,
            plan.conversation_id,
            plan.turn_id,
            plan.turn,
            &message_ids,
            quote_key,
            regeneration.as_ref(),
        )?;
        let leader_project = crate::workspace_roster::admit_leader_chat_witness(
            self.vault,
            wtxn,
            plan.conversation_id,
            self.actor,
            plan.turn
                .messages
                .iter()
                .any(|m| m.author == super::WitnessAuthor::System),
        )?;
        if let Some(project) = leader_project
            && self
                .vault
                .get_entity_type_in_txn(wtxn, &plan.turn_id)?
                .is_some()
        {
            crate::workspace_roster::verify_existing_leader_chat_turn(
                self.vault,
                wtxn,
                plan.turn_id,
                plan.conversation_id,
                self.actor,
                project,
            )?;
        }
        if leader_project.is_some() {
            crate::workspace_roster::permit_leader_chat_record(
                &self.vault.store,
                wtxn,
                plan.turn_id,
                plan.conversation_id,
            )?;
        }
        // L7-05: a work-talk conversation admits its two bound writers only;
        // a third writer is refused here. The binding needs no settle step:
        // work-talk turns are ordinary company content.
        let _work_talk = crate::workspace_roster::admit_work_talk_witness(
            self.vault,
            wtxn,
            plan.conversation_id,
            self.actor,
        )?;
        Ok(BaseGuards::Clear {
            mint_conversation: current_conversation.is_none(),
            person_author,
            leader_project,
            quoted: witnessed.quoted,
            thread: witnessed.thread,
        })
    }

    /// The base receipt, read in the transaction `txn` that wrote the turn:
    /// canonical short ids, hex when none exists, and the typed refs of the
    /// TURN and MESSAGEs built from the ids the plan holds, with no read.
    pub(super) fn base_receipt_in_txn(
        &self,
        plan: &WitnessPlan<'_>,
        txn: &heed::RoTxn<'_>,
    ) -> MemoryResult<WitnessReceipt> {
        let mut message_short_ids = Vec::with_capacity(plan.messages.len());
        let mut messages = Vec::with_capacity(plan.messages.len());
        for planned in &plan.messages {
            let short = self.short_ref_of_in_txn(txn, &planned.id)?;
            messages.push(crate::lens::RecordRef::from_id(
                crate::registry::ENTITY_TYPE_MESSAGE,
                &planned.id,
                short.as_deref(),
            ));
            message_short_ids.push(short.unwrap_or_else(|| planned.id.to_hex()));
        }
        let turn_short = self.short_ref_of_in_txn(txn, &plan.turn_id)?;
        Ok(WitnessReceipt {
            turn_id: plan.turn_id,
            turn: Some(crate::lens::RecordRef::from_id(
                crate::registry::ENTITY_TYPE_TURN,
                &plan.turn_id,
                turn_short.as_deref(),
            )),
            turn_short_id: turn_short.unwrap_or_else(|| plan.turn_id.to_hex()),
            message_short_ids,
            receipt_ref: format!("witness:{}", plan.turn_id.to_hex()),
            messages,
            // The wake this turn owes is judged after the receipt is read,
            // in the same writer (`run_witness_as`).
            wake_outcome: None,
        })
    }

    fn resolve_or_new_container(
        &self,
        reference: &str,
        expected_type: u8,
        admit: Option<Admit<'_>>,
    ) -> MemoryResult<(EntityId, bool)> {
        let rtxn = self.vault.store.env.read_txn().map_err(Error::from)?;
        if let Some(admit) = admit {
            admit(&rtxn)?;
        }
        let trimmed = reference.trim();
        if trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let id = EntityId::from_hex(trimmed)
                .map_err(|_| MemoryError::bad_request(format!("invalid entity id {trimmed:?}")))?;
            return match self.vault.get_entity_type_in_txn(&rtxn, &id)? {
                Some(entity_type) if entity_type == expected_type => Ok((id, false)),
                Some(entity_type) => Err(MemoryError::bad_request(format!(
                    "ref {trimmed:?} resolves to kind {} but {} was expected",
                    self.vault.entity_kind_name(entity_type),
                    self.vault.entity_kind_name(expected_type),
                ))),
                None => Ok((id, true)),
            };
        }
        let id = resolve_entity_ref_in_txn(self.vault, &rtxn, trimmed)?;
        match self.vault.get_entity_type_in_txn(&rtxn, &id)? {
            Some(entity_type) if entity_type == expected_type => Ok((id, false)),
            Some(entity_type) => Err(MemoryError::bad_request(format!(
                "ref {reference:?} resolves to kind {} but {} was expected",
                self.vault.entity_kind_name(entity_type),
                self.vault.entity_kind_name(expected_type),
            ))),
            None => Err(MemoryError::not_found(format!(
                "entity {reference:?} does not resolve"
            ))),
        }
    }
}

/// [`resolve_entity_ref`] in `rtxn`: a short ref resolves in that snapshot. A
/// hex id or a malformed ref reads nothing, so it takes the shared path.
fn resolve_entity_ref_in_txn(
    vault: &crate::Vault,
    rtxn: &heed::RoTxn<'_>,
    reference: &str,
) -> MemoryResult<EntityId> {
    match crate::entity_id::parse_short_ref_syntax(reference) {
        Ok((short_id, content_hash)) => vault
            .hydrate_short_id_in(rtxn, short_id, content_hash)?
            .map(|entry| entry.id)
            .ok_or_else(|| {
                MemoryError::not_found(format!("short ref {reference:?} does not resolve"))
            }),
        Err(_) => resolve_entity_ref(vault, reference),
    }
}

/// [`crate::batch::BatchBuilder::put`] of the turn's TURN or CONVERSATION
/// row, through the source-bound door when the landing holds a source's
/// proof: its rows carry the source-audience obligation (fix list row 16256).
fn put_container<'b>(
    batch: crate::batch::BatchBuilder<'b>,
    birth: Option<&crate::source_audience::SourceAudienceBirth>,
    phone: Option<&crate::voice_call::PhoneThreadBirth>,
    id: &EntityId,
    entity_type: u8,
    (occurred, learned_at): (crate::temporal::TimeRange, u64),
    body: &[u8],
) -> crate::batch::BatchBuilder<'b> {
    match (birth, phone) {
        (Some(birth), _) => {
            batch.put_source_bound(id, entity_type, occurred, learned_at, body, birth)
        }
        (None, Some(phone)) => {
            batch.put_phone_bound(id, entity_type, occurred, learned_at, body, phone)
        }
        (None, None) => batch.put(id, entity_type, occurred, learned_at, body),
    }
}
