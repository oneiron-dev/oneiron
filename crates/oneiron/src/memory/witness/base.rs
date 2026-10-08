//! Base witness landing: container resolve, K7 door, batch write, text ops, session bump.

use super::super::structural::*;
use super::super::support::*;
use super::super::*;
use super::program::{AdmittedTurn, WitnessAdmission, WitnessDoor, WitnessPlan, WitnessTarget};

use std::sync::atomic::Ordering;

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::session_overlay::SessionWriteRoute;

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
            WitnessTarget::Base { route: None },
            WitnessDoor::Guest,
            || {},
            |_| Ok(()),
            |_| Ok(()),
        )
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
            },
            WitnessDoor::Guest,
            before_txn,
            |_| Ok(()),
            |_| Ok(()),
        )
    }

    pub(crate) fn witness_host_executor(
        &self,
        turn: &WitnessTurn,
        session_route: Option<&SessionWriteRoute>,
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness(
            turn,
            WitnessTarget::Base {
                route: session_route,
            },
            WitnessDoor::HostExecutor,
            || {},
            |_| Ok(()),
            |_| Ok(()),
        )
    }

    /// Stream terminal sidecars and EntityDoc birth share the canonical witness
    /// transaction. An error rolls back row, indexes, receipt and seed deletion.
    pub(crate) fn witness_with_route_and_txn_effect(
        &self,
        turn: &WitnessTurn,
        session_route: Option<&SessionWriteRoute>,
        before_txn: impl FnOnce(),
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness(
            turn,
            WitnessTarget::Base {
                route: session_route,
            },
            WitnessDoor::Guest,
            before_txn,
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
            WitnessTarget::Base { route: None },
            WitnessDoor::Guest,
            || {},
            prepare,
            |_| Ok(()),
        )
    }

    // ── the base landing ────────────────────────────────────────────────

    /// The conversation and TURN a base landing writes, each with its
    /// pre-transaction "not stored yet" answer. `continuation` is the session's
    /// on-record shell, which replaces the caller's conversation ref.
    pub(super) fn resolve_base_containers(
        &self,
        turn: &WitnessTurn,
        continuation: Option<EntityId>,
        door: WitnessDoor,
    ) -> MemoryResult<((EntityId, bool), (EntityId, bool))> {
        let conversation = match continuation {
            Some(shell) => {
                self.resolve_or_new_container(&shell.to_hex(), ENTITY_TYPE_CONVERSATION)?
            }
            None => {
                self.resolve_or_new_container(&turn.conversation_ref, ENTITY_TYPE_CONVERSATION)?
            }
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
            (WitnessDoor::HostTurn(id), _) => {
                self.resolve_or_new_container(&id.to_hex(), ENTITY_TYPE_TURN)?
            }
            (_, Some(reference)) => self.resolve_or_new_container(reference, ENTITY_TYPE_TURN)?,
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
    /// PERSON is refused, and a project room admits the witness.
    pub(super) fn base_guards_in_txn(
        &self,
        plan: &WitnessPlan<'_>,
        wtxn: &mut heed::RwTxn<'_>,
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
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
        prepare(wtxn)?;
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
        crate::workspace_roster::admit_room_witness(
            self.vault,
            wtxn,
            self.actor,
            self.actor_class,
            plan.conversation_id,
            plan.turn_id,
            plan.turn,
            &message_ids,
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
        Ok(BaseGuards::Clear {
            mint_conversation: current_conversation.is_none(),
            person_author,
            leader_project,
        })
    }

    /// Stages the admitted turn into base: one batch, its text ops, the open
    /// session's activity bump and the turn's session membership.
    pub(super) fn stage_in_base(
        &self,
        plan: &WitnessPlan<'_>,
        admission: &WitnessAdmission<'_>,
        sink: &BaseSink<'_>,
        mint_conversation: bool,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> MemoryResult<()> {
        let mut batch = self.vault.batch_in();
        if mint_conversation {
            batch = batch.put(
                &plan.conversation_id,
                ENTITY_TYPE_CONVERSATION,
                plan.occurred,
                plan.learned_at,
                &plan.conversation_body,
            );
        }
        match &admission.turn {
            // The structural TURN → CONVERSATION edge, minted with the row:
            // `ChildOf` is the ONLY reader-side answer to "which conversation
            // is this turn in", so a turn minted without it is one no
            // consolidation round can group.
            AdmittedTurn::Mint { body } => {
                batch = batch
                    .put(
                        &plan.turn_id,
                        ENTITY_TYPE_TURN,
                        plan.occurred,
                        plan.learned_at,
                        body,
                    )
                    .edge(&plan.turn_id, EdgeKind::ChildOf, &plan.conversation_id, 1.0);
            }
            // Only a genuinely new child re-dirties an established TURN. A
            // byte-identical deterministic MESSAGE retry is a transcript no-op;
            // moving the TURN watermark on every CAS retry would make
            // idempotency observable downstream.
            AdmittedTurn::Existing(record) if admission.has_new_messages() => {
                let redirtied_at = plan
                    .turn
                    .occurred_at
                    .max(record.learned_at.saturating_add(1));
                batch = batch.put(
                    &plan.turn_id,
                    ENTITY_TYPE_TURN,
                    record.occurred,
                    redirtied_at,
                    &record.body,
                );
            }
            AdmittedTurn::Existing(_) => {}
        }
        for ((planned, authorized), exists) in plan
            .messages
            .iter()
            .zip(&admission.authorized)
            .zip(&admission.message_exists)
        {
            // An exact retry: its canonical body and bindings were proved and
            // re-authorized under the current policy; the transcript stays
            // byte-for-byte unchanged.
            if *exists {
                continue;
            }
            // The PUT consumes the authorization itself, not a body handed
            // alongside it: `put_witness_message` is reachable only with the
            // door's own value and writes exactly the bytes it proved.
            batch = batch
                .put_witness_message(&planned.id, plan.occurred, plan.learned_at, authorized)
                .edge(&planned.id, EdgeKind::PartOf, &plan.turn_id, 1.0)
                .edge(&planned.id, EdgeKind::BelongsTo, &plan.conversation_id, 1.0);
            if planned.message.author != WitnessAuthor::System {
                batch = batch.edge(&planned.id, EdgeKind::AuthoredBy, &self.actor, 1.0);
            }
        }
        batch.apply(wtxn)?;
        // The re-put moves the TURN only to `old + 1`, which a scope cursor a
        // later TURN advanced can already be past; the re-dirty carrier puts it
        // past every cursor in this same commit.
        if matches!(admission.turn, AdmittedTurn::Existing(_)) && admission.has_new_messages() {
            crate::dreamer_consolidation::redirty::redirty_turn_in_txn(
                self.vault,
                wtxn,
                &plan.turn_id,
                plan.turn.occurred_at,
            )?;
        }
        let text_ops: Vec<BatchOp> = plan
            .messages
            .iter()
            .zip(&admission.message_exists)
            .filter(|(planned, exists)| !**exists && !planned.message.content.is_empty())
            .map(|(planned, _)| BatchOp::Text {
                id: planned.id,
                fields: vec![("content".to_owned(), planned.message.content.clone())],
            })
            .collect();
        if !text_ops.is_empty() {
            apply_ops(
                &self.vault.store,
                &self.vault.config,
                &self.vault.analyzer,
                wtxn,
                text_ops,
                sink.text_index_trusted,
                false,
                true,
            )?;
        }
        // RT-03 (ONE-1685): a witnessed turn bumps the open session's
        // activity clock — atomically with the turn write, so a crash
        // cannot record the turn without the bump.
        let bumped_session = crate::session_lifecycle::bump_open_session_activity_in_txn(
            &self.vault.store,
            wtxn,
            plan.learned_at,
        )?;
        // DREAM-008 (ONE-1250): the TURN → SESSION membership fact, in THIS
        // transaction for the same reason the bump is — a crash cannot record
        // a turn without its sitting, so the compaction handoff door can prove
        // which session a turn came from instead of trusting a packet's claim.
        // Minted turns only: an append to an already-stored turn never
        // re-homes it into whatever sitting is open now, and a turn witnessed
        // outside any session records nothing (ARCH-0002 open-endedness).
        let membership_session =
            bumped_session.filter(|_| matches!(admission.turn, AdmittedTurn::Mint { .. }));
        crate::session_lifecycle::record_turn_session_membership_in_txn(
            &self.vault.store,
            wtxn,
            &plan.turn_id,
            membership_session,
        )?;
        Ok(())
    }

    /// The base receipt: canonical short ids, hex when none exists.
    pub(super) fn base_receipt(&self, plan: &WitnessPlan<'_>) -> MemoryResult<WitnessReceipt> {
        let mut message_short_ids = Vec::with_capacity(plan.messages.len());
        for planned in &plan.messages {
            message_short_ids.push(self.short_ref_or_hex(&planned.id)?);
        }
        Ok(WitnessReceipt {
            turn_short_id: self.short_ref_or_hex(&plan.turn_id)?,
            message_short_ids,
            receipt_ref: format!("witness:{}", plan.turn_id.to_hex()),
        })
    }

    fn resolve_or_new_container(
        &self,
        reference: &str,
        expected_type: u8,
    ) -> MemoryResult<(EntityId, bool)> {
        let trimmed = reference.trim();
        if trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let id = EntityId::from_hex(trimmed)
                .map_err(|_| MemoryError::bad_request(format!("invalid entity id {trimmed:?}")))?;
            return match self.vault.get_entity_type(&id)? {
                Some(entity_type) if entity_type == expected_type => Ok((id, false)),
                Some(entity_type) => Err(MemoryError::bad_request(format!(
                    "ref {trimmed:?} resolves to kind {} but {} was expected",
                    kind_string_for_type(entity_type),
                    kind_string_for_type(expected_type),
                ))),
                None => Ok((id, true)),
            };
        }
        let id = self.resolve_ref(reference)?;
        match self.vault.get_entity_type(&id)? {
            Some(entity_type) if entity_type == expected_type => Ok((id, false)),
            Some(entity_type) => Err(MemoryError::bad_request(format!(
                "ref {reference:?} resolves to kind {} but {} was expected",
                kind_string_for_type(entity_type),
                kind_string_for_type(expected_type),
            ))),
            None => Err(MemoryError::not_found(format!(
                "entity {reference:?} does not resolve"
            ))),
        }
    }
}
