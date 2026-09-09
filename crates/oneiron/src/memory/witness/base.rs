//! Base witness program: container resolve, K7 door, batch write, text ops, session bump.

use super::super::structural::*;
use super::super::support::*;
use super::super::*;
use super::codec::{encode_witness_turn_body, incoming_turn_speaker};
use super::validation::{
    validate_existing_witness_message, validate_existing_witness_message_orders,
    validate_existing_witness_turn,
};
use super::{distinct_message_orders, witness_message_envelope};

use std::collections::HashSet;
use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{check_witness_message_ceiling, resolve_policy_manifest};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::session_overlay::SessionWriteRoute;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

impl Memory<'_> {
    // ── write verbs ─────────────────────────────────────────────────────

    /// Witnesses one turn: create-or-get CONVERSATION/TURN, MESSAGE puts,
    /// `PartOf`/`BelongsTo`/`AuthoredBy` edges, and BM25 `content`
    /// indexing — all in ONE atomic batch.
    ///
    /// Every MESSAGE passes the approval-ceiling door
    /// (`gate::witness_message`) immediately before its own put, inside that
    /// batch's transaction. The door binds the FULL envelope — author, type,
    /// content, metadata, visibility, order — to the authenticated actor and
    /// the policy ceiling resolved in the same snapshot, so a caller cannot
    /// smuggle an unattributed `system` row, a metadata side channel or an
    /// ordering signal through a path that only stamps `AuthoredBy`. A refusal
    /// on any message rolls the whole turn back.
    pub fn witness(&self, turn: &WitnessTurn) -> MemoryResult<WitnessReceipt> {
        self.witness_with_route(turn, None)
    }

    /// The base witness program, optionally bound to a session write route.
    ///
    /// `session_route` is `Some` only on [`Self::witness_into_session`]'s
    /// post-flip `Base` arm, where the route is the sole evidence that the
    /// room was ON RECORD when this turn was admitted. The route is
    /// revalidated INSIDE the write transaction, after every row is staged
    /// and before the commit, so a flip back to `OffRecord` landing mid-call
    /// rolls the whole turn back instead of publishing the room's substance
    /// to durable base under a session that now claims to be private.
    ///
    /// The check cannot hold the session state lock: the session mutators hold
    /// that lock ACROSS their own write transactions (state -> writer), so a
    /// base writer taking it (writer -> state) would invert the order.
    /// `revalidate` takes only the overlay's own lifecycle lock, which no
    /// holder ever blocks on the base writer for, so this ordering is safe.
    /// What remains uncovered is the instant between this check and
    /// `wtxn.commit()`; closing that would require the flip to drain base
    /// writers the way `seal_writes` drains overlay segments.
    pub(crate) fn witness_with_route(
        &self,
        turn: &WitnessTurn,
        session_route: Option<&SessionWriteRoute>,
    ) -> MemoryResult<WitnessReceipt> {
        self.witness_with_route_and_before_txn(turn, session_route, || {})
    }

    /// [`Self::witness_with_route`], running `before_txn` in the window
    /// between the ADVISORY container create-or-get and the write
    /// transaction.
    ///
    /// That window is the race the in-transaction TURN re-read closes: the
    /// "this turn does not exist yet" answer taken outside the transaction
    /// may be stale by the time the transaction runs. The seam exists so a
    /// test can move it deliberately; production callers pass a no-op.
    pub(in crate::memory) fn witness_with_route_and_before_txn(
        &self,
        turn: &WitnessTurn,
        session_route: Option<&SessionWriteRoute>,
        before_txn: impl FnOnce(),
    ) -> MemoryResult<WitnessReceipt> {
        if turn.messages.is_empty() {
            return Err(MemoryError::bad_request("witness turn carries no messages"));
        }
        let occurred = TimeRange {
            start: turn.occurred_at,
            end: turn.occurred_at,
        };
        let learned_at = turn.occurred_at;
        let (conversation_id, conversation_is_new) =
            self.resolve_or_new_container(&turn.conversation_ref, ENTITY_TYPE_CONVERSATION)?;
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
            .owning_session_ref(&conversation_id)?
        {
            return Err(Error::OffRecordWitnessDoorRejected {
                session_ref,
                conversation_ref: conversation_id.to_hex(),
            }
            .into());
        }
        let (turn_id, turn_is_new) = match &turn.turn_ref {
            Some(reference) => self.resolve_or_new_container(reference, ENTITY_TYPE_TURN)?,
            None => (EntityId::now(), true),
        };

        // The turn-level grouping fact, derived BEFORE the transaction: a
        // call carrying two non-system speakers is a bad request whatever
        // the store holds. `None` means system/tooling interleave only.
        let incoming_speaker = incoming_turn_speaker(&turn.messages)?;
        distinct_message_orders(&turn.messages)?;

        let conversation_body = encode_rmpv(&Value::Map(Vec::new()))?;
        let mut message_ids = Vec::with_capacity(turn.messages.len());
        let mut envelopes = Vec::with_capacity(turn.messages.len());
        let mut bodies = Vec::with_capacity(turn.messages.len());
        for message in &turn.messages {
            message_ids.push(id_from_optional_hex(message.id.as_deref())?);
            let envelope = witness_message_envelope(message);
            bodies.push(envelope.encode_body()?);
            envelopes.push(envelope);
        }
        // Ids created by this call must be marker-free; checked INSIDE the
        // write transaction below so a concurrent hard delete cannot land
        // between check and commit (A1 atomicity).
        let mut created_ids = message_ids.clone();
        if conversation_is_new {
            created_ids.push(conversation_id);
        }
        if turn_is_new {
            created_ids.push(turn_id);
        }
        let has_text_ops = turn
            .messages
            .iter()
            .any(|message| !message.content.is_empty());
        let text_index_trusted = if has_text_ops {
            self.vault.ensure_text_index_trusted()?;
            true
        } else {
            self.vault.text_index_trusted.load(Ordering::Acquire)
        };
        before_txn();

        let refused = self.with_verified_actor_write_txn(|wtxn| {
            for id in &created_ids {
                if self
                    .vault
                    .local_hard_delete_marker_exists_in_txn(wtxn, id)?
                {
                    return Ok(Some(*id));
                }
            }
            let mut batch = self.vault.batch_in();
            if conversation_is_new {
                batch = batch.put(
                    &conversation_id,
                    ENTITY_TYPE_CONVERSATION,
                    occurred,
                    learned_at,
                    &conversation_body,
                );
            }
            // The pre-transaction create-or-get answer is ADVISORY: a
            // concurrent witness can commit this TURN between that resolve
            // and this transaction. Re-reading the row HERE makes the mint
            // -versus-append decision — and the speaker validation that
            // rides it — transaction-authoritative, so a same-id race takes
            // the append path instead of overwriting the committed turn.
            let existing_turn_raw = self
                .vault
                .store
                .entities
                .get(&*wtxn, turn_id.as_bytes())?
                .map(|raw| raw.to_vec());
            let existing_turn = match existing_turn_raw {
                // Absent and expected absent: the pre-transaction answer holds.
                None if turn_is_new => None,
                // Expected present and gone (a concurrent delete). Recreating
                // it here would silently mint the turn the caller asked to
                // append to, speaker and all.
                None => {
                    return Err(MemoryError::not_found(
                        "the witnessed turn no longer exists",
                    ));
                }
                Some(raw) => {
                    let header = EntityMetadataHeader::parse(&raw)
                        .ok_or(Error::CorruptedIndex("entity header"))?;
                    if header.entity_type != ENTITY_TYPE_TURN {
                        return Err(MemoryError::bad_request(
                            "the witnessed turn ref resolves to a non-TURN entity",
                        ));
                    }
                    Some((header, raw))
                }
            };
            let mut message_already_exists = Vec::with_capacity(message_ids.len());
            for ((message, id), body) in turn.messages.iter().zip(&message_ids).zip(&bodies) {
                message_already_exists.push(validate_existing_witness_message(
                    &self.vault.store,
                    &*wtxn,
                    id,
                    body,
                    &turn_id,
                    &conversation_id,
                    message.author,
                    &self.actor,
                )?);
            }
            if existing_turn.is_none() && message_already_exists.iter().any(|exists| *exists) {
                return Err(MemoryError::bad_request(
                    "an existing witnessed message cannot mint its missing turn",
                ));
            }
            let has_new_messages = message_already_exists.iter().any(|exists| !exists);
            if existing_turn.is_some() {
                let existing_message_ids = message_ids
                    .iter()
                    .zip(&message_already_exists)
                    .filter_map(|(id, exists)| exists.then_some(*id))
                    .collect::<HashSet<_>>();
                validate_existing_witness_message_orders(
                    &self.vault.store,
                    &*wtxn,
                    &turn_id,
                    &turn.messages,
                    &existing_message_ids,
                )?;
            }
            match &existing_turn {
                None => {
                    // A minted TURN carries exactly one grouping speaker; an
                    // all-system call has none to stamp, and the scanner
                    // reads this key (`speaker`) to score the turn's role.
                    let Some(speaker) = incoming_speaker else {
                        return Err(MemoryError::bad_request(
                            "a new witnessed turn needs one non-system speaker",
                        ));
                    };
                    let turn_body = encode_witness_turn_body(speaker)?;
                    // The structural TURN → CONVERSATION edge, minted with
                    // the row: `ChildOf` is the ONLY reader-side answer to
                    // "which conversation is this turn in", so a turn minted
                    // without it is one no consolidation round can group.
                    batch = batch
                        .put(&turn_id, ENTITY_TYPE_TURN, occurred, learned_at, &turn_body)
                        .edge(&turn_id, EdgeKind::ChildOf, &conversation_id, 1.0);
                }
                Some((header, raw)) => {
                    if !validate_existing_witness_turn(
                        &self.vault.store,
                        &*wtxn,
                        &turn_id,
                        &conversation_id,
                        incoming_speaker,
                    )? {
                        return Err(Error::InvariantViolation(
                            "transaction-authoritative TURN disappeared during witness validation",
                        )
                        .into());
                    }
                    // Only a genuinely new child re-dirties an established
                    // TURN. A byte-identical deterministic MESSAGE retry is a
                    // transcript no-op; moving the TURN watermark on every CAS
                    // retry would make idempotency observable downstream.
                    if has_new_messages {
                        let stored_body = &raw[ENTITY_METADATA_HEADER_LEN..];
                        let redirtied_at =
                            turn.occurred_at.max(header.learned_at.saturating_add(1));
                        batch = batch.put(
                            &turn_id,
                            ENTITY_TYPE_TURN,
                            TimeRange {
                                start: header.occurred_start,
                                end: header.occurred_end,
                            },
                            redirtied_at,
                            stored_body,
                        );
                    }
                }
            }
            // ONE-1686 (RT-04): the approval-ceiling door for MESSAGE writes.
            // The policy manifest is resolved from THIS transaction's snapshot,
            // so the ceiling that authorizes the rows is the one the commit
            // lands under — and the whole check runs inside the same
            // transaction as the puts, edges, text ops and TURN re-put, so a
            // refusal on any message rolls the entire turn back.
            let policy = resolve_policy_manifest(&self.vault.store, &*wtxn)?;
            let write_actor = WriteActor::new(self.actor, self.actor_class);
            for (index, ((message, (id, body)), already_exists)) in turn
                .messages
                .iter()
                .zip(message_ids.iter().zip(&bodies))
                .zip(&message_already_exists)
                .enumerate()
            {
                // Immediately before THIS message's put, and the put consumes
                // the door's own bytes: nothing between the authorization and
                // the write can substitute an envelope.
                let authorized = check_witness_message_ceiling(
                    &self.vault.store,
                    &*wtxn,
                    write_actor,
                    &envelopes[index],
                    body,
                    &policy,
                )?;
                if *already_exists {
                    // The exact canonical body and all structural bindings were
                    // proved above. Re-authorize under the current policy, then
                    // leave the transcript byte-for-byte unchanged.
                    continue;
                }
                // The PUT consumes the authorization itself, not a body handed
                // alongside it: `put_witness_message` is reachable only with
                // the door's own value and writes exactly the bytes it proved.
                batch = batch
                    .put_witness_message(id, occurred, learned_at, &authorized)
                    .edge(id, EdgeKind::PartOf, &turn_id, 1.0)
                    .edge(id, EdgeKind::BelongsTo, &conversation_id, 1.0);
                if message.author != WitnessAuthor::System {
                    batch = batch.edge(id, EdgeKind::AuthoredBy, &self.actor, 1.0);
                }
            }
            batch.apply(wtxn)?;
            let text_ops: Vec<BatchOp> = turn
                .messages
                .iter()
                .zip(&message_ids)
                .zip(&message_already_exists)
                .filter(|((message, _), already_exists)| {
                    !**already_exists && !message.content.is_empty()
                })
                .map(|((message, id), _)| BatchOp::Text {
                    id: *id,
                    fields: vec![("content".to_owned(), message.content.clone())],
                })
                .collect();
            if !text_ops.is_empty() {
                apply_ops(
                    &self.vault.store,
                    &self.vault.config,
                    &self.vault.analyzer,
                    wtxn,
                    text_ops,
                    text_index_trusted,
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
                learned_at,
            )?;
            // DREAM-008 (ONE-1250): the TURN → SESSION membership fact, in
            // THIS transaction for the same reason the bump is — a crash
            // cannot record a turn without its sitting, so the compaction
            // handoff door can prove which session a turn came from instead
            // of trusting a packet's claim. Minted turns only: an append to
            // an already-stored turn never re-homes it into whatever sitting
            // is open now, and a turn witnessed outside any session records
            // nothing (ARCH-0002 open-endedness).
            let membership_session = bumped_session.filter(|_| existing_turn.is_none());
            crate::session_lifecycle::record_turn_session_membership_in_txn(
                &self.vault.store,
                wtxn,
                &turn_id,
                membership_session,
            )?;
            // LAST statement in the transaction, deliberately: a session
            // witness admitted on record must not commit base rows once the
            // room has flipped back off record (K10). Every earlier row is
            // rolled back with this `Err`.
            if let Some(route) = session_route {
                route.revalidate()?;
            }
            Ok(None)
        })?;
        if let Some(id) = refused {
            return Err(hard_deleted_refusal(&id));
        }

        let mut message_short_ids = Vec::with_capacity(message_ids.len());
        for id in &message_ids {
            message_short_ids.push(self.short_ref_or_hex(id)?);
        }
        Ok(WitnessReceipt {
            turn_short_id: self.short_ref_or_hex(&turn_id)?,
            message_short_ids,
            receipt_ref: format!("witness:{}", turn_id.to_hex()),
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
