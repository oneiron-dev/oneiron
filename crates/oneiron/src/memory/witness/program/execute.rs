//! The witness program's run: request shape, target, plan, then one write transaction per landing.
//! `Memory::run_witness` and `Memory::run_witness_as` are its call surface.
//! `memory::witness::program` defines the target, door, landing and plan types it runs on.

use super::*;

impl Memory<'_> {
    /// The witness program. Every witness verb is this function with a target
    /// and a door; the target's session is the only thing that decides where
    /// the rows land.
    ///
    /// Order, for both landings: request shape, target resolution, the plan
    /// (containers, speaker, message ids and bodies), the landing's pre-write
    /// state, `before_txn`, then ONE write transaction that runs a session
    /// door's [`Admit`], the actor checks, the landing's guards, the
    /// erased-PERSON refusal, the ceiling door on every envelope, the
    /// create-or-verify checks, the landing's staging and receipt, `effect`,
    /// and the route revalidation.
    ///
    /// `before_txn` runs in the window between the ADVISORY container
    /// create-or-get and the transaction, which is the race the in-transaction
    /// TURN re-read closes; production callers pass a no-op. `prepare` runs in
    /// a base landing's transaction before the conversation is re-read (project
    /// birth assembles its room there). `effect` shares the transaction (stream
    /// sidecars, EntityDoc birth): its error rolls back every row, index and
    /// receipt.
    pub(in crate::memory::witness) fn run_witness(
        &self,
        turn: &WitnessTurn,
        target: WitnessTarget<'_, '_>,
        door: WitnessDoor,
        before_txn: impl FnOnce(),
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness_as(
            crate::store::Callback::Audited,
            turn,
            target,
            door,
            before_txn,
            |txn| prepare(txn).map(|()| None),
            effect,
        )
    }

    /// [`Self::run_witness`] through the write door `callback` names: an
    /// `effect` that runs host code is [`crate::store::Callback::Opaque`].
    /// Its `prepare` may prove a Retry's room regeneration permit, which the
    /// room guard admits the witness under (FIX 3149).
    #[expect(
        clippy::too_many_arguments,
        reason = "the write door joins the witness program's inputs"
    )]
    pub(in crate::memory::witness) fn run_witness_as(
        &self,
        callback: crate::store::Callback,
        turn: &WitnessTurn,
        target: WitnessTarget<'_, '_>,
        door: WitnessDoor,
        before_txn: impl FnOnce(),
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<Option<RoomRegenerationPermit>>,
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        validate_witness_origin(turn, door.is_host())?;
        if turn.messages.is_empty() {
            return Err(MemoryError::bad_request("witness turn carries no messages"));
        }
        if matches!(door, WitnessDoor::HostTurn(_)) && turn.turn_ref.is_some() {
            return Err(Error::InvariantViolation(
                "host-bound session witness also carried a guest turn ref",
            )
            .into());
        }
        distinct_message_orders(&turn.messages)?;
        // Generated code speaks as the companion: a person's word or the
        // engine's system voice needs an origin a guest cannot assert.
        if self.writes_generated()
            && turn
                .messages
                .iter()
                .any(|message| message.author != WitnessAuthor::Companion)
        {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "generated code cannot author a user or system message",
                &["Witness generated text as the companion."],
            ));
        }
        let session_route;
        let mut on_record_session = None;
        // An on-record stretch's saver, checked again where the turn lands.
        let mut saver = None;
        let mut admit = None;
        let mut room_speech = None;
        let landing = match target {
            WitnessTarget::Base { route } => Landing::Base {
                route,
                continuation: None,
                imported: None,
                held: None,
            },
            WitnessTarget::Held { held } => Landing::Base {
                route: None,
                continuation: None,
                imported: None,
                held: Some(held),
            },
            WitnessTarget::Imported { stamp } => {
                if turn
                    .messages
                    .iter()
                    .any(|message| message.author == WitnessAuthor::System)
                {
                    // A source's system prompt is the source's, never the
                    // engine's own voice.
                    return Err(MemoryError::bad_request(
                        "an imported turn carries no system rows",
                    ));
                }
                if stamp.message_occurred.len() != turn.messages.len() {
                    return Err(MemoryError::bad_request(
                        "an imported turn carries one source time per message",
                    ));
                }
                Landing::Base {
                    route: None,
                    continuation: None,
                    imported: Some(stamp),
                    held: None,
                }
            }
            WitnessTarget::Session {
                session,
                summary,
                admit: session_admit,
                rostered,
            } => {
                on_record_session = Some(session);
                admit = session_admit;
                (session_route, saver) = session.landing_route()?;
                // WitnessReceipt promises materialized turns and messages.
                // Anonymous sessions cannot fulfill that promise, so refuse
                // before shell reservation, transaction acquisition, or policy
                // receipt creation.
                session_route.require_recording(session.session_ref())?;
                if session_route.target() == RouteTarget::Base {
                    // Post-flip: the stretch is on record, so the witness lands in
                    // base under the continuation shell. It never reuses the
                    // overlay conversation id, so K4 sees no overlay refs and
                    // K7 does not fire (the shell is not an overlay member).
                    // The route rides INTO the base transaction: the base half
                    // is the one that publishes durably, so it is the half
                    // that most needs the refusal.
                    Landing::Base {
                        route: Some(&session_route),
                        continuation: Some(session.on_record_continuation_shell()?),
                        imported: None,
                        held: None,
                    }
                } else {
                    room_speech = rostered.map(|room| (session, room));
                    Landing::Overlay {
                        session,
                        route: &session_route,
                        summary,
                    }
                }
            }
        };

        // A quote rides a message of a room turn that lands at base and is
        // no import (OF-460, FIX 2027, FIX 2028); the room guard proves each
        // there, cited by its message.
        let quoting = turn.messages.iter().any(|m| m.quote.is_some());
        if quoting && !matches!(landing, Landing::Base { imported: None, .. }) {
            return Err(MemoryError::bad_request(
                "a quote lands only on a non-imported room turn at base",
            ));
        }
        // OF-063 prose links (Engine ruling 10-17): every AI-written message
        // this program lands, whatever door it came through, is read for
        // links its writer cannot resolve, receipt-only and before the writer
        // opens; the receipt is written only once the turn has landed (Engine
        // ruling 10-18: landed speech only). An overlay landing is a
        // non-anonymous off-record session (an anonymous one was refused
        // above), so its room speech keeps its receipt; only an anonymous
        // session keeps none. An imported turn is a source's words, not this
        // writer's.
        let unlinked_prose = if matches!(
            landing,
            Landing::Base {
                imported: Some(_),
                ..
            }
        ) {
            Vec::new()
        } else {
            crate::gate::record_references::witness_prose_unlinked(self, turn)
        };
        // OF-063 (FIX 1225/1670): the records a reply asserts it cited or
        // created are read through the writer's own lane, opened here since
        // it takes its own snapshot and so never runs inside the writer. A
        // turn that asserts nothing opens none. `refused` carries the first
        // pointer the lane cannot read out of the aborted writer.
        let silent = turn.assertions.cited.is_empty() && turn.assertions.created.is_empty();
        let assertion_lane = if silent {
            None
        } else {
            Some(self.read_lane(ClaimReadStatus::Recorded)?)
        };
        let refused = Cell::new(None);
        let unproven = Cell::new(Vec::new());
        let plan = self.plan_witness(turn, &landing, door, admit)?;
        let held = match &landing {
            Landing::Base { held, .. } => *held,
            Landing::Overlay { .. } => None,
        };
        let sink = match landing {
            Landing::Base { route, .. } => WitnessSink::Base(self.base_sink(&plan, route)?),
            Landing::Overlay {
                session,
                route,
                summary,
            } => WitnessSink::Overlay(self.overlay_sink(session, route, summary)?),
        };
        // FIX 2027: a quote's selection is read under the speaker's own key,
        // taken here, before the writer opens: no read snapshot nests in it.
        let quote_key = quoting.then(|| self.read_key()).transpose()?;
        // FIX 3284: which of the turn's messages this write lands new, carried
        // out of its transaction. A message an exact retry finds stored lands
        // nothing and owes no second prose receipt.
        let mut lands_new: Vec<bool> = Vec::new();
        before_txn();

        let landed = self.with_witness_write_txn_as(callback, admit, room_speech, |wtxn| {
            let mut mint_conversation = false;
            let mut leader_project = None;
            let mut quoted: Option<crate::conversation_dag::QuotedReply> = None;
            let admission = match &sink {
                WitnessSink::Base(_) => {
                    let (person_author, thread) =
                        match self.base_guards_in_txn(&plan, wtxn, prepare, quote_key.as_ref())? {
                            BaseGuards::HardDeleted(id) => return Ok(Landed::HardDeleted(id)),
                            BaseGuards::Clear {
                                mint_conversation: absent,
                                person_author,
                                leader_project: project,
                                quoted: proven,
                                thread,
                            } => {
                                mint_conversation = absent;
                                leader_project = project;
                                quoted = proven;
                                // The importer is not the author of the source's words.
                                (person_author.filter(|_| plan.imported.is_none()), thread)
                            }
                        };
                    let assertions = assertion_lane.as_ref().map(|lane| AssertionRead {
                        lane,
                        refused: &refused,
                        unproven: &unproven,
                    });
                    self.admit_witness_in_txn(
                        &plan,
                        &self.vault.store,
                        wtxn,
                        assertions,
                        person_author,
                        quoted.as_ref(),
                        thread.as_ref(),
                    )?
                }
                // Host-derived ids are create-or-verify in the COMPOSED
                // overlay/base snapshot. The view is dropped before the
                // overlay segment installs, and a divergent body or parent
                // leaves no journal or index delta.
                WitnessSink::Overlay(overlay) => {
                    let rostered = room_speech.is_some();
                    let person_author =
                        self.overlay_guards_in_txn(&plan, overlay, rostered, wtxn)?;
                    // The writer's own key reads the composed room view, as
                    // recall's session lane does; both drop here.
                    let view = overlay.read_view()?;
                    // A thread turn staged here is born bound as on base, to
                    // the stretch's room and read against its base members
                    // (FIX 3122); a stored one keeps its thread and takes
                    // words from its audience alone.
                    let thread = crate::workspace_roster::overlay_thread_binding_in(
                        self.vault,
                        &view.read(),
                        wtxn,
                        overlay.room()?,
                        plan.conversation_id,
                        plan.turn_id,
                        self.actor,
                        plan.turn,
                    )?;
                    let session_lane = assertion_lane.as_ref().map(|lane| {
                        self.vault
                            .scoped_read_in_session(lane.actor_key().clone(), &view)
                            .with_claim_status(ClaimReadStatus::Recorded)
                    });
                    let assertions = session_lane.as_ref().map(|lane| AssertionRead {
                        lane,
                        refused: &refused,
                        unproven: &unproven,
                    });
                    self.admit_witness_in_txn(
                        &plan,
                        &view,
                        wtxn,
                        assertions,
                        person_author,
                        None,
                        thread.as_ref(),
                    )?
                }
            };
            lands_new = admission
                .message_exists
                .iter()
                .map(|exists| !exists)
                .collect();
            let landed = match &sink {
                WitnessSink::Base(base) => {
                    self.stage_in_base(
                        &plan,
                        &admission,
                        base,
                        mint_conversation,
                        quoted.as_ref(),
                        wtxn,
                    )?;
                    // The outbox rule (write-path hub; ARCH-0036): a turn that
                    // gained text owes the vault's tagger a pass, and its
                    // embedder a vector of the new text (ARCH-0004), committed
                    // with the turn. An exact retry stages nothing and owes
                    // nothing.
                    if matches!(admission.turn, AdmittedTurn::Mint { .. })
                        || admission.has_new_messages()
                    {
                        // A chat or voice commit owes a live pass; an import,
                        // held tags and the host executor a bulk one (FIX 6755).
                        let work = if plan.imported.is_some()
                            || held.is_some()
                            || matches!(door, WitnessDoor::HostExecutor)
                        {
                            crate::memory::extraction::ExtractionWork::Bulk
                        } else {
                            crate::memory::extraction::ExtractionWork::Live
                        };
                        crate::tagging::mark_turn_in_txn(self.vault, wtxn, plan.turn_id, work)?;
                        crate::embed::mark_turn_in_txn(self.vault, wtxn, plan.turn_id)?;
                        crate::workspace_roster::stage_project_detection_in_txn(
                            self.vault,
                            wtxn,
                            plan.conversation_id,
                            plan.turn_id,
                            plan.messages
                                .iter()
                                .rev()
                                .find(|planned| {
                                    planned.message.author == WitnessAuthor::User
                                        && planned.message.is_visible
                                        && !planned.message.content.is_empty()
                                })
                                .map(|planned| planned.id),
                            (self.actor_class == crate::edge::EdgeActorClass::Human
                                && plan.imported.is_none())
                            .then_some(self.actor),
                            plan.learned_at,
                        )?;
                    }
                    // Held tags settle the marker just committed, in this
                    // write, so no worker ever claims it. Their spans index
                    // the messages as sent.
                    if let Some(held) = held {
                        let sent: Vec<_> = plan
                            .messages
                            .iter()
                            .map(|planned| (planned.id, planned.message.content.as_str()))
                            .collect();
                        held.outcome
                            .set(Some(crate::tagging::settle_held_tags_in_txn(
                                self.vault,
                                wtxn,
                                &plan.turn_id,
                                held.tags,
                                Some(&sent),
                            )?));
                    }
                    // Read here: a body put after this commit is not its receipt.
                    Landed::Base(self.base_receipt_in_txn(&plan, wtxn)?)
                }
                WitnessSink::Overlay(overlay) => {
                    let (segment, aliases) =
                        self.stage_in_overlay(&plan, &admission, overlay, wtxn)?;
                    Landed::Overlay { segment, aliases }
                }
            };
            effect(wtxn)?;
            // FIX 10260: a reply born whole keeps the set its turn asserted,
            // as admitted above, beside each MESSAGE this write landed new; a
            // streamed birth's receipt, which `effect` saved, keeps it there.
            if matches!(&sink, WitnessSink::Base(_)) && !silent {
                let assertions = super::super::reply_assertions::admitted_reply_assertions_in_txn(
                    &self.vault.store,
                    wtxn,
                    &[&plan.turn.assertions],
                )?;
                let landed: Vec<EntityId> = plan
                    .messages
                    .iter()
                    .zip(&lands_new)
                    .filter(|(_, new)| **new)
                    .map(|(planned, _)| planned.id)
                    .collect();
                super::super::reply_assertions::keep_birth_reply_assertions_in_txn(
                    self.vault,
                    wtxn,
                    plan.conversation_id,
                    plan.turn_id,
                    (self.actor, self.actor_class as u8),
                    &assertions,
                    &landed,
                )?;
            }
            // DOOR-141: a turn that lands new words at base owes each program
            // its actor armed a wake, recorded in this commit so a crash after
            // it cannot lose one. An import is a source's words and a host
            // door's turn the engine's own: neither wakes a program. The
            // record never fails the turn; one it cannot write is logged.
            if matches!(&sink, WitnessSink::Base(_))
                && plan.imported.is_none()
                && !door.is_host()
                && (matches!(admission.turn, AdmittedTurn::Mint { .. })
                    || admission.has_new_messages())
            {
                self.record_turn_program_wakes_in_txn(wtxn, plan.conversation_id, plan.turn_id);
            }
            if let Some(project) = leader_project {
                let message_ids = plan.message_ids();
                for id in std::iter::once(plan.turn_id).chain(message_ids.iter().copied()) {
                    crate::workspace_roster::settle_leader_chat_record(
                        self.vault,
                        wtxn,
                        id,
                        plan.conversation_id,
                        self.actor,
                        project,
                    )?;
                }
            }
            // LAST statement in the transaction, deliberately: a witness
            // admitted on record must not commit base rows once the room has
            // flipped back off record (K10). Every earlier row rolls back with
            // this `Err`. The overlay route is revalidated by every staged
            // entry instead.
            //
            // The check cannot hold the session state lock: the session
            // mutators hold that lock ACROSS their own write transactions
            // (state -> writer), so a base writer taking it (writer -> state)
            // would invert the order. `revalidate` takes only the overlay's
            // own lifecycle lock, which no holder ever blocks on the base
            // writer for. What remains uncovered is the instant between this
            // check and `wtxn.commit()`; closing that would require the flip
            // to drain base writers the way `seal_writes` drains overlay
            // segments.
            if let WitnessSink::Base(base) = &sink
                && let Some(route) = base.route
            {
                // A stretch on record saves into its saver's vault only while
                // they hold it (in a room, whoever speaks; ARCH-0052 D5).
                if let Some(saver) = &saver {
                    saver.in_txn(wtxn)?;
                }
                route.revalidate()?;
            }
            Ok(landed)
        });
        // A refused assertion is receipted only now, on its own write, once
        // the turn's writer has aborted.
        if let Some(pointer) = refused.take() {
            return Err(self.settle_refused_assertion(&pointer));
        }
        let landed = landed?;

        let answer = match landed {
            Landed::HardDeleted(id) => Err(hard_deleted_refusal(&id)),
            Landed::Base(receipt) => {
                // A stretch on record took this turn into base; a copy of the
                // talk reads its messages there.
                if let Some(session) = on_record_session {
                    let messages: Vec<(EntityId, u64, &[u8])> = plan
                        .messages
                        .iter()
                        .map(|planned| {
                            (planned.id, planned.occurred.start, planned.body.as_slice())
                        })
                        .collect();
                    session.note_on_record_messages(plan.turn_id, &messages);
                }
                // A room row this turn extended reaches the room's live window
                // after commit: an append-only extension re-puts no TURN for
                // the live mirror to carry. No room row, no window: a no-op.
                #[cfg(feature = "sync")]
                self.vault.refresh_room_turn_in_live_window(&plan.turn_id);
                Ok(receipt)
            }
            Landed::Overlay { segment, aliases } => {
                // The overlay segment and the base txn commit together: the
                // segment applies staged rows only now, so a failure anywhere
                // in staging left the room byte-unchanged.
                segment.commit()?;
                if let WitnessSink::Overlay(overlay) = sink {
                    overlay.commit_shell();
                }
                overlay_receipt(&plan, aliases)
            }
        };
        if answer.is_ok() {
            let landed_prose =
                crate::gate::record_references::landed_witness_prose(unlinked_prose, &lands_new);
            crate::gate::record_references::receipt_landed_prose(self, &landed_prose);
            crate::receipt::receipt_creations_not_proven(
                self,
                crate::gate::record_references::WITNESS_PROSE_ROW,
                &unproven.take(),
            );
        }
        answer
    }

    /// Receipts a refused assertion on its own write, as a refused typed ref
    /// is (`admit_row_references`), and returns the refusal; if the receipt
    /// cannot be written, the store's error instead. Inside an anonymous
    /// off-record session the refusal stands with no receipt. A model
    /// stream's continuation terminal settles its own through it too (FIX
    /// 3416).
    pub(in crate::memory::witness) fn settle_refused_assertion(
        &self,
        pointer: &str,
    ) -> MemoryError {
        let facts = crate::receipt::ReferenceRefusalFacts {
            actor: self.actor,
            actor_class: self.actor_class,
            row: crate::gate::record_references::WITNESS_PROSE_ROW,
            field: pointer.to_owned(),
            outcome: crate::receipt::ReferenceOutcome::Refused,
        };
        match crate::receipt::receipt_reference_refusals(self, &[facts]) {
            Ok(recorded) => crate::gate::record_references::invented_reference(pointer, recorded),
            Err(error) => error.into(),
        }
    }
}
