//! The witness program's one write transaction: guards and admission, staging, `effect`,
//! the reply's assertions, program wakes, leader chats, and the route revalidated last.

use super::*;

/// What the witness write reads, prepared before its transaction opens.
pub(super) struct WitnessWrite<'w, 't, 'a, 'v, 'l> {
    pub(super) plan: &'w WitnessPlan<'t>,
    pub(super) sink: &'w WitnessSink<'a, 'v>,
    pub(super) held: Option<HeldTags<'a>>,
    pub(super) door: WitnessDoor,
    pub(super) room_speech: Option<(&'a OffRecordSession<'v>, EntityId)>,
    pub(super) quote_key: Option<&'w crate::claim::ScopedReadActorKey>,
    pub(super) assertion_lane: Option<&'w ScopedRead<'l>>,
    pub(super) refused: &'w Cell<Option<String>>,
    pub(super) unproven: &'w Cell<Vec<String>>,
    pub(super) silent: bool,
    pub(super) saver: Option<&'w crate::off_record::SaverCheck<'a, 'v>>,
    pub(super) terminal: Option<&'w super::super::super::stream::SessionStreamTerminal>,
}

impl Memory<'_> {
    /// The write transaction's body. `lands_new` carries out which of the
    /// turn's messages this write lands new.
    pub(super) fn land_witness_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        write: &WitnessWrite<'_, '_, '_, '_, '_>,
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<Option<RoomRegenerationPermit>>,
        effect: impl FnOnce(&mut heed::RwTxn<'_>, Option<&WitnessReceipt>) -> MemoryResult<()>,
        lands_new: &mut Vec<bool>,
    ) -> MemoryResult<Landed> {
        let mut mint_conversation = false;
        let mut person_author = None;
        let mut leader_project = None;
        let mut quoted = None;
        let mut thread = None;
        let guarded_plan = match write.sink {
            WitnessSink::Base(_) => {
                match self.base_guards_in_txn(write.plan, wtxn, prepare, write.quote_key)? {
                    BaseGuards::HardDeleted(id) => return Ok(Landed::HardDeleted(id)),
                    BaseGuards::Clear {
                        mint_conversation: absent,
                        person_author: person,
                        leader_project: project,
                        quoted: proven,
                        thread: binding,
                    } => {
                        mint_conversation = absent;
                        person_author = person.filter(|_| write.plan.imported.is_none());
                        leader_project = project;
                        quoted = proven;
                        thread = binding;
                    }
                }
                Some(self.custody_witness_plan_in_txn(wtxn, write.plan)?)
            }
            WitnessSink::Overlay(_) => None,
        };
        let write = &WitnessWrite {
            plan: guarded_plan.as_ref().unwrap_or(write.plan),
            ..*write
        };
        let WitnessWrite {
            plan,
            sink,
            door,
            unproven,
            silent,
            saver,
            ..
        } = *write;
        let admission = match sink {
            WitnessSink::Base(_) => {
                let assertions = write.assertion_lane.map(|lane| AssertionRead {
                    lane,
                    refused: write.refused,
                    unproven: write.unproven,
                });
                self.admit_witness_in_txn(
                    plan,
                    &self.vault.store,
                    wtxn,
                    assertions,
                    person_author,
                    quoted.as_ref(),
                    thread.as_ref(),
                )?
            }
            WitnessSink::Overlay(overlay) => self.admit_overlay_in_txn(wtxn, write, overlay)?,
        };
        *lands_new = admission
            .message_exists
            .iter()
            .map(|exists| !exists)
            .collect();
        // An exact retry lands nothing new, so its assertions earn no
        // creation status again (FIX 1211).
        let lands_nothing =
            !matches!(admission.turn, AdmittedTurn::Mint { .. }) && !admission.has_new_messages();
        if lands_nothing {
            unproven.take();
        }
        if matches!(sink, WitnessSink::Base(_))
            && matches!(admission.turn, AdmittedTurn::Mint { .. })
        {
            crate::conversation_dag::permit_core_turn_in_txn(
                self.vault,
                wtxn,
                &plan.conversation_id,
                plan.turn_id,
            )?;
        }
        let mut landed = match sink {
            WitnessSink::Base(base) => {
                let receipt = self.stage_base_landing_in_txn(
                    wtxn,
                    write,
                    base,
                    &admission,
                    mint_conversation,
                    quoted.as_ref(),
                )?;
                // Admission produces one authorization per planned message,
                // in plan order, including exact retries.
                let bodies = plan
                    .messages
                    .iter()
                    .enumerate()
                    .map(|(index, planned)| {
                        (
                            planned.id,
                            planned.occurred.start,
                            admission.authorized[index].body().to_vec(),
                        )
                    })
                    .collect();
                Landed::Base { receipt, bodies }
            }
            WitnessSink::Overlay(overlay) => {
                let (segment, aliases) = self.stage_in_overlay(plan, &admission, overlay, wtxn)?;
                Landed::Overlay { segment, aliases }
            }
        };
        if matches!(sink, WitnessSink::Base(_))
            && matches!(admission.turn, AdmittedTurn::Mint { .. })
        {
            crate::conversation_dag::join_core_turn_in_txn(
                self.vault,
                wtxn,
                &plan.conversation_id,
                plan.turn_id,
                plan.learned_at,
            )?;
        }
        if let Some(terminal) = write.terminal
            && let [planned] = plan.messages.as_slice()
            && admission.message_exists.as_slice() == [false]
        {
            let view = match sink {
                WitnessSink::Base(_) => None,
                WitnessSink::Overlay(overlay) => Some(overlay.read_view()?),
            };
            let dbs = match &view {
                Some(view) => crate::side_table::RoutedDbs::Session(view),
                None => crate::side_table::RoutedDbs::Base(self.vault),
            };
            let assertions = match &view {
                Some(view) => {
                    super::super::super::reply_assertions::admitted_reply_assertions_in_txn(
                        view,
                        wtxn,
                        &[&plan.turn.assertions],
                    )?
                }
                None => super::super::super::reply_assertions::admitted_reply_assertions_in_txn(
                    &self.vault.store,
                    wtxn,
                    &[&plan.turn.assertions],
                )?,
            };
            let bytes = match &view {
                Some(view) => staged_message_bytes(view, wtxn, &planned.id)?,
                None => staged_message_bytes(&self.vault.store, wtxn, &planned.id)?,
            };
            let receipt = super::super::super::stream::MessageStreamReceipt {
                message_id: planned.id,
                actor: self.actor,
                generation: terminal.generation,
                finality: terminal.finality,
                finality_reason: terminal.finality_reason.clone(),
                finish_reason: terminal.finish_reason.clone(),
                bytes,
                recovered: false,
                ephemeral_text_lost: false,
                receipt_ref: format!(
                    "stream:v1:{}:{}",
                    planned.id.to_hex(),
                    terminal.generation.to_hex()
                ),
                reply_assertions: assertions,
            };
            super::super::super::stream::keep_session_terminal_in_txn(&dbs, wtxn, &receipt)?;
            terminal.remember(receipt);
        }
        effect(
            wtxn,
            match &landed {
                Landed::Base { receipt, .. } => Some(receipt),
                _ => None,
            },
        )?;
        // A source landing binds in `effect` every row it marked born, or
        // commits none of them (fix list row 16256).
        if matches!(sink, WitnessSink::Base(_)) && plan.source_audience().is_some() {
            let mut stamped = vec![plan.conversation_id, plan.turn_id];
            stamped.extend(plan.message_ids());
            crate::source_audience::refuse_unbound_births_in(self.vault, wtxn, &stamped)?;
        }
        // FIX 10260: a reply born whole keeps the set its turn asserted,
        // as admitted above, beside each MESSAGE this write landed new; a
        // streamed birth's receipt, which `effect` saved, keeps it there.
        if matches!(sink, WitnessSink::Base(_)) && !silent {
            self.keep_reply_assertions_in_txn(wtxn, plan, lands_new)?;
        }
        // DOOR-141: a turn that lands new words at base owes each program
        // its actor armed a wake, recorded in this commit so a crash after
        // it cannot lose one. An import is a source's words and a host
        // door's turn the engine's own: neither wakes a program. The
        // record never fails the turn; one it cannot write is logged, and
        // the turn's receipt says what the wake came to (FIX 9970).
        if matches!(sink, WitnessSink::Base(_))
            && plan.imported.is_none()
            && !door.is_host()
            && (matches!(admission.turn, AdmittedTurn::Mint { .. }) || admission.has_new_messages())
        {
            let outcome =
                self.record_turn_program_wakes_in_txn(wtxn, plan.conversation_id, plan.turn_id);
            if let Landed::Base { receipt, .. } = &mut landed {
                receipt.wake_outcome = Some(outcome);
            }
        }
        if let Some(project) = leader_project {
            self.settle_leader_chats_in_txn(wtxn, plan, project)?;
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
        if let WitnessSink::Base(base) = sink
            && let Some(route) = base.route
        {
            // A stretch on record saves into its saver's vault only while
            // they hold it (in a room, whoever speaks; ARCH-0052 D5).
            if let Some(saver) = saver {
                saver.in_txn(wtxn)?;
            }
            route.revalidate()?;
        }
        Ok(landed)
    }

    /// A base turn's asserted set, as admitted in this write, kept beside
    /// each MESSAGE the write landed new.
    fn keep_reply_assertions_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        plan: &WitnessPlan<'_>,
        lands_new: &[bool],
    ) -> MemoryResult<()> {
        let assertions =
            crate::memory::witness::reply_assertions::admitted_reply_assertions_in_txn(
                &self.vault.store,
                wtxn,
                &[&plan.turn.assertions],
            )?;
        let landed: Vec<EntityId> = plan
            .messages
            .iter()
            .zip(lands_new)
            .filter(|(_, new)| **new)
            .map(|(planned, _)| planned.id)
            .collect();
        crate::memory::witness::reply_assertions::keep_birth_reply_assertions_in_txn(
            self.vault,
            wtxn,
            plan.conversation_id,
            plan.turn_id,
            (self.actor, self.actor_class as u8),
            &assertions,
            &landed,
        )?;
        Ok(())
    }

    /// A leader chat's turn and messages settle onto the project it leads.
    fn settle_leader_chats_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        plan: &WitnessPlan<'_>,
        project: EntityId,
    ) -> MemoryResult<()> {
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
        Ok(())
    }
}

/// The text the same staged row actually holds, after its canonical write admission.
fn staged_message_bytes(
    dbs: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> MemoryResult<u64> {
    let row = crate::ports::EntityStoreRead::port_entity_record(dbs, txn, message)?.ok_or(
        Error::InvariantViolation("a staged stream MESSAGE is missing"),
    )?;
    let body = crate::entity_doc::resolve_record_body(dbs, txn, message, &row.body)?;
    let body: serde_json::Value =
        rmp_serde::from_slice(&body).map_err(|_| Error::CorruptedIndex("stream MESSAGE body"))?;
    let content = body
        .get("content")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::CorruptedIndex("stream MESSAGE content"))?;
    Ok(content.len() as u64)
}
