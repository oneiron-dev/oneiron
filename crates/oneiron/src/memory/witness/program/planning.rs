//! Witness planning and the in-transaction admission both landings share.
//! `Memory::plan_witness` and `Memory::admit_witness_in_txn` are its call surface.
//! `memory::witness::program` defines `WitnessPlan`, `WitnessAdmission` and `AssertionRead`.

use super::*;

impl Memory<'_> {
    pub(super) fn plan_witness<'t>(
        &self,
        turn: &'t WitnessTurn,
        landing: &Landing<'_, '_>,
        door: WitnessDoor,
        admit: Option<Admit<'_>>,
    ) -> MemoryResult<WitnessPlan<'t>> {
        let ((conversation_id, conversation_is_new), (turn_id, turn_is_new)) = match landing {
            Landing::Base { continuation, .. } => {
                self.resolve_base_containers(turn, *continuation, door, admit)?
            }
            // The room's one shell; the TURN is fresh, or the host's
            // deterministic id, create-or-verified in the transaction.
            Landing::Overlay { session, .. } => {
                let shell = session.overlay_conversation_shell()?;
                let turn_id = match door {
                    WitnessDoor::HostTurn(id) => id,
                    WitnessDoor::Guest | WitnessDoor::HostExecutor => {
                        self.vault.store.clock.entity_id()?
                    }
                };
                ((shell, false), (turn_id, true))
            }
        };

        // The turn-level grouping fact, derived BEFORE the transaction: a call
        // carrying two non-system speakers is a bad request whatever the store
        // holds. `None` means system/tooling interleave only.
        let speaker = incoming_turn_speaker(&turn.messages)?;
        // ONE-1767 binds the overlay door exactly as it binds the base one,
        // and an overlay witness always mints its TURN (or create-or-verifies
        // the host's), so the call must carry the speaker that mint stamps.
        // Promote (ONE-1730) replays the stamped mint into base.
        if matches!(landing, Landing::Overlay { .. }) && speaker.is_none() {
            return Err(MemoryError::bad_request(
                "a new witnessed turn needs one non-system speaker",
            ));
        }

        let imported = match landing {
            Landing::Base { imported, .. } => imported.cloned(),
            Landing::Overlay { .. } => None,
        };
        let mut messages = Vec::with_capacity(turn.messages.len());
        for (position, message) in turn.messages.iter().enumerate() {
            let id = id_from_optional_hex(self.vault, message.id.as_deref())?;
            let envelope = witness_message_envelope(message);
            let body = envelope.encode_body()?;
            let at = imported
                .as_ref()
                .and_then(|stamp| stamp.message_occurred.get(position).copied())
                .unwrap_or(turn.occurred_at);
            messages.push(PlannedMessage {
                message,
                id,
                occurred: TimeRange { start: at, end: at },
                envelope,
                body,
            });
        }
        // A witnessed row is learned as it occurs; an imported one when it is
        // imported, whatever clock its source kept.
        if imported.is_none() {
            let now = self.vault.store.clock.now_recorded_at();
            validate_witness_occurrence(now, turn.occurred_at)?;
        }
        let learned_at = imported
            .as_ref()
            .map_or(turn.occurred_at, |stamp| stamp.imported_at);
        let conversation_body = match &imported {
            Some(stamp) => stamp.conversation_body.clone(),
            None => encode_rmpv(&Value::Map(Vec::new()))?,
        };
        Ok(WitnessPlan {
            turn,
            occurred: TimeRange {
                start: turn.occurred_at,
                end: turn.occurred_at,
            },
            learned_at,
            conversation_id,
            conversation_is_new,
            conversation_body,
            turn_id,
            turn_is_new,
            speaker,
            messages,
            imported,
        })
    }

    /// The in-transaction half both landings share: the ONE-1686 door on every
    /// envelope, then the create-or-verify checks against `dbs` (base for a
    /// base landing, the composed room view for an overlay one). A minted TURN
    /// carries `person_author` as its immutable byline, or with none an Agent
    /// writer's own AGENT_DEF (FIX 7129), `quoted`, the reply topology the
    /// room guard fixed for its quoted messages, in its first body (OF-460,
    /// FIX 2028), and `thread`, its thread binding (FIX 2951).
    /// `assertions` reads the reply's cited and created records first, when
    /// it names any (OF-063).
    #[expect(
        clippy::too_many_arguments,
        reason = "the shared admission joins both landings' in-transaction inputs"
    )]
    pub(super) fn admit_witness_in_txn<'p>(
        &self,
        plan: &'p WitnessPlan<'_>,
        dbs: &impl ManifestDbs,
        wtxn: &heed::RoTxn<'_>,
        assertions: Option<AssertionRead<'_, '_>>,
        person_author: Option<EntityId>,
        quoted: Option<&crate::conversation_dag::QuotedReply>,
        thread: Option<&crate::workspace_roster::ThreadBinding>,
    ) -> MemoryResult<WitnessAdmission<'p>> {
        // OF-063 (FIX 1225/1670): every record the reply asserts is read in
        // THIS snapshot before any row stages. The first the writer cannot
        // read refuses the turn; its pointer leaves the writer in `refused`.
        if let Some(read) = assertions
            && let Some(pointer) = unread_assertion_in(read.lane, wtxn, &plan.turn.assertions)?
        {
            read.refused.set(Some(pointer));
            return Err(MemoryError::bad_request(
                "a record the reply asserts does not resolve for this writer",
            ));
        }
        // FIX 1211: a created record every check above read is proved made
        // by this writer in the durable run its dispatcher is bound to, or
        // recorded not proven once the turn lands. The reply stands either way.
        if let Some(read) = assertions {
            let run = self
                .host_origin
                .as_ref()
                .and_then(HostWriteOrigin::bound_run);
            let created = unproven_creations_in(dbs, wtxn, &plan.turn.assertions, self.actor, run);
            read.unproven.set(created);
        }
        // ONE-1686 (RT-04): the approval-ceiling door, before ANY row stages.
        // The policy manifest is resolved from THIS transaction's snapshot, so
        // the ceiling that authorizes the rows is the one the commit lands
        // under, and a refusal on any message rolls the whole turn back. The
        // room is not a weaker door: promote replays its journal into base
        // verbatim, so an envelope the base boundary refuses is refused at
        // staging too, before the overlay segment installs.
        let policy = resolve_policy_manifest(&self.vault.store, wtxn)?;
        let write_actor = self.write_actor();
        let mut authorized = Vec::with_capacity(plan.messages.len());
        for planned in &plan.messages {
            // The Coach's own question about a pending training offer may
            // carry its scoped reach to the System-author floor (OF-577);
            // every other message carries none.
            let permit = coach_offer_question_permit_in_txn(
                self.vault,
                wtxn,
                write_actor,
                plan.conversation_id,
                plan.turn_id,
                planned.id,
                &planned.envelope,
                &policy,
            )?;
            authorized.push(check_witness_message_ceiling_with_permit(
                &self.vault.store,
                wtxn,
                write_actor,
                &planned.envelope,
                &planned.body,
                &policy,
                permit.as_ref(),
            )?);
        }

        // The pre-transaction create-or-get answer is ADVISORY: a concurrent
        // witness can commit this TURN between that resolve and this
        // transaction. Re-reading the row HERE makes the mint-versus-append
        // decision, and the speaker check that rides it,
        // transaction-authoritative, so a same-id race takes the append path
        // instead of overwriting the committed turn.
        let existing_turn = validate_existing_witness_turn(
            dbs,
            wtxn,
            &plan.turn_id,
            &plan.conversation_id,
            plan.speaker,
            person_author,
        )?;
        validate_container_provenance(
            dbs,
            wtxn,
            plan.imported.as_ref().map(|stamp| stamp.source),
            &plan.conversation_id,
            existing_turn.as_ref(),
        )?;
        // Expected present and gone (a concurrent delete). Recreating it here
        // would silently mint the turn the caller asked to append to.
        if existing_turn.is_none() && !plan.turn_is_new {
            return Err(MemoryError::not_found(
                "the witnessed turn no longer exists",
            ));
        }
        let mut message_exists = Vec::with_capacity(plan.messages.len());
        for planned in &plan.messages {
            let attributed =
                plan.imported.is_none() && planned.message.author != WitnessAuthor::System;
            message_exists.push(validate_existing_witness_message(
                dbs,
                wtxn,
                &planned.id,
                &planned.body,
                &plan.turn_id,
                &plan.conversation_id,
                attributed.then_some(self.actor),
            )?);
        }
        let turn = match existing_turn {
            Some(record) => {
                validate_existing_witness_quote(quoted)?;
                let existing_message_ids = plan
                    .messages
                    .iter()
                    .zip(&message_exists)
                    .filter_map(|(planned, exists)| exists.then_some(planned.id))
                    .collect::<HashSet<_>>();
                validate_existing_witness_message_orders(
                    dbs,
                    wtxn,
                    &plan.turn_id,
                    &plan.turn.messages,
                    &existing_message_ids,
                )?;
                AdmittedTurn::Existing(record)
            }
            None if message_exists.iter().any(|exists| *exists) => {
                return Err(MemoryError::bad_request(
                    "an existing witnessed message cannot mint its missing turn",
                ));
            }
            // A minted TURN carries exactly one grouping speaker; an all-system
            // call has none to stamp, and the scanner reads this key to score
            // the turn's role.
            None => match plan.speaker {
                Some(speaker) => {
                    // With no PERSON byline, a writer this transaction verified
                    // as Agent class, so its AGENT_DEF, stamps itself (FIX 7129).
                    let agent = self.actor_class == crate::edge::EdgeActorClass::Agent;
                    let author = person_author.or(agent.then_some(self.actor));
                    let body = match &plan.imported {
                        Some(stamp) => encode_imported_turn_body(speaker, stamp.source)?,
                        None => encode_witness_turn_body(speaker, author, quoted)?,
                    };
                    AdmittedTurn::Mint {
                        body: match thread {
                            Some(binding) => crate::workspace_roster::stamp_thread(&body, binding)?,
                            None => body,
                        },
                    }
                }
                None => {
                    return Err(MemoryError::bad_request(
                        "a new witnessed turn needs one non-system speaker",
                    ));
                }
            },
        };
        Ok(WitnessAdmission {
            turn,
            authorized,
            message_exists,
        })
    }
}
