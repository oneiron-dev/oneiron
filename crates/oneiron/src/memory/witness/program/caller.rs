//! Caller-bound session speech. The caller's credential and the MESSAGE author stay separate.

use super::*;
use crate::memory::support::verify_actor_binding_in_txn;

mod binding;
mod claims;
pub use binding::SessionWitnessBinding;

/// An admitted caller's live session and its captured mode generation.
///
/// Constructed only from the caller's bound [`Memory`]. It is not serializable,
/// and neither an author id nor a session name can construct one. This is a
/// native one-shot witness context, not a code-run or stream capability.
pub struct SessionWitnessContext<'v> {
    caller: Memory<'v>,
    session: OffRecordSession<'v>,
    route: SessionWriteRoute,
    room: Option<EntityId>,
    entered_by: Option<[u8; 16]>,
}

/// A session witness's actual retention, without inventing a durable receipt.
#[derive(Debug)]
pub enum SessionWitnessOutcome {
    /// Session-local rows while off record, ordinary rows while on record.
    Retained(WitnessReceipt),
    /// The anonymous caller's speech was admitted, but no row or receipt exists.
    Unretained,
}

impl<'v> Memory<'v> {
    /// Captures the session this caller's actual credential-bound surface names.
    /// No session binding returns `None`; construction grants no author rights.
    pub fn session_witness_context(&self) -> MemoryResult<Option<SessionWitnessContext<'v>>> {
        let Some((session_ref, Some(principal))) = self.off_record_binding() else {
            return Ok(None);
        };
        if principal != self.actor {
            return Err(caller_refused());
        }
        // Authenticate before looking up the caller's session.
        {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            verify_caller_in_txn(self, &txn)?;
        }
        let session = self
            .vault
            .off_record_session_vault()
            .bind_caller_session(session_ref, principal)?;
        let (route, _) = session.landing_route()?;
        let context = SessionWitnessContext::new(self.clone(), session, route)?;
        {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            context.admit_in_txn(&txn)?;
        }
        Ok(Some(context))
    }
}

impl<'v> SessionWitnessContext<'v> {
    fn new(
        caller: Memory<'v>,
        session: OffRecordSession<'v>,
        route: SessionWriteRoute,
    ) -> MemoryResult<Self> {
        // Session state precedes the base writer. Capture instance metadata
        // here; admission inside the writer never takes that mutex.
        let record = session.record()?;
        if record.closing {
            return Err(caller_refused());
        }
        let room = record.room.map(EntityId::from_bytes).transpose()?;
        route.revalidate()?;
        Ok(Self {
            caller,
            session,
            route,
            room,
            entered_by: record.entered_by,
        })
    }

    /// Whether the captured route retains nothing. Check this before opening
    /// any durable stream, custody, invocation or receipt state for the call.
    pub fn keeps_no_record(&self) -> bool {
        self.route.target() == RouteTarget::Discard
    }

    /// Witnesses `turn` as `author`, not as the caller. The caller's own proof,
    /// room membership and captured route are checked in each owning transaction;
    /// the existing witness program independently admits the author and envelopes.
    /// Anonymous speech checks those inputs on one read snapshot and writes nothing.
    pub fn witness(
        &self,
        author: &Memory<'_>,
        turn: &WitnessTurn,
    ) -> MemoryResult<SessionWitnessOutcome> {
        self.witness_with_terminal(author, turn, None)
    }

    pub(in crate::memory::witness) fn witness_with_terminal(
        &self,
        author: &Memory<'_>,
        turn: &WitnessTurn,
        terminal: Option<&super::super::stream::SessionStreamTerminal>,
    ) -> MemoryResult<SessionWitnessOutcome> {
        if !std::ptr::eq(self.caller.vault, author.vault) {
            return Err(caller_refused());
        }
        let admit = |txn: &heed::RoTxn<'_>| -> MemoryResult<()> {
            self.admit_in_txn(txn)?;
            if let Some(room) = self.room
                && !self.session.is_member_in_txn(txn, room, author.actor)?
            {
                return Err(caller_refused());
            }
            Ok(())
        };
        if self.keeps_no_record() {
            author.admit_witness_request(turn, WitnessDoor::Guest)?;
            if incoming_turn_speaker(&turn.messages)?.is_none() {
                return Err(MemoryError::bad_request(
                    "a new witnessed turn needs one non-system speaker",
                ));
            }
            validate_witness_occurrence(self.caller.vault.now_recorded_at(), turn.occurred_at)?;
            let lane = (!turn.assertions.cited.is_empty() || !turn.assertions.created.is_empty())
                .then(|| author.read_lane(ClaimReadStatus::Recorded))
                .transpose()?;
            let txn = self
                .caller
                .vault
                .store
                .env
                .read_txn()
                .map_err(Error::from)?;
            admit(&txn)?;
            author.verify_actor_write_in_txn(&txn)?;
            if let Some(lane) = &lane
                && unread_assertion_in(lane, &txn, &turn.assertions)?.is_some()
            {
                return Err(MemoryError::bad_request(
                    "a record the reply asserts does not resolve for this writer",
                ));
            }
            let policy = resolve_policy_manifest(&self.caller.vault.store, &txn)?;
            for message in &turn.messages {
                let envelope = witness_message_envelope(message);
                let body = envelope.encode_body()?;
                crate::gate::check_witness_message_ceiling(
                    &self.caller.vault.store,
                    &txn,
                    author.write_actor(),
                    &envelope,
                    &body,
                    &policy,
                )?;
            }
            self.route.revalidate()?;
            return Ok(SessionWitnessOutcome::Unretained);
        }
        let receipt = author.run_witness(
            turn,
            WitnessTarget::Session {
                session: &self.session,
                route: Some(&self.route),
                summary: None,
                admit: Some(&admit),
                rostered: self.room,
                turn_vector: None,
                terminal,
            },
            WitnessDoor::Guest,
            || {},
            |_| Ok(()),
            |_| Ok(()),
        )?;
        Ok(SessionWitnessOutcome::Retained(receipt))
    }

    /// Checks a private native stream without reserving containers or writing a seed.
    pub(in crate::memory::witness) fn admit_stream(
        &self,
        author: &Memory<'_>,
        turn: &WitnessTurn,
    ) -> MemoryResult<()> {
        if !std::ptr::eq(self.caller.vault, author.vault) {
            return Err(caller_refused());
        }
        author.admit_witness_request(turn, WitnessDoor::Guest)?;
        if incoming_turn_speaker(&turn.messages)?.is_none() {
            return Err(MemoryError::bad_request(
                "a new witnessed turn needs one non-system speaker",
            ));
        }
        validate_witness_occurrence(self.caller.vault.now_recorded_at(), turn.occurred_at)?;
        let txn = self
            .caller
            .vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)?;
        self.admit_in_txn(&txn)?;
        if self.room.is_some() && self.route.target() != RouteTarget::Base {
            verify_actor_binding_in_txn(author.vault, &txn, author.actor, author.actor_class)?;
            if author.vault.shared_vault_creation_in_txn(&txn)?.is_some() {
                author
                    .vault
                    .verify_write_actor_in_txn(&txn, &author.write_actor())?;
            }
        } else {
            author.verify_actor_write_in_txn(&txn)?;
        }
        if let Some(room) = self.room
            && !self.session.is_member_in_txn(&txn, room, author.actor)?
        {
            return Err(caller_refused());
        }
        let policy = resolve_policy_manifest(&self.caller.vault.store, &txn)?;
        for message in &turn.messages {
            let envelope = witness_message_envelope(message);
            let body = envelope.encode_body()?;
            crate::gate::check_witness_message_ceiling(
                &self.caller.vault.store,
                &txn,
                author.write_actor(),
                &envelope,
                &body,
                &policy,
            )?;
        }
        self.route.revalidate()?;
        Ok(())
    }

    pub(in crate::memory::witness) fn project_stream_text(
        &self,
        text: &str,
        complete: bool,
    ) -> MemoryResult<String> {
        let txn = self
            .caller
            .vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)?;
        self.admit_in_txn(&txn)?;
        let mut value = serde_json::Value::String(text.to_owned());
        let masked = match (&self.caller.host_action, &self.caller.read_proof) {
            (None, Some(proof)) => {
                let owner = self.caller.is_vault_owner_in_txn(&txn)?;
                self.caller
                    .vault
                    .credential_read_key_in_txn(&txn, proof, self.caller.actor, owner)?
                    .is_none_or(|key| {
                        key.secret_sight() == crate::secret_custody::SecretSight::Masked
                    })
            }
            _ => self.caller.reads_lifted_keys_masked_in_txn(&txn)?,
        };
        if masked {
            let keys = crate::batch::secret_scan::LiftedKeys::of_json_in_txn(
                &self.caller.vault.store,
                &txn,
                &value,
            )?;
            keys.mask_json(&mut value);
        }
        let serde_json::Value::String(text) = value else {
            return Err(
                Error::InvariantViolation("stream projection changed the text type").into(),
            );
        };
        drop(txn);
        let text = text.as_str();
        let projected = if masked {
            match self.caller.vault.known_source()? {
                Some(source) => source.pass(|known| {
                    let Some(known) = known else {
                        return text.to_owned();
                    };
                    let data = text.as_bytes();
                    let mut limit = if complete {
                        data.len()
                    } else {
                        let growing = known.growing(data);
                        growing.opens.unwrap_or(data.len()).min(growing.held)
                    };
                    while !text.is_char_boundary(limit) {
                        limit -= 1;
                    }
                    let mut projected = Vec::new();
                    let mut from = 0;
                    for hit in known.spans(data) {
                        if hit.span.start >= limit {
                            break;
                        }
                        projected.extend_from_slice(&data[from..hit.span.start]);
                        projected.extend_from_slice(
                            crate::store::known_value_index::handle_text(hit.handle).as_bytes(),
                        );
                        from = hit.span.end;
                    }
                    projected.extend_from_slice(&data[from..from.max(limit)]);
                    String::from_utf8_lossy(&projected).into_owned()
                })?,
                None => text.to_owned(),
            }
        } else {
            text.to_owned()
        };
        self.route.revalidate()?;
        Ok(projected)
    }

    pub(in crate::memory::witness) fn stream_terminal_receipt(
        &self,
        candidate: &super::super::stream::MessageStreamReceipt,
    ) -> MemoryResult<Option<super::super::stream::MessageStreamReceipt>> {
        let view = (self.route.target() == RouteTarget::Overlay)
            .then(|| self.session.read_view())
            .transpose()?;
        let txn = self
            .caller
            .vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)?;
        self.admit_in_txn(&txn)?;
        let dbs = match &view {
            Some(view) => crate::side_table::RoutedDbs::Session(view),
            None => crate::side_table::RoutedDbs::Base(self.caller.vault),
        };
        let receipt = super::super::stream::generation_receipt_in(
            &dbs,
            &txn,
            candidate.message_id,
            candidate.generation,
        )?;
        self.route.revalidate()?;
        Ok(receipt)
    }

    fn admit_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        verify_caller_in_txn(&self.caller, txn)?;
        if !self.session.is_open_for_witness() {
            return Err(caller_refused());
        }
        match self.room {
            Some(room) => {
                if !self
                    .session
                    .is_member_in_txn(txn, room, self.caller.actor)?
                {
                    return Err(caller_refused());
                }
            }
            None => match self.session.creator() {
                Some(creator)
                    if creator.actor != self.caller.actor
                        || creator.class != self.caller.actor_class =>
                {
                    return Err(caller_refused());
                }
                Some(_) => {}
                None => match self.entered_by {
                    Some(entered_by) if entered_by != *self.caller.actor.as_bytes() => {
                        return Err(caller_refused());
                    }
                    Some(_) => {}
                    // An anonymous stretch opened without a principal binds nobody.
                    None if self.keeps_no_record() => return Err(caller_refused()),
                    None => self.caller.verify_owner_in_txn(txn)?,
                },
            },
        }
        self.route.revalidate()?;
        Ok(())
    }
}

fn verify_caller_in_txn(caller: &Memory<'_>, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
    verify_actor_binding_in_txn(caller.vault, txn, caller.actor, caller.actor_class)?;
    if let Some(proof) = &caller.read_proof {
        if proof.claims().holder_ref != caller.actor.to_hex()
            || proof.claims().actor_class.as_deref().unwrap_or("human")
                != caller.actor_class.gate_actor_class()
            || !caller.vault.capability_slip_is_live_in_txn(txn, proof)?
        {
            return Err(caller_refused());
        }
    } else if let Some(action) = &caller.host_action {
        action.guard().holds_in(caller.vault, txn)?;
    } else if let Some(owner) = &caller.owner_authorship {
        if owner.revalidate_person_in_txn(caller.vault, txn)? != caller.actor {
            return Err(caller_refused());
        }
    } else if !caller.native_invocation() || caller.credential {
        // A transport's actor label is not its credential. Its native host must
        // bind the verified slip or owner proof, not substitute a credential flag.
        return Err(caller_refused());
    }
    Ok(())
}

fn caller_refused() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "the caller's credential or session binding no longer holds",
        &["Bind the caller's own live credential and session before witnessing."],
    )
}
