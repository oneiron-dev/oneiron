//! The witness program's request: its shape and origin, the landing its target resolves to,
//! and the prose links read before its writer opens.

use super::*;

/// Where a witness target lands, and the session state that rides its write.
pub(super) struct ResolvedLanding<'a, 'v> {
    pub(super) landing: Landing<'a, 'v>,
    pub(super) on_record_session: Option<&'a OffRecordSession<'v>>,
    /// An on-record stretch's saver, checked again where the turn lands.
    pub(super) saver: Option<crate::off_record::SaverCheck<'a, 'v>>,
    pub(super) admit: Option<Admit<'a>>,
    pub(super) room_speech: Option<(&'a OffRecordSession<'v>, EntityId)>,
}

/// Resolves the target to its landing; a session target's write route is
/// kept in `session_route`, which the landing borrows.
pub(super) fn resolve_witness_landing<'a, 'v>(
    turn: &WitnessTurn,
    target: WitnessTarget<'a, 'v>,
    session_route: &'a mut Option<SessionWriteRoute>,
) -> MemoryResult<ResolvedLanding<'a, 'v>> {
    let mut on_record_session = None;
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
            let (route, session_saver) = session.landing_route()?;
            saver = session_saver;
            let session_route: &'a SessionWriteRoute = session_route.insert(route);
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
                    route: Some(session_route),
                    continuation: Some(session.on_record_continuation_shell()?),
                    imported: None,
                    held: None,
                }
            } else {
                room_speech = rostered.map(|room| (session, room));
                Landing::Overlay {
                    session,
                    route: session_route,
                    summary,
                }
            }
        }
    };
    Ok(ResolvedLanding {
        landing,
        on_record_session,
        saver,
        admit,
        room_speech,
    })
}

impl Memory<'_> {
    /// The turn's shape and origin: messages present and distinctly ordered,
    /// no guest turn ref on a host-bound session, and generated code speaking
    /// only as the companion.
    pub(super) fn admit_witness_request(
        &self,
        turn: &WitnessTurn,
        door: WitnessDoor,
    ) -> MemoryResult<()> {
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
        Ok(())
    }

    /// OF-063 prose links (Engine ruling 10-17): every AI-written message
    /// this program lands, whatever door it came through, is read for
    /// links its writer cannot resolve, receipt-only and before the writer
    /// opens; the receipt is written only once the turn has landed (Engine
    /// ruling 10-18: landed speech only). An overlay landing is a
    /// non-anonymous off-record session (an anonymous one is refused
    /// when its landing resolves), so its room speech keeps its receipt;
    /// only an anonymous session keeps none. An imported turn is a
    /// source's words, not this writer's.
    pub(super) fn witness_unlinked_prose(
        &self,
        turn: &WitnessTurn,
        landing: &Landing<'_, '_>,
    ) -> Vec<crate::receipt::ReferenceRefusalFacts> {
        if matches!(
            landing,
            Landing::Base {
                imported: Some(_),
                ..
            }
        ) {
            Vec::new()
        } else {
            crate::gate::record_references::witness_prose_unlinked(self, turn)
        }
    }
}
