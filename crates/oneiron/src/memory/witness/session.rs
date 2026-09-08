//! Off-record session witness route: overlay journal staging, shell reservation, post-flip base arm.

use super::super::support::*;
use super::super::*;
use super::codec::{encode_witness_turn_body, incoming_turn_speaker, session_short_ref_string};
use super::validation::{
    validate_existing_witness_message, validate_existing_witness_message_orders,
    validate_existing_witness_turn,
};
use super::{distinct_message_orders, witness_message_envelope};

use std::collections::HashSet;

use rmpv::Value;

use crate::batch::BatchOp;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{check_witness_message_ceiling, resolve_policy_manifest};
use crate::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::session_overlay::{JournalEntry, JournalRole, JournalScope, RouteTarget};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

impl Memory<'_> {
    // ── write verbs ─────────────────────────────────────────────────────

    /// Witnesses one turn INTO a session (ARCH-0052 §7, ONE-1728).
    ///
    /// Runs the base witness program — conversation shell, TURN put, MESSAGE
    /// puts with `PartOf`/`BelongsTo`/`AuthoredBy` edges, BM25 `content` text
    /// ops — plus a session-only SUMMARY put and its `DerivedFrom` edge when
    /// `summary` is `Some`. While the route resolves to `Overlay` every row
    /// stages into the session overlay and evaporates at close; after a flip
    /// to `OnRecord` the same program runs through the ordinary base apply
    /// under the session's on-record continuation shell.
    ///
    /// The staged MESSAGE puts run the base door's ONE-1686 approval-ceiling
    /// contract, for the same reason the mint contract binds here: promote
    /// replays this journal into base verbatim, so an envelope the base
    /// boundary would refuse must be refused at staging rather than admitted
    /// into a room that can later publish it.
    ///
    /// The staged TURN mint runs the base door's ONE-1767 contract, because
    /// promote replays this journal into base verbatim: the call must carry
    /// exactly one non-system speaker (mixed non-system and all-system calls
    /// are the same bad request the base door raises), the TURN body is the
    /// additive `speaker` entry, and the TURN -> room-shell `ChildOf` edge is
    /// journaled as a turn-owned artifact so the promoted turn groups and
    /// roles exactly like a base-witnessed one.
    ///
    /// The receipt carries SESSION-LOCAL short ids: in-room aliases are
    /// temporary presentation handles, and canonical ids are allocated at
    /// promote (ONE-1730).
    ///
    /// # Why the summary is session-only
    ///
    /// A summary of an off-record turn is derived FROM content that does not
    /// exist in base. Materializing it through the base door would publish the
    /// substance of the room while the room still claims to be private — the
    /// exact leak the vault exists to prevent. It rides the overlay with the
    /// turn it summarizes and promotes with it or not at all.
    pub fn witness_into_session(
        &self,
        session: &crate::off_record::OffRecordSession<'_>,
        turn: &WitnessTurn,
        summary: Option<&str>,
    ) -> MemoryResult<WitnessReceipt> {
        self.witness_into_session_routed(session, turn, summary, None)
    }

    /// Host-bound variant for executor speech. `host_turn_ref` is derived from
    /// the run identity behind a crate-private capability; it is deliberately a
    /// separate parameter from guest [`WitnessTurn::turn_ref`], so preserving a
    /// deterministic retry target cannot weaken the guest `Some(turn_ref)`
    /// refusal on [`crate::off_record::OffRecordSession::witness_executor_turn`].
    pub(crate) fn witness_into_session_with_host_turn(
        &self,
        session: &crate::off_record::OffRecordSession<'_>,
        turn: &WitnessTurn,
        summary: Option<&str>,
        host_turn_ref: EntityId,
    ) -> MemoryResult<WitnessReceipt> {
        self.witness_into_session_routed(session, turn, summary, Some(host_turn_ref))
    }

    fn witness_into_session_routed(
        &self,
        session: &crate::off_record::OffRecordSession<'_>,
        turn: &WitnessTurn,
        summary: Option<&str>,
        host_turn_ref: Option<EntityId>,
    ) -> MemoryResult<WitnessReceipt> {
        if turn.messages.is_empty() {
            return Err(MemoryError::bad_request("witness turn carries no messages"));
        }
        if host_turn_ref.is_some() && turn.turn_ref.is_some() {
            return Err(Error::InvariantViolation(
                "host-bound session witness also carried a guest turn ref",
            )
            .into());
        }
        distinct_message_orders(&turn.messages)?;
        let route = session.write_route()?;
        if route.target() == RouteTarget::Base {
            // Post-flip: the room is on record, so the witness takes the
            // ordinary base apply under the continuation shell. It never
            // reuses the overlay conversation id, so K4 sees no overlay refs
            // and K7 does not fire (the shell is not an overlay member).
            //
            // The route rides INTO the base transaction: the overlay arms
            // revalidate before they commit, and a base-routed turn is the
            // half that publishes durably, so it is the half that most needs
            // the same refusal.
            let continuation = session.on_record_continuation_shell()?;
            let mut base_turn = turn.clone();
            base_turn.conversation_ref = continuation.to_hex();
            if let Some(host_turn_ref) = host_turn_ref {
                base_turn.turn_ref = Some(host_turn_ref.to_hex());
            }
            return self.witness_with_route(&base_turn, Some(&route));
        }

        let occurred = TimeRange {
            start: turn.occurred_at,
            end: turn.occurred_at,
        };
        let learned_at = turn.occurred_at;
        let overlay = session.overlay();
        let conversation_id = session.overlay_conversation_shell()?;
        let turn_id = host_turn_ref.unwrap_or_else(EntityId::now);
        let container_body = encode_rmpv(&Value::Map(Vec::new()))?;

        // ONE-1767's mint contract binds this door exactly as it binds the
        // base one. Ordinary session witnesses mint a fresh TURN; the separate
        // host-bound executor path may name a deterministic TURN and then
        // create-or-verify it on retry. Either way the first mint carries one
        // non-system speaker plus its `ChildOf` edge, and the verification arm
        // below refuses a different speaker or conversation before staging.
        // Those are the exact facts promote (ONE-1730) replays into base.
        let Some(turn_speaker) = incoming_turn_speaker(&turn.messages)? else {
            return Err(MemoryError::bad_request(
                "a new witnessed turn needs one non-system speaker",
            ));
        };
        let turn_body = encode_witness_turn_body(turn_speaker)?;

        let mut entries = Vec::new();
        let scope = JournalScope::new(conversation_id, turn_id);
        // Every entry carries the witness's own `occurred`/`learned_at` — never
        // `unix_seconds_now()` — because promote replays these stamps and a
        // restamped row would land in the wrong month window (ARCH-0052 D4).
        let entry = |role: JournalRole, op: BatchOp| JournalEntry {
            scope,
            role,
            learned_at,
            occurred,
            op,
        };
        let put = |id: &EntityId, entity_type: u8, data: &[u8]| BatchOp::Put {
            id: *id,
            entity_type,
            occurred,
            learned_at,
            data: data.to_vec(),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        };
        let edge = |src: &EntityId, kind: EdgeKind, tgt: &EntityId| BatchOp::Edge {
            src: *src,
            kind,
            tgt: *tgt,
            weight: 1.0,
            vad: crate::affect::Vad::NEUTRAL,
        };

        entries.push(entry(
            JournalRole::TurnPut,
            put(&turn_id, ENTITY_TYPE_TURN, &turn_body),
        ));
        // The structural TURN -> room-shell `ChildOf` edge rides as a
        // turn-owned artifact: promote's closure predicate selects every
        // `TurnOwnedArtifact` whose scope names THIS turn and the generic
        // `Edge` arm of `promotion_replay_op` replays it into base, so the
        // promoted TURN carries the one reader-side conversation answer
        // consolidation groups by.
        entries.push(entry(
            JournalRole::TurnOwnedArtifact,
            edge(&turn_id, EdgeKind::ChildOf, &conversation_id),
        ));

        let mut message_ids = Vec::with_capacity(turn.messages.len());
        // The staged envelopes and their canonical bodies, kept for the ceiling
        // door below: the journal entry a promote replays carries a COPY of
        // `body`, so authorizing this vector authorizes exactly what lands.
        let mut staged = Vec::with_capacity(turn.messages.len());
        for message in &turn.messages {
            let id = id_from_optional_hex(message.id.as_deref())?;
            let envelope = witness_message_envelope(message);
            let body = envelope.encode_body()?;
            message_ids.push(id);
            entries.push(entry(
                JournalRole::MessagePartOf,
                put(&id, ENTITY_TYPE_MESSAGE, &body),
            ));
            entries.push(entry(
                JournalRole::MessagePartOf,
                edge(&id, EdgeKind::PartOf, &turn_id),
            ));
            entries.push(entry(
                JournalRole::AttributionEdge,
                edge(&id, EdgeKind::BelongsTo, &conversation_id),
            ));
            if message.author != WitnessAuthor::System {
                entries.push(entry(
                    JournalRole::AttributionEdge,
                    edge(&id, EdgeKind::AuthoredBy, &self.actor),
                ));
            }
            if !message.content.is_empty() {
                entries.push(entry(
                    JournalRole::TurnOwnedArtifact,
                    BatchOp::Text {
                        id,
                        fields: vec![("content".to_owned(), message.content.clone())],
                    },
                ));
            }
            staged.push((envelope, body));
        }

        let summary_id = match summary {
            Some(text) => {
                let id = EntityId::now();
                let body = encode_rmpv(&Value::Map(vec![(
                    Value::from("content"),
                    Value::from(text),
                )]))?;
                entries.push(entry(
                    JournalRole::SummaryDerivedFrom,
                    put(&id, ENTITY_TYPE_SUMMARY, &body),
                ));
                entries.push(entry(
                    JournalRole::SummaryDerivedFrom,
                    edge(&id, EdgeKind::DerivedFrom, &turn_id),
                ));
                if !text.is_empty() {
                    entries.push(entry(
                        JournalRole::TurnOwnedArtifact,
                        BatchOp::Text {
                            id,
                            fields: vec![("content".to_owned(), text.to_owned())],
                        },
                    ));
                }
                Some(id)
            }
            None => None,
        };

        // The room's one shell-staging claim is taken HERE — after every
        // fallible step above (caller-controlled message ids and bodies) and
        // released if the transaction below fails. Taking it earlier burned it
        // on a witness that never staged the shell row, leaving later witnesses
        // to hang `PartOf`/`BelongsTo` edges off a conversation id with no
        // entity row. The shell `Put` leads the journal, so promote replays the
        // shell before anything referring to it.
        let shell_reservation = session.reserve_overlay_conversation_shell()?;
        if shell_reservation.is_some() {
            entries.insert(
                0,
                entry(
                    JournalRole::ConversationShell,
                    put(&conversation_id, ENTITY_TYPE_CONVERSATION, &container_body),
                ),
            );
        }

        // The overlay segment and the base txn commit together: the segment
        // guard applies staged rows only after `wtxn.commit()` returns, so a
        // failure anywhere in staging leaves the room byte-unchanged.
        let alias_ids: Vec<EntityId> = std::iter::once(turn_id)
            .chain(message_ids.iter().copied())
            .chain(summary_id)
            .collect();
        let (segment, short_refs) = self.vault.try_with_write_txn(
            |wtxn| -> MemoryResult<(crate::session_overlay::TxnSegmentGuard, Vec<(String, u8)>)> {
                verify_actor_binding_in_txn(self.vault, &*wtxn, self.actor, self.actor_class)?;
                // ONE-1686 (RT-04): the SAME approval-ceiling door the base
                // witness runs, on the same envelopes, before ANY row stages.
                // The room is not a weaker door: a promote replays this journal
                // into base verbatim, so an envelope this door would refuse at
                // the base boundary must be refused here too — and refused
                // BEFORE the overlay segment installs, so the room stays
                // byte-unchanged.
                let policy = resolve_policy_manifest(&self.vault.store, &*wtxn)?;
                let write_actor = WriteActor::new(self.actor, self.actor_class);
                for (envelope, body) in &staged {
                    check_witness_message_ceiling(
                        &self.vault.store,
                        &*wtxn,
                        write_actor,
                        envelope,
                        body,
                        &policy,
                    )?;
                }

                // Host-derived ids are create-or-verify in the COMPOSED
                // overlay/base snapshot. This runs before the segment exists,
                // so a divergent body or parent leaves no journal/index delta.
                let view = session.read_view()?;
                let turn_already_exists = validate_existing_witness_turn(
                    &view,
                    &*wtxn,
                    &turn_id,
                    &conversation_id,
                    Some(turn_speaker),
                )?;
                let mut existing_messages = HashSet::new();
                for ((message, id), (_, body)) in
                    turn.messages.iter().zip(&message_ids).zip(&staged)
                {
                    if validate_existing_witness_message(
                        &view,
                        &*wtxn,
                        id,
                        body,
                        &turn_id,
                        &conversation_id,
                        message.author,
                        &self.actor,
                    )? {
                        existing_messages.insert(*id);
                    }
                }
                if turn_already_exists {
                    validate_existing_witness_message_orders(
                        &view,
                        &*wtxn,
                        &turn_id,
                        &turn.messages,
                        &existing_messages,
                    )?;
                }
                drop(view);
                if !turn_already_exists && !existing_messages.is_empty() {
                    return Err(MemoryError::bad_request(
                        "an existing witnessed message cannot mint its missing turn",
                    ));
                }

                // Exact retries do not restage rows or duplicate journal scope.
                // New messages may append to the verified deterministic turn;
                // the turn's original Put/ChildOf journal entries remain its
                // single authoritative mint.
                entries.retain(|entry| match &entry.op {
                    BatchOp::Put {
                        id, entity_type, ..
                    } if turn_already_exists
                        && *id == turn_id
                        && *entity_type == ENTITY_TYPE_TURN =>
                    {
                        false
                    }
                    BatchOp::Edge { src, kind, .. }
                        if turn_already_exists && *src == turn_id && *kind == EdgeKind::ChildOf =>
                    {
                        false
                    }
                    BatchOp::Put {
                        id, entity_type, ..
                    } if existing_messages.contains(id) && *entity_type == ENTITY_TYPE_MESSAGE => {
                        false
                    }
                    BatchOp::Edge { src, kind, .. }
                        if existing_messages.contains(src)
                            && matches!(
                                kind,
                                EdgeKind::PartOf | EdgeKind::BelongsTo | EdgeKind::AuthoredBy
                            ) =>
                    {
                        false
                    }
                    BatchOp::Text { id, .. } if existing_messages.contains(id) => false,
                    _ => true,
                });

                let segment = overlay.install_txn_segment()?;
                // ONE ENTRY PER CALL, each against a FRESHLY constructed view.
                //
                // A `SessionStoreView` freezes its overlay snapshot at
                // construction, so a view built once and reused across the
                // whole program cannot see rows staged earlier in the same
                // program. That is invisible for independent row writes but
                // corrupts every READ-MODIFY-WRITE accumulator: two BM25
                // documents in one turn (a message and its summary) would
                // both read the pre-turn `total_docs`, both write
                // `before + 1`, and leave 2 postings under a doc count of 1 —
                // which the next in-room search fails closed on with
                // `posting list length exceeds total_docs`.
                //
                // `read_view` is segment-aware (`SessionOverlay::snapshot`
                // returns the active segment's preview), so re-taking it per
                // entry gives each op read-your-own-writes over its
                // predecessors. Atomicity is untouched: this is all still one
                // base txn and one overlay segment, committed once below.
                for entry in entries {
                    crate::batch::apply_ops_session(
                        &session.read_view()?,
                        &route,
                        &self.vault.config,
                        &self.vault.analyzer,
                        wtxn,
                        vec![entry],
                    )?;
                }
                let mut short_refs = Vec::with_capacity(alias_ids.len());
                for id in &alias_ids {
                    short_refs.push(overlay.alloc_session_short_id(id, id.as_bytes())?);
                }
                Ok((segment, short_refs))
            },
        )?;
        segment.commit()?;
        // The shell row is in the room now, so the claim is spent for good.
        if let Some(reservation) = shell_reservation {
            reservation.commit();
        }

        let mut short_refs = short_refs.into_iter();
        let turn_short_id = session_short_ref_string(&short_refs.next().ok_or(
            Error::InvariantViolation("session witness allocated no turn alias"),
        )?);
        let message_short_ids = short_refs
            .by_ref()
            .take(message_ids.len())
            .map(|alias| session_short_ref_string(&alias))
            .collect();
        Ok(WitnessReceipt {
            turn_short_id,
            message_short_ids,
            receipt_ref: format!("witness:{}", turn_id.to_hex()),
        })
    }
}
