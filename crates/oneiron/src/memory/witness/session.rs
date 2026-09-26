//! Session overlay landing: journal staging from the door's authorized values, room-shell claim.

use super::super::support::*;
use super::super::*;
use super::program::{AdmittedTurn, WitnessAdmission, WitnessDoor, WitnessPlan, WitnessTarget};

use std::sync::Arc;

use rmpv::Value;

use crate::batch::BatchOp;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::off_record::{OffRecordSession, OverlayShellReservation};
use crate::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::session_overlay::{
    JournalEntry, JournalRole, JournalScope, SessionOverlay, SessionWriteRoute, TxnSegmentGuard,
};

/// An overlay landing's pre-write state.
pub(super) struct OverlaySink<'a, 'v> {
    session: &'a OffRecordSession<'v>,
    route: &'a SessionWriteRoute,
    overlay: Arc<SessionOverlay>,
    /// The session-only SUMMARY: its id, encoded body and text.
    summary: Option<(EntityId, Vec<u8>, &'a str)>,
    /// The room's one shell-staging claim, when this witness holds it.
    shell: Option<OverlayShellReservation>,
}

impl OverlaySink<'_, '_> {
    /// The composed overlay/base view the create-or-verify checks read.
    pub(super) fn read_view(&self) -> crate::error::Result<crate::store::SessionStoreView<'_>> {
        self.session.read_view()
    }

    /// The shell row is in the room now, so the claim is spent for good.
    pub(super) fn commit_shell(self) {
        if let Some(reservation) = self.shell {
            reservation.commit();
        }
    }
}

impl Memory<'_> {
    // ── write verbs ─────────────────────────────────────────────────────

    /// Witnesses one turn INTO a session (ARCH-0052 §7, ONE-1728).
    ///
    /// The same witness program as [`Self::witness`] with the session as its
    /// target — conversation shell, TURN put, MESSAGE puts with
    /// `PartOf`/`BelongsTo`/`AuthoredBy` edges, BM25 `content` text ops —
    /// plus a session-only SUMMARY put and its `DerivedFrom` edge when
    /// `summary` is `Some`. While the route resolves to `Overlay` every row
    /// stages into the session overlay and evaporates at close; after a flip
    /// to `OnRecord` the same program lands in base under the session's
    /// on-record continuation shell.
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
        session: &OffRecordSession<'_>,
        turn: &WitnessTurn,
        summary: Option<&str>,
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness(
            turn,
            WitnessTarget::Session { session, summary },
            WitnessDoor::Guest,
            || {},
            |_| Ok(()),
        )
    }

    /// Host-bound variant for executor speech. `host_turn_ref` is derived from
    /// the run identity behind a crate-private capability; it is deliberately a
    /// separate parameter from guest [`WitnessTurn::turn_ref`], so preserving a
    /// deterministic retry target cannot weaken the guest `Some(turn_ref)`
    /// refusal on [`crate::off_record::OffRecordSession::witness_executor_turn`].
    pub(crate) fn witness_into_session_with_host_turn(
        &self,
        session: &OffRecordSession<'_>,
        turn: &WitnessTurn,
        summary: Option<&str>,
        host_turn_ref: EntityId,
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness(
            turn,
            WitnessTarget::Session { session, summary },
            WitnessDoor::HostTurn(host_turn_ref),
            || {},
            |_| Ok(()),
        )
    }

    // ── the overlay landing ─────────────────────────────────────────────

    pub(super) fn overlay_sink<'a, 'v>(
        &self,
        session: &'a OffRecordSession<'v>,
        route: &'a SessionWriteRoute,
        summary: Option<&'a str>,
    ) -> MemoryResult<OverlaySink<'a, 'v>> {
        let summary = match summary {
            Some(text) => {
                let id = self.vault.store.clock.entity_id()?;
                let body = encode_rmpv(&Value::Map(vec![(
                    Value::from("content"),
                    Value::from(text),
                )]))?;
                Some((id, body, text))
            }
            None => None,
        };
        // The room's one shell-staging claim is taken HERE — after every
        // fallible step of the plan (caller-controlled message ids and bodies)
        // and released if the transaction fails. Taking it earlier burned it
        // on a witness that never staged the shell row, leaving later witnesses
        // to hang `PartOf`/`BelongsTo` edges off a conversation id with no
        // entity row.
        let shell = session.reserve_overlay_conversation_shell()?;
        Ok(OverlaySink {
            session,
            route,
            overlay: session.overlay(),
            summary,
            shell,
        })
    }

    /// Stages the admitted turn into the room's journal and allocates its
    /// session-local aliases. Rows apply only when the returned segment
    /// commits, after the base transaction.
    pub(super) fn stage_in_overlay(
        &self,
        plan: &WitnessPlan<'_>,
        admission: &WitnessAdmission<'_>,
        sink: &OverlaySink<'_, '_>,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> MemoryResult<(TxnSegmentGuard, Vec<(String, u8)>)> {
        let scope = JournalScope::new(plan.conversation_id, plan.turn_id);
        let entry = |role: JournalRole, op: BatchOp| JournalEntry {
            scope,
            role,
            learned_at: plan.learned_at,
            occurred: plan.occurred,
            op,
        };
        let put = |id: &EntityId, entity_type: u8, data: &[u8]| BatchOp::Put {
            id: *id,
            entity_type,
            occurred: plan.occurred,
            learned_at: plan.learned_at,
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
        let text = |id: EntityId, content: &str| BatchOp::Text {
            id,
            fields: vec![("content".to_owned(), content.to_owned())],
        };

        let mut entries = Vec::new();
        // The shell `Put` leads the journal, so promote replays the shell
        // before anything referring to it.
        if sink.shell.is_some() {
            entries.push(entry(
                JournalRole::ConversationShell,
                put(
                    &plan.conversation_id,
                    ENTITY_TYPE_CONVERSATION,
                    &plan.conversation_body,
                ),
            ));
        }
        // A verified existing TURN keeps its original Put/ChildOf entries as
        // its single authoritative mint; new messages append to it.
        if let AdmittedTurn::Mint { body } = &admission.turn {
            entries.push(entry(
                JournalRole::TurnPut,
                put(&plan.turn_id, ENTITY_TYPE_TURN, body),
            ));
            // The structural TURN -> room-shell `ChildOf` edge rides as a
            // turn-owned artifact: promote's closure predicate selects every
            // `TurnOwnedArtifact` whose scope names THIS turn and the generic
            // `Edge` arm of `promotion_replay_op` replays it into base, so the
            // promoted TURN carries the one reader-side conversation answer
            // consolidation groups by.
            entries.push(entry(
                JournalRole::TurnOwnedArtifact,
                edge(&plan.turn_id, EdgeKind::ChildOf, &plan.conversation_id),
            ));
        }
        for ((planned, authorized), exists) in plan
            .messages
            .iter()
            .zip(&admission.authorized)
            .zip(&admission.message_exists)
        {
            // Exact retries do not restage rows or duplicate journal scope.
            if *exists {
                continue;
            }
            // The staged MESSAGE is the door's own value: the journal entry a
            // promote replays carries a copy of exactly the bytes it proved.
            entries.push(entry(
                JournalRole::MessagePartOf,
                put(&planned.id, ENTITY_TYPE_MESSAGE, authorized.body()),
            ));
            entries.push(entry(
                JournalRole::MessagePartOf,
                edge(&planned.id, EdgeKind::PartOf, &plan.turn_id),
            ));
            entries.push(entry(
                JournalRole::AttributionEdge,
                edge(&planned.id, EdgeKind::BelongsTo, &plan.conversation_id),
            ));
            if planned.message.author != WitnessAuthor::System {
                entries.push(entry(
                    JournalRole::AttributionEdge,
                    edge(&planned.id, EdgeKind::AuthoredBy, &self.actor),
                ));
            }
            if !planned.message.content.is_empty() {
                entries.push(entry(
                    JournalRole::TurnOwnedArtifact,
                    text(planned.id, &planned.message.content),
                ));
            }
        }
        if let Some((id, body, content)) = &sink.summary {
            entries.push(entry(
                JournalRole::SummaryDerivedFrom,
                put(id, ENTITY_TYPE_SUMMARY, body),
            ));
            entries.push(entry(
                JournalRole::SummaryDerivedFrom,
                edge(id, EdgeKind::DerivedFrom, &plan.turn_id),
            ));
            if !content.is_empty() {
                entries.push(entry(JournalRole::TurnOwnedArtifact, text(*id, content)));
            }
        }

        // The segment permit is taken INSIDE the base writer (R3 lock order:
        // base writer, then segment permit, on every session write path).
        let segment = sink.overlay.install_txn_segment()?;
        // ONE ENTRY PER CALL, each against a FRESHLY constructed view.
        //
        // A `SessionStoreView` freezes its overlay snapshot at construction,
        // so a view built once and reused across the whole program cannot see
        // rows staged earlier in the same program. That is invisible for
        // independent row writes but corrupts every READ-MODIFY-WRITE
        // accumulator: two BM25 documents in one turn (a message and its
        // summary) would both read the pre-turn `total_docs`, both write
        // `before + 1`, and leave 2 postings under a doc count of 1 — which
        // the next in-room search fails closed on with `posting list length
        // exceeds total_docs`.
        //
        // `read_view` is segment-aware (`SessionOverlay::snapshot` returns the
        // active segment's preview), so re-taking it per entry gives each op
        // read-your-own-writes over its predecessors. Atomicity is untouched:
        // this is all still one base txn and one overlay segment.
        for entry in entries {
            crate::batch::apply_ops_session(
                &sink.session.read_view()?,
                sink.route,
                &self.vault.config,
                &self.vault.analyzer,
                wtxn,
                vec![entry],
            )?;
        }
        let alias_ids = std::iter::once(plan.turn_id)
            .chain(plan.messages.iter().map(|planned| planned.id))
            .chain(sink.summary.as_ref().map(|(id, _, _)| *id));
        let mut aliases = Vec::new();
        for id in alias_ids {
            aliases.push(sink.overlay.alloc_session_short_id(&id, id.as_bytes())?);
        }
        Ok((segment, aliases))
    }
}
