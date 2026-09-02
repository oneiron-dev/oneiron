//! Witness/turn-ingestion verbs: conversation/turn/message witnessing,
//! off-record session routing, and the turn-speaker wire helpers.
//! Split from the flat `facade.rs`; surface re-exported by [`super`].

use super::structural::*;
use super::support::*;
use super::*;

use std::sync::atomic::Ordering;

use rmpv::{Value, ValueRef};
use serde::{Deserialize, Serialize};

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::session_overlay::{
    JournalEntry, JournalRole, JournalScope, RouteTarget, SessionWriteRoute,
};
use crate::temporal::TimeRange;

/// Who authored one witnessed message (facade vocabulary; the MESSAGE body
/// `author` key stores the snake_case string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessAuthor {
    /// The vault owner.
    User,
    /// The companion persona.
    Companion,
    /// System/tooling rows; these get NO `AuthoredBy` edge (design §2.1).
    System,
}

impl WitnessAuthor {
    /// Stable string form (`user`/`companion`/`system`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Companion => "companion",
            Self::System => "system",
        }
    }

    /// Parses the stable string form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "companion" => Some(Self::Companion),
            "system" => Some(Self::System),
            _ => None,
        }
    }
}

/// One message inside a witnessed turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessMessage {
    /// Caller-supplied deterministic 32-hex entity id; `None` ⇒ generated.
    pub id: Option<String>,
    /// Author bucket; `System` rows get no `AuthoredBy` edge.
    pub author: WitnessAuthor,
    /// Message type string (closed set app-side, opaque here).
    pub message_type: String,
    /// Text content; BM25-indexed under the `content` field when non-empty.
    pub content: String,
    /// Opaque metadata, passed through as MessagePack.
    pub metadata: Option<serde_json::Value>,
    /// Visibility flag (default true app-side).
    pub is_visible: bool,
    /// Position of the message within its turn.
    pub order: u32,
}

/// One conversational turn to witness: create-or-get CONVERSATION/TURN plus
/// gated MESSAGE puts, edges, and text indexing in ONE batch (B2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessTurn {
    /// CONVERSATION ref: short-id ref or 32-hex id (create-or-get for hex).
    pub conversation_ref: String,
    /// TURN ref (create-or-get for hex); `None` ⇒ a fresh TURN is created.
    pub turn_ref: Option<String>,
    /// Messages, all attributed to the bound actor unless `System`.
    ///
    /// A TURN is the maximal consecutive run of ONE speaker, so every
    /// non-system message in one call must share an author; `System` rows
    /// interleave freely. Consecutive runs of different speakers are
    /// witnessed as different turns, never as one `turn_ref` re-witnessed
    /// under another author.
    pub messages: Vec<WitnessMessage>,
    /// Unix seconds; used for both `occurred` and `learned_at` so
    /// migration backfill stays deterministic.
    pub occurred_at: u64,
}

/// Receipt for one witnessed turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessReceipt {
    /// Short-id ref of the TURN (hex fallback if no short id exists).
    pub turn_short_id: String,
    /// Short-id refs of the written MESSAGE entities, input order.
    pub message_short_ids: Vec<String>,
    /// Facade write ref (`witness:<turn-hex>`). Structural puts produce no
    /// gate decision at base, so this is a write marker, not a
    /// `receipts()`-resolvable gate ref.
    pub receipt_ref: String,
}

impl Memory<'_> {
    // ── write verbs ─────────────────────────────────────────────────────

    /// Witnesses one turn: create-or-get CONVERSATION/TURN, MESSAGE puts,
    /// `PartOf`/`BelongsTo`/`AuthoredBy` edges, and BM25 `content`
    /// indexing — all in ONE atomic batch.
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
    pub(super) fn witness_with_route(
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
    pub(super) fn witness_with_route_and_before_txn(
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

        let conversation_body = encode_rmpv(&Value::Map(Vec::new()))?;
        let mut message_ids = Vec::with_capacity(turn.messages.len());
        let mut bodies = Vec::with_capacity(turn.messages.len());
        for message in &turn.messages {
            message_ids.push(id_from_optional_hex(message.id.as_deref())?);
            bodies.push(encode_witness_message_body(message)?);
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
        let text_ops: Vec<BatchOp> = turn
            .messages
            .iter()
            .zip(&message_ids)
            .filter(|(message, _)| !message.content.is_empty())
            .map(|(message, id)| BatchOp::Text {
                id: *id,
                fields: vec![("content".to_owned(), message.content.clone())],
            })
            .collect();
        let text_index_trusted = if text_ops.is_empty() {
            self.vault.text_index_trusted.load(Ordering::Acquire)
        } else {
            self.vault.ensure_text_index_trusted()?;
            true
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
                    let stored_body = &raw[ENTITY_METADATA_HEADER_LEN..];
                    let stored_speaker = decode_witness_turn_speaker(stored_body)?;
                    if incoming_speaker.is_some_and(|incoming| incoming != stored_speaker) {
                        return Err(MemoryError::bad_request(
                            "the witnessed turn already belongs to another speaker",
                        ));
                    }
                    // The TURN's stored `ChildOf` edge — never the
                    // caller-passed conversation ref — names the conversation
                    // an append lands in: the mint arm makes that edge the
                    // ONLY reader-side answer to "which conversation is this
                    // turn in", so writing MESSAGE `BelongsTo` under any
                    // other id would commit mutually inconsistent
                    // authoritative graph facts in ONE transaction. Rejecting
                    // HERE precedes every MESSAGE put, edge, text op, TURN
                    // re-put, and the session-activity bump below, so the
                    // whole call rolls back. A stamped TURN mints its
                    // `ChildOf` by construction; a missing or divergent one
                    // fails closed under the same no-grandfather posture as
                    // the speaker decode.
                    let stored_conversation = {
                        let prefix = crate::vault::edge_kind_prefix(&turn_id, EdgeKind::ChildOf);
                        let mut edges = self.vault.store.edges_out.prefix_iter(&*wtxn, &prefix)?;
                        match edges.next() {
                            Some(row) => {
                                let (key, _) = row?;
                                let (_, _, target) =
                                    crate::edge::parse_strict_edge_record_key(&key)?;
                                Some(target)
                            }
                            None => None,
                        }
                    };
                    if stored_conversation != Some(conversation_id) {
                        return Err(MemoryError::bad_request(
                            "the witnessed turn already belongs to another conversation",
                        ));
                    }
                    // Re-put the row unchanged EXCEPT for a strictly newer
                    // `learned_at`: an append landing after consolidation
                    // watched this turn go by must re-dirty it. `max` over
                    // `old + 1` keeps that true for same-second and
                    // backdated appends, which would otherwise rewrite an
                    // equal (or older) stamp and stay invisible.
                    let redirtied_at = turn.occurred_at.max(header.learned_at.saturating_add(1));
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
            for (message, (id, body)) in turn.messages.iter().zip(message_ids.iter().zip(&bodies)) {
                batch = batch
                    .put(id, ENTITY_TYPE_MESSAGE, occurred, learned_at, body)
                    .edge(id, EdgeKind::PartOf, &turn_id, 1.0)
                    .edge(id, EdgeKind::BelongsTo, &conversation_id, 1.0);
                if message.author != WitnessAuthor::System {
                    batch = batch.edge(id, EdgeKind::AuthoredBy, &self.actor, 1.0);
                }
            }
            batch.apply(wtxn)?;
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
        if turn.messages.is_empty() {
            return Err(MemoryError::bad_request("witness turn carries no messages"));
        }
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
            return self.witness_with_route(&base_turn, Some(&route));
        }

        let occurred = TimeRange {
            start: turn.occurred_at,
            end: turn.occurred_at,
        };
        let learned_at = turn.occurred_at;
        let overlay = session.overlay();
        let conversation_id = session.overlay_conversation_shell()?;
        let turn_id = EntityId::now();
        let container_body = encode_rmpv(&Value::Map(Vec::new()))?;

        // ONE-1767's mint contract binds this door exactly as it binds the
        // base one: every overlay witness mints a FRESH TURN (the
        // `EntityId::now()` above — there is no overlay append arm), so the
        // call must carry exactly one non-system speaker to stamp. The staged
        // TURN body and `ChildOf` edge below are what a promote (ONE-1730)
        // replays into base verbatim, so a skipped stamp here is the durable
        // no-speaker/no-conversation defect again on the promote path. The
        // bad-request codes and copies are the base door's own.
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
        for message in &turn.messages {
            let id = id_from_optional_hex(message.id.as_deref())?;
            let body = encode_witness_message_body(message)?;
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

/// Renders a session-local alias in the same `short_id:content_hash` shape the
/// base resolver produces, so a client formats one kind of ref.
///
/// The alias itself is what keeps the namespaces apart: session ids carry the
/// `s` sigil, which is not a legal base prefix, so an in-room ref can neither
/// shadow a durable entity nor resolve at a base door.
fn session_short_ref_string((short_id, content_hash): &(String, u8)) -> String {
    format!("{short_id}:{content_hash:02x}")
}

/// The one additive TURN-body key the witness door stamps. A turn's speaker
/// is a turn-level grouping fact, not a per-message one: the content stays
/// on the MESSAGE children.
const WITNESS_TURN_SPEAKER_KEY: &str = "speaker";

/// The canonical TURN speaker string for one author bucket; `None` for the
/// `System` bucket, which is interleave and never a grouping speaker.
///
/// These are the ROLE strings the consolidation scanner reads
/// (`dreamer_turn_role`), not the MESSAGE-body `author` vocabulary: a turn
/// stamped `companion` would score `Unknown` and never reach extraction.
const fn canonical_turn_speaker(author: WitnessAuthor) -> Option<&'static str> {
    match author {
        WitnessAuthor::User => Some("user"),
        WitnessAuthor::Companion => Some("assistant"),
        WitnessAuthor::System => None,
    }
}

/// The call's unique non-system speaker.
///
/// `None` means this call contains only permitted system/tooling/REPL
/// interleave. More than one distinct non-system speaker is a bad request:
/// a TURN is the maximal consecutive run of ONE speaker.
fn incoming_turn_speaker(messages: &[WitnessMessage]) -> MemoryResult<Option<&'static str>> {
    let mut speaker: Option<&'static str> = None;
    for message in messages {
        let Some(candidate) = canonical_turn_speaker(message.author) else {
            continue;
        };
        match speaker {
            Some(existing) if existing != candidate => {
                return Err(MemoryError::bad_request_with(
                    "a witnessed turn carries one non-system speaker",
                    &["Witness each speaker's consecutive run as its own turn."],
                ));
            }
            _ => speaker = Some(candidate),
        }
    }
    Ok(speaker)
}

/// Strict writer-side TURN-speaker decoder: the body must carry exactly one
/// `speaker` entry holding a non-empty string.
///
/// It deliberately does not inspect MESSAGE children, follow `AuthoredBy`,
/// read the scanner's `spkr` alias, or accept a missing key. An append that
/// cannot read the grouping fact must refuse, not invent one — a synthesized
/// speaker would let a second speaker's messages join a turn that already
/// belongs to someone else.
pub(super) fn decode_witness_turn_speaker(body: &[u8]) -> MemoryResult<&str> {
    let unstamped = || {
        MemoryError::bad_request_with(
            "the witnessed turn carries no speaker",
            &["Witness a new turn instead of appending to an unstamped one."],
        )
    };
    let mut cursor = body;
    let Ok(ValueRef::Map(entries)) = rmpv::decode::read_value_ref(&mut cursor) else {
        return Err(unstamped());
    };
    let mut speaker: Option<&str> = None;
    for (key, value) in entries {
        let ValueRef::String(key) = key else {
            continue;
        };
        if key.as_str() != Some(WITNESS_TURN_SPEAKER_KEY) {
            continue;
        }
        if speaker.is_some() {
            return Err(unstamped());
        }
        let ValueRef::String(text) = value else {
            return Err(unstamped());
        };
        speaker = match text.into_str() {
            Some(text) if !text.is_empty() => Some(text),
            _ => return Err(unstamped()),
        };
    }
    speaker.ok_or_else(unstamped)
}

/// The minted TURN body: one additive `speaker` entry, nothing else.
fn encode_witness_turn_body(speaker: &str) -> MemoryResult<Vec<u8>> {
    encode_rmpv(&Value::Map(vec![(
        Value::from(WITNESS_TURN_SPEAKER_KEY),
        Value::from(speaker),
    )]))
}

pub(super) fn encode_witness_message_body(message: &WitnessMessage) -> MemoryResult<Vec<u8>> {
    let mut entries = vec![
        (Value::from("author"), Value::from(message.author.as_str())),
        (
            Value::from("type"),
            Value::from(message.message_type.as_str()),
        ),
        (
            Value::from("content"),
            Value::from(message.content.as_str()),
        ),
    ];
    if let Some(metadata) = &message.metadata {
        entries.push((Value::from("metadata"), json_to_rmpv(metadata)));
    }
    entries.push((
        Value::from("is_visible"),
        Value::Boolean(message.is_visible),
    ));
    entries.push((Value::from("order"), Value::from(u64::from(message.order))));
    encode_rmpv(&Value::Map(entries))
}
