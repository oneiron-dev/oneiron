//! Seam: the session handle — `SessionVault` enter/bind/witness/stage/search/close/promote — and the typed `SeamError` refusals.

use crate::batch::BatchOp;
use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::session_overlay::{JournalEntry, JournalRole, JournalScope};
use crate::temporal::TimeRange;
use crate::vault::Vault;

use super::binding::{map_session_error, scoped_read_actor_key, scoped_read_visible_claim_count};

/// A typed journal entry for the substrate-level oracles, which assert
/// journal ATOMICITY and byte accounting rather than role semantics.
pub(crate) fn seam_journal_entry(scope: JournalScope, op: BatchOp) -> JournalEntry {
    JournalEntry {
        scope,
        role: JournalRole::TurnOwnedArtifact,
        learned_at: 1,
        occurred: TimeRange { start: 1, end: 1 },
        op,
    }
}

/// Session write-overlay handle (ONE-1726 owns the real substrate type;
/// ONE-1727 owns the vault-level session handle that wraps it).
pub(crate) struct SessionVault<'vault> {
    pub(super) session: crate::off_record::OffRecordSession<'vault>,
    pub(super) vault: &'vault Vault,
    /// The base PERSON this room witnesses as, once one has been bound.
    ///
    /// The witness door requires a base-resident actor, so witnessing
    /// necessarily adds ONE base row. Zero-residue oracles therefore call
    /// `bind_actor` BEFORE taking their census, putting the actor in the
    /// baseline instead of making it look like session residue.
    pub(super) actor: Option<EntityId>,
}

/// One (key, value) row as the model oracle sees it.
pub(crate) type ModelRow = (Vec<u8>, Vec<u8>);

/// The room clock every witness fixture uses unless it pins its own.
pub(crate) const WITNESS_OCCURRED_AT: u64 = 1;

/// Placeholder TYPED refusals for every contract that pins a typed
/// error / fail-closed behavior (ONE-1726 budget+lease, ONE-1727
/// kill-switch+single-shot, ONE-1728 taint, ONE-1729 policy, ONE-1732
/// ABI gate). The arming ticket maps each variant onto the real error
/// type; VARIANT-LEVEL DISCRIMINATION must survive the mapping — these
/// tests assert exact variants, never bare `is_err()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeamError {
    /// ONE-1727: `off_record_enabled = false` — enter fails closed.
    KillSwitchDisabled,
    /// ONE-1727: re-entering a session ref that is still live.
    SessionRefLive,
    /// ONE-1728: base batch preflight taint-guard rejection.
    TaintedBaseWrite,
    /// ONE-1729: guest-supplied turn_ref policy rejection.
    GuestTurnRef,
    /// ONE-1729: durable-memory-write verb policy rejection.
    PolicyMemoryWrite,
    /// ONE-1729: binding a session ref no live registry entry answers.
    SessionNotFound,
    /// ONE-1729: binding a session whose close pass has begun.
    SessionClosing,
    /// ONE-1726: pre-insert byte budget (`OffRecordOverlayFull`).
    OverlayFull,
    /// ONE-1726: generation-stamped lease refused after close.
    LeaseClosed,
    /// ONE-1732: the STORAGE_ABI gate fails closed.
    AbiFailClosed,
}

pub(crate) type SeamResult<T> = std::result::Result<T, SeamError>;

/// ONE-1730 ARMED: the PRODUCTION promote return type, not a test twin.
/// The shim this replaced pinned exactly these two fields and `PartialEq`
/// (the retry oracle asserts the second call returns the identical
/// outcome); the landed type carries them, so the oracle now measures the
/// engine's own surface rather than a parallel struct that could drift.
pub(crate) use crate::off_record::PromoteOutcome;

impl<'vault> SessionVault<'vault> {
    pub(crate) fn enter(vault: &'vault Vault, session_ref: &str) -> SeamResult<Self> {
        vault
            .off_record_session_vault()
            .enter(session_ref, crate::off_record::OffRecordBackendClass::Local)
            .map(|session| Self {
                session,
                vault,
                actor: None,
            })
            .map_err(map_session_error)
    }

    /// ONE-1726 budget-oracle seam: the passed session owns the requested
    /// overlay budget so rejection and close exercise the same handle.
    pub(crate) fn enter_with_budget(
        vault: &'vault Vault,
        _session_ref: &str,
        budget: usize,
    ) -> SeamResult<Self> {
        vault
            .off_record_session_vault()
            .enter_with_budget(
                _session_ref,
                crate::off_record::OffRecordBackendClass::Local,
                budget,
            )
            .map(|session| Self {
                session,
                vault,
                actor: None,
            })
            .map_err(map_session_error)
    }

    /// ONE-1727: enter with the kill-switch config disabled.
    pub(crate) fn enter_with_kill_switch_off(
        _vault: &Vault,
        _session_ref: &str,
    ) -> SeamResult<Self> {
        let dir = tempfile::tempdir().expect("kill-switch oracle temp dir");
        let config = VaultConfig {
            off_record_enabled: false,
            ..Default::default()
        };
        let disabled = Vault::open(dir.path(), config).expect("open kill-switch oracle vault");
        let refusal = disabled.off_record_session_vault().enter(
            _session_ref,
            crate::off_record::OffRecordBackendClass::Local,
        );
        assert!(
            disabled
                .off_record_session(_session_ref)
                .expect("inspect kill-switch registry")
                .is_none(),
            "kill-switch refusal must not leave a registry entry"
        );
        match refusal {
            Err(error) => Err(map_session_error(error)),
            Ok(_) => panic!("kill-switch-disabled session enter unexpectedly succeeded"),
        }
    }

    /// Seeds and binds the base PERSON this room witnesses as.
    ///
    /// Separate from `enter` because it WRITES a base row: a zero-residue
    /// oracle calls it before taking its census, so the actor is baseline
    /// rather than apparent session residue.
    pub(crate) fn bind_actor(&mut self) -> Result<EntityId> {
        let actor = EntityId::now();
        self.vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"branch-store oracle witness actor",
        )?;
        self.actor = Some(actor);
        Ok(actor)
    }

    /// ONE-1727: witness one turn (+ PartOf MESSAGE, DerivedFrom SUMMARY)
    /// through the session handle; rows land in the overlay only.
    /// Returns the ids of (turn, message, summary).
    ///
    /// Armed on `Memory::witness_into_session` with a summary, so
    /// the room lands TURN + MESSAGE + SUMMARY — the three transcript
    /// entities the master-close oracle counts.
    pub(crate) fn witness_turn(&self, text: &str) -> Result<(EntityId, EntityId, EntityId)> {
        self.witness_turn_with_summary(text, text)
    }

    /// ONE-1730: the same witness with the SUMMARY text chosen separately.
    ///
    /// The summary is a SECOND BM25 document. An oracle whose evidence is
    /// a search-hit COUNT therefore has to control whether the summary
    /// repeats the query term, or its count measures how many documents a
    /// turn happens to produce rather than which turn was promoted.
    pub(crate) fn witness_turn_with_summary(
        &self,
        text: &str,
        summary: &str,
    ) -> Result<(EntityId, EntityId, EntityId)> {
        let (turn, message, summary) =
            self.witness_turn_shape(text, Some(summary), WITNESS_OCCURRED_AT)?;
        // With `Some(summary)` the room always materializes a SUMMARY,
        // EXCEPT post-flip, where the base program has none — the
        // fallback below is the flip oracle's, not this arm's.
        Ok((turn, message, summary.unwrap_or(turn)))
    }

    /// ONE-1730: the same witness with the ROOM CLOCK pinned.
    ///
    /// `occurred_at` is what the witness journals as both `occurred` and
    /// `learned_at`, so this is how an oracle names the timestamp it
    /// expects promote to carry into base unchanged.
    pub(crate) fn witness_turn_at(
        &self,
        text: &str,
        occurred_at: u64,
    ) -> Result<(EntityId, EntityId, EntityId)> {
        let (turn, message, summary) = self.witness_turn_shape(text, Some(text), occurred_at)?;
        Ok((turn, message, summary.unwrap_or(turn)))
    }

    /// ONE-1728: the same witness with the SUMMARY suppressed.
    ///
    /// The staged transcript shape is a parameter, not a constant: an
    /// oracle that asserts "this room created zero background jobs" wants
    /// the SMALLEST program that still exercises the session write path,
    /// and a summary is one more `Text` op whose absence sharpens rather
    /// than weakens the claim. Returns `(turn, message)`.
    pub(crate) fn witness_turn_without_summary(&self, text: &str) -> Result<(EntityId, EntityId)> {
        let (turn, message, summary) = self.witness_turn_shape(text, None, WITNESS_OCCURRED_AT)?;
        assert!(
            summary.is_none(),
            "a witness with summary=None must materialize no SUMMARY"
        );
        Ok((turn, message))
    }

    /// The one witness body both shapes share: `summary` is threaded
    /// straight through to `witness_into_session`, and the SUMMARY id is
    /// reported as `Option` rather than collapsed into the turn id, so a
    /// caller that asked for no summary can PROVE none was made.
    fn witness_turn_shape(
        &self,
        text: &str,
        summary: Option<&str>,
        occurred_at: u64,
    ) -> Result<(EntityId, EntityId, Option<EntityId>)> {
        // The bound actor is a BASE entity by construction — the witness
        // door proves the actor exists in the store before it writes. It
        // is therefore seeded once at `enter`, BEFORE any oracle takes its
        // zero-residue census, so the actor row is part of the baseline
        // rather than residue the room appears to have left behind.
        let actor = self.actor.ok_or(Error::InvariantViolation(
            "witness_turn needs bind_actor() first: the witness door writes \
             one BASE actor row, which zero-residue oracles must census",
        ))?;
        let facade = self.vault.memory(actor, crate::edge::EdgeActorClass::Human);
        let message_id = EntityId::now();
        let receipt = facade
            .witness_into_session(
                &self.session,
                &crate::memory::WitnessTurn {
                    conversation_ref: String::new(),
                    turn_ref: None,
                    messages: vec![crate::memory::WitnessMessage {
                        id: Some(message_id.to_hex()),
                        author: crate::memory::WitnessAuthor::User,
                        message_type: "utterance".to_owned(),
                        content: text.to_owned(),
                        metadata: None,
                        is_visible: true,
                        order: 0,
                    }],
                    occurred_at,
                },
                summary,
            )
            .unwrap_or_else(|error| panic!("oracle session witness failed: {error:?}"));
        let turn_id = EntityId::from_hex(
            receipt
                .receipt_ref
                .strip_prefix("witness:")
                .ok_or(Error::InvariantViolation("witness receipt names no turn"))?,
        )?;
        // The SUMMARY is the room's only `DerivedFrom` source on this
        // turn, so the edge index names it exactly — no guessing from
        // put order. SUMMARY materialization is SESSION-ONLY (blueprint
        // §facade), so a post-flip witness legitimately has none; `None`
        // states that rather than aliasing the turn id.
        let view = self.session.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        let mut summary_id = None;
        for row in view.edges_in.prefix_iter(&rtxn, turn_id.as_bytes())? {
            let (key, _) = row?;
            // An `edges_in` key is (TARGET ‖ kind ‖ SOURCE) — the mirror of
            // `edges_out` — so the parser's first element is the turn this
            // scan is already prefixed on and the PEER element is the edge's
            // source. Reading the first one back handed the turn its own id
            // as its summary, which every caller then silently aliased
            // through `summary.unwrap_or(turn)` (ONE-1730: the promote
            // closure oracle is the first assertion that can see it).
            let (_scanned_turn, kind, peer) = crate::edge::parse_strict_edge_record_key(&key)?;
            if kind == crate::edge::EdgeKind::DerivedFrom {
                summary_id = Some(peer);
                break;
            }
        }
        drop(rtxn);
        drop(view);
        Ok((turn_id, message_id, summary_id))
    }

    /// ONE-1728: stage one legal CLAIM into the session overlay.
    ///
    /// CLAIM is the only entity class the BASE apply marks pending-embed
    /// (`batch.rs`' op-loop CLAIM arm calls `mark_pending_embedding`), so
    /// it is the exact op the K6 routing rule has to skip. A witness of
    /// TURN/MESSAGE alone would prove nothing here: those types never
    /// reach the marker branch on either path, so the assertion would
    /// hold even if the session path DID enqueue.
    ///
    /// Staged through the same `apply_ops_session` entry the witness
    /// uses, with a `TurnOwnedArtifact` role — the claim is turn-scoped
    /// content, not one of the five closed transcript roles.
    pub(crate) fn stage_session_claim(&self, subject: &EntityId) -> Result<EntityId> {
        use crate::claim::{
            ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
        };

        let claim_id = EntityId::now();
        let mut body = ClaimBody::new(
            "dream.symbol",
            ClaimSubject::Entity(*subject),
            rmpv::Value::from("a blue door"),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Inferred);
        let data = crate::claim::encode_claim_body(&body)?;

        let route = self.session.write_route()?;
        let overlay = self.session.overlay();
        let occurred = TimeRange { start: 1, end: 1 };
        let entry = JournalEntry {
            scope: JournalScope::new(EntityId::now(), *subject),
            role: JournalRole::TurnOwnedArtifact,
            learned_at: 1,
            occurred,
            op: BatchOp::Put {
                id: claim_id,
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                occurred,
                learned_at: 1,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            },
        };
        let segment = self.vault.with_write_txn(|wtxn| {
            let segment = overlay.install_txn_segment()?;
            crate::batch::apply_ops_session(
                &self.session.read_view()?,
                &route,
                &self.vault.config,
                &self.vault.analyzer,
                wtxn,
                vec![entry],
            )?;
            Ok(segment)
        })?;
        segment.commit()?;
        Ok(claim_id)
    }

    /// ONE-1728: does the room's composed view (overlay ∪ base) hold an
    /// entity body for `id`? The landing probe every staging helper needs
    /// — a stage that silently wrote nothing must not read as success.
    pub(crate) fn session_sees_entity(&self, id: &EntityId) -> Result<bool> {
        let view = self.session.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        let seen = view.entities.get(&rtxn, id.as_bytes())?.is_some();
        drop(rtxn);
        drop(view);
        Ok(seen)
    }

    /// ONE-1728: session retrieval through the composed handle (records
    /// its retrieval-run rows in the overlay). Scores are projected away
    /// here because the visibility oracles ask WHICH ids surfaced, not how
    /// they ranked.
    pub(crate) fn search_text(&self, query: &str, limit: usize) -> Result<Vec<EntityId>> {
        Ok(self
            .session
            .search_text(query, limit)?
            .into_iter()
            .map(|scored| scored.id)
            .collect())
    }

    /// ONE-1728: the room's own retrieval-run rows, read through the
    /// composed view (overlay ∪ base).
    pub(crate) fn retrieval_run_count(&self) -> Result<usize> {
        let view = self.session.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        let count = view.retrieval_runs_in_txn(&rtxn, 1_000)?.len();
        drop(rtxn);
        drop(view);
        Ok(count)
    }

    /// ONE-1727: mode flip (OffRecord <-> OnRecord).
    pub(crate) fn flip_on_record(&self) -> Result<()> {
        self.session.flip_on_record()
    }

    /// ONE-1726 test seam: drain leases and drop the overlay. ONE-1727
    /// adds SessionLocalReceiptLog outcome counts.
    ///
    /// The third slot is FLOOR SURVIVORS: the K1 crossings still readable
    /// in base after the room evaporated — egress gate decisions
    /// (`FloorWrites` op 1/3) plus any REDACTION_AUDIT rows in base. It is
    /// counted from BASE after close, not from the close path's own report,
    /// because "kept" is a claim about what SURVIVED, and a close that
    /// forgot to spare a floor row would still have reported minting it.
    /// ONE-1731: close mints nothing of its own here — it performs no
    /// deletion at all — so every counted row predates it.
    pub(crate) fn close(self) -> Result<(usize, usize, usize)> {
        let Self { session, vault, .. } = self;
        let outcome = session.close()?;
        let floor_receipts_kept = vault.store.gate_decisions(1_000)?.len()
            + vault
                .entities_by_type(crate::registry::ENTITY_TYPE_REDACTION_AUDIT)?
                .len();
        Ok((
            outcome.turns_deleted,
            outcome.context_receipts_deleted + outcome.emit_receipts_deleted,
            floor_receipts_kept,
        ))
    }

    /// ONE-1728 (K1 op 1/3): make ONE durable floor crossing while the
    /// room is live, through the only surface allowed to make one.
    ///
    /// Goes through `FloorWrites::append_egress_gate_decision` rather than
    /// `Store::append_gate_decision_in_txn` directly: the done-means pins
    /// the FLOOR path, and a probe that wrote the same row through the
    /// store would prove a row survives close without proving the sealed
    /// crossing is what put it there.
    pub(crate) fn append_floor_egress_decision(&self) -> Result<()> {
        let record = crate::store::GateDecisionRecord {
            version: 0,
            decision_id: crate::store::GateDecisionId::now(),
            created_at: 10,
            outcome: "allow".to_owned(),
            reason_codes: vec!["gate.policy_model.allow".to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "agent".to_owned(),
            actor_ref: Some("agent-alpha".to_owned()),
            content_kind: "outbound_content".to_owned(),
            policy_manifest_version: "test-policy".to_owned(),
            // No grant_ref and no claim_id, so this crossing writes
            // EXACTLY one `vault_meta` row — the census delta below names
            // that one row rather than an unexplained bump.
            claim_id: None,
            grant_ref: None,
            diff_handle: vec![0xA5],
            read_frontier_hash: [0xB6; 32],
            redacted_at: None,
        };
        self.vault.with_write_txn(|wtxn| {
            crate::off_record::FloorWrites::new(&self.vault.store)
                .append_egress_gate_decision(wtxn, &record)
        })
    }

    /// ONE-1730 ARMED: promote exactly one turn; returns the replayed
    /// closure (from the TYPED journal) and the temp->canonical short-id
    /// mapping.
    pub(crate) fn promote_turn(&self, turn: &EntityId) -> Result<PromoteOutcome> {
        self.session.promote_turn(turn)
    }

    /// ONE-1730 ARMED: the fresh conversation shell wrapping a witnessed
    /// turn (needed to pin the promoted closure's EXACT identity).
    ///
    /// The room allocates ONE shell and every turn in it hangs off that
    /// shell, so the turn argument names which room to ask rather than
    /// selecting between shells. It is kept because the promotion CONTRACT
    /// is per turn: a future room with per-turn shells must answer this
    /// question without a signature change.
    pub(crate) fn session_shell_for_turn(&self, _turn: &EntityId) -> Result<EntityId> {
        self.session.overlay_conversation_shell()
    }

    /// ONE-1728: the session-local short ref (short id + content hash)
    /// allocated in-room for `id` — session-scoped, never resolvable
    /// through the BASE resolver until promote.
    ///
    /// Witness already allocated the alias, so this reads the existing
    /// one back rather than minting a second: `alloc_session_short_id` is
    /// idempotent per id within a room.
    pub(crate) fn session_short_ref(&self, id: &EntityId) -> Result<(String, u8)> {
        let overlay = self.session.overlay();
        let _segment = overlay.install_txn_segment()?;
        overlay.alloc_session_short_id(id, id.as_bytes())
    }

    /// ONE-1728: the number of claims a SESSION-side ScopedRead surfaces
    /// for `subject` — the union half of the R10 reader family.
    pub(crate) fn session_scoped_read_visible_claim_count(
        &self,
        subject: &EntityId,
    ) -> Result<usize> {
        let view = self.session.read_view()?;
        let count = scoped_read_visible_claim_count(
            &self
                .vault
                .scoped_read_in_session(scoped_read_actor_key(), &view),
            subject,
        )?;
        drop(view);
        Ok(count)
    }

    /// ONE-1728 (K10): flip the room back to off record, rearming the
    /// overlay so new writes stage there again.
    pub(crate) fn flip_off_record(&self) -> Result<()> {
        self.session.flip_off_record()
    }

    /// ONE-1728 (K10): mint a write route at the CURRENT mode, so a test
    /// can hold it across a flip and prove `revalidate` refuses it.
    pub(crate) fn write_route(&self) -> Result<crate::session_overlay::SessionWriteRoute> {
        self.session.write_route()
    }

    /// ONE-1729: exact artifact census through the SESSION view —
    /// (speak turns, code-run replay records, raw-output rows).
    ///
    /// The two `vault_meta` prefixes are spelled out rather than imported:
    /// the acceptance pin is that the code-run key FORMATS did not change
    /// under the session route, and a census that reused the producer's
    /// own constants would agree with a rename.
    pub(crate) fn session_artifact_census(&self) -> Result<(usize, usize, usize)> {
        let view = self.session.read_view()?;
        let rtxn = self.vault.store.env.read_txn()?;
        let mut turns = 0_usize;
        for row in view
            .type_index
            .prefix_iter(&rtxn, &[crate::registry::ENTITY_TYPE_TURN])?
        {
            row?;
            turns += 1;
        }
        let count = |prefix: &[u8]| -> Result<usize> {
            let mut rows = 0_usize;
            for row in view.vault_meta.prefix_iter(&rtxn, prefix)? {
                row?;
                rows += 1;
            }
            Ok(rows)
        };
        let replay_records = count(b"code_run:replay:v1:")?;
        let raw_outputs = count(b"code_run:raw_output:v1:")?;
        drop(rtxn);
        drop(view);
        Ok((turns, replay_records, raw_outputs))
    }
}
