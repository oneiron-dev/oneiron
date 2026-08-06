//! BRST forward test oracle — ARCH-0052 off-record branch store (ONE-1725).
//!
//! Contract-level red tests for every subsequent phase of the branch-store
//! epic, authored with the P1 path opener (owner path-opener pattern). Each
//! test is `#[ignore = "armed by ONE-XXXX"]`: the arming ticket removes the
//! ignore, adapts SIGNATURES to the machinery it lands (the [`seam`] shims
//! below are the thinnest plausible surface, not a design), and NEVER weakens
//! an assertion. Assertions are count-exact by rule — never `any()`.
//!
//! Contract sources: ARCH-0052 §3 (D1–D9), §4 (test oracle), §7 (phase
//! plan); ticket acceptance criteria ONE-1726..ONE-1732; the wave-1 fence
//! findings ledger (reader-visibility breadth = the acceptance spec for the
//! base-leak sweep: `get_raw`-class raw reads first, then search/short-id,
//! edge readers, existence/enumeration, tree walks, ScopedRead, telemetry).

use std::ops::Bound;

use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Thinnest plausible seam for machinery the arming tickets own.
///
/// Unarmed functions panic with the owning ticket. These signatures exist
/// ONLY so the oracle compiles red; each arming ticket replaces its shim with
/// the real API. Do NOT grow logic here.
mod seam {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use heed::types::Bytes;
    use heed::{DatabaseFlags, Env, EnvOpenOptions, RwTxn};

    use super::*;
    use crate::batch::BatchOp;
    use crate::config::DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES;
    use crate::error::Error;
    use crate::overlay_db::OverlayDb;
    use crate::session_overlay::{
        JournalEntry, JournalRole, JournalScope, OverlayKeyspace, SessionOverlay,
    };
    use crate::temporal::TimeRange;

    /// A typed journal entry for the substrate-level oracles, which assert
    /// journal ATOMICITY and byte accounting rather than role semantics.
    pub(super) fn seam_journal_entry(scope: JournalScope, op: BatchOp) -> JournalEntry {
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
    pub(super) struct SessionVault<'vault> {
        session: crate::off_record::OffRecordSession<'vault>,
        vault: &'vault Vault,
        /// The base PERSON this room witnesses as, once one has been bound.
        ///
        /// The witness door requires a base-resident actor, so witnessing
        /// necessarily adds ONE base row. Zero-residue oracles therefore call
        /// `bind_actor` BEFORE taking their census, putting the actor in the
        /// baseline instead of making it look like session residue.
        actor: Option<EntityId>,
    }

    /// One (key, value) row as the model oracle sees it.
    pub(super) type ModelRow = (Vec<u8>, Vec<u8>);

    /// Placeholder TYPED refusals for every contract that pins a typed
    /// error / fail-closed behavior (ONE-1726 budget+lease, ONE-1727
    /// kill-switch+single-shot, ONE-1728 taint, ONE-1729 policy, ONE-1732
    /// ABI gate). The arming ticket maps each variant onto the real error
    /// type; VARIANT-LEVEL DISCRIMINATION must survive the mapping — these
    /// tests assert exact variants, never bare `is_err()`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum SeamError {
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

    pub(super) type SeamResult<T> = std::result::Result<T, SeamError>;

    /// ONE-1730: what one promote returns — the replayed closure and the
    /// temp->canonical short-id mapping (ticket: "Promote returns the
    /// temp→canonical mapping"). PartialEq so the idempotent-retry oracle
    /// can assert the SECOND call returns the identical outcome.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct PromoteOutcome {
        pub(super) replayed: Vec<EntityId>,
        pub(super) short_id_mapping: Vec<(String, String)>,
    }

    impl<'vault> SessionVault<'vault> {
        pub(super) fn enter(vault: &'vault Vault, session_ref: &str) -> SeamResult<Self> {
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
        pub(super) fn enter_with_budget(
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
        pub(super) fn enter_with_kill_switch_off(
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
        pub(super) fn bind_actor(&mut self) -> Result<EntityId> {
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
        /// Armed on `MemoryFacade::witness_into_session` with a summary, so
        /// the room lands TURN + MESSAGE + SUMMARY — the three transcript
        /// entities the master-close oracle counts.
        pub(super) fn witness_turn(&self, text: &str) -> Result<(EntityId, EntityId, EntityId)> {
            let (turn, message, summary) = self.witness_turn_shape(text, Some(text))?;
            // With `Some(summary)` the room always materializes a SUMMARY,
            // EXCEPT post-flip, where the base program has none — the
            // fallback below is the flip oracle's, not this arm's.
            Ok((turn, message, summary.unwrap_or(turn)))
        }

        /// ONE-1728: the same witness with the SUMMARY suppressed.
        ///
        /// The staged transcript shape is a parameter, not a constant: an
        /// oracle that asserts "this room created zero background jobs" wants
        /// the SMALLEST program that still exercises the session write path,
        /// and a summary is one more `Text` op whose absence sharpens rather
        /// than weakens the claim. Returns `(turn, message)`.
        pub(super) fn witness_turn_without_summary(
            &self,
            text: &str,
        ) -> Result<(EntityId, EntityId)> {
            let (turn, message, summary) = self.witness_turn_shape(text, None)?;
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
            let facade = self
                .vault
                .memory_facade(actor, crate::edge::EdgeActorClass::Human);
            let message_id = EntityId::now();
            let receipt = facade
                .witness_into_session(
                    &self.session,
                    &crate::facade::WitnessTurn {
                        conversation_ref: String::new(),
                        turn_ref: None,
                        messages: vec![crate::facade::WitnessMessage {
                            id: Some(message_id.to_hex()),
                            author: crate::facade::WitnessAuthor::User,
                            message_type: "utterance".to_owned(),
                            content: text.to_owned(),
                            metadata: None,
                            is_visible: true,
                            order: 0,
                        }],
                        occurred_at: 1,
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
                let (source, kind, _) = crate::edge::parse_strict_edge_record_key(&key)?;
                if kind == crate::edge::EdgeKind::DerivedFrom {
                    summary_id = Some(source);
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
        pub(super) fn stage_session_claim(&self, subject: &EntityId) -> Result<EntityId> {
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
        pub(super) fn session_sees_entity(&self, id: &EntityId) -> Result<bool> {
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
        pub(super) fn search_text(&self, query: &str, limit: usize) -> Result<Vec<EntityId>> {
            Ok(self
                .session
                .search_text(query, limit)?
                .into_iter()
                .map(|scored| scored.id)
                .collect())
        }

        /// ONE-1728: the room's own retrieval-run rows, read through the
        /// composed view (overlay ∪ base).
        pub(super) fn retrieval_run_count(&self) -> Result<usize> {
            let view = self.session.read_view()?;
            let rtxn = self.vault.store.env.read_txn()?;
            let count = view.retrieval_runs_in_txn(&rtxn, 1_000)?.len();
            drop(rtxn);
            drop(view);
            Ok(count)
        }

        /// ONE-1727: mode flip (OffRecord <-> OnRecord).
        pub(super) fn flip_on_record(&self) -> Result<()> {
            self.session.flip_on_record()
        }

        /// ONE-1726 test seam: drain leases and drop the overlay. ONE-1727
        /// adds SessionLocalReceiptLog outcome counts.
        ///
        /// The third slot is FLOOR SURVIVORS: the K1 crossings still readable
        /// in base after the room evaporated — egress gate decisions
        /// (`FloorWrites` op 1/3) plus the REDACTION_AUDIT receipts minted by
        /// the legacy per-turn deletions (op 2/3). It is counted from BASE
        /// after close, not from the close path's own report, because "kept"
        /// is a claim about what SURVIVED, and a close that forgot to spare a
        /// floor row would still have reported minting it.
        pub(super) fn close(self) -> Result<(usize, usize, usize)> {
            let Self { session, vault, .. } = self;
            let outcome = session.close()?;
            let floor_receipts_kept =
                vault.store.gate_decisions(1_000)?.len() + outcome.redaction_receipt_ids.len();
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
        pub(super) fn append_floor_egress_decision(&self) -> Result<()> {
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

        /// ONE-1730: promote exactly one turn; returns the replayed closure
        /// (from the TYPED journal) and the temp->canonical short-id mapping.
        pub(super) fn promote_turn(&self, _turn: &EntityId) -> Result<PromoteOutcome> {
            unimplemented!("armed by ONE-1730: typed-journal one-txn promote")
        }

        /// ONE-1730: the fresh conversation shell wrapping a witnessed turn
        /// (needed to pin the promoted closure's EXACT identity).
        pub(super) fn session_shell_for_turn(&self, _turn: &EntityId) -> Result<EntityId> {
            unimplemented!("armed by ONE-1730: conversation shell id for the closure")
        }

        /// ONE-1728: the session-local short ref (short id + content hash)
        /// allocated in-room for `id` — session-scoped, never resolvable
        /// through the BASE resolver until promote.
        ///
        /// Witness already allocated the alias, so this reads the existing
        /// one back rather than minting a second: `alloc_session_short_id` is
        /// idempotent per id within a room.
        pub(super) fn session_short_ref(&self, id: &EntityId) -> Result<(String, u8)> {
            let overlay = self.session.overlay();
            let _segment = overlay.install_txn_segment()?;
            overlay.alloc_session_short_id(id, id.as_bytes())
        }

        /// ONE-1728: the number of claims a SESSION-side ScopedRead surfaces
        /// for `subject` — the union half of the R10 reader family.
        pub(super) fn session_scoped_read_visible_claim_count(
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
        pub(super) fn flip_off_record(&self) -> Result<()> {
            self.session.flip_off_record()
        }

        /// ONE-1728 (K10): mint a write route at the CURRENT mode, so a test
        /// can hold it across a flip and prove `revalidate` refuses it.
        pub(super) fn write_route(&self) -> Result<crate::session_overlay::SessionWriteRoute> {
            self.session.write_route()
        }

        /// ONE-1729: exact artifact census through the SESSION view —
        /// (speak turns, code-run replay records, raw-output rows).
        ///
        /// The two `vault_meta` prefixes are spelled out rather than imported:
        /// the acceptance pin is that the code-run key FORMATS did not change
        /// under the session route, and a census that reused the producer's
        /// own constants would agree with a rename.
        pub(super) fn session_artifact_census(&self) -> Result<(usize, usize, usize)> {
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

        /// ONE-1729: run one executor verb under the session binding;
        /// Err = the exact typed refusal.
        ///
        /// The four durable memory verbs go through the PUBLIC dispatch call,
        /// so the probe brackets the same entry point production uses — the
        /// policy check itself is module-private, and bracketing dispatch is
        /// the observable equivalent. `Speak` runs the full executor artifact
        /// round (one turn, one replay record, one raw output) through the
        /// bound storage; `GuestTurnRef` calls the session-side witness entry
        /// with a guest-supplied turn ref.
        pub(super) fn dispatch_executor_verb(&self, verb: &str) -> SeamResult<()> {
            self.run_executor_verb(verb).map_err(map_executor_error)
        }

        /// ONE-1729: the same dispatch, reported as the PRODUCTION error kind.
        ///
        /// Once the room is on record these verbs take the ordinary path, and
        /// the ordinary path's answer is the write GATE's — which is not an
        /// off-record concern and must not be folded into a [`SeamError`] that
        /// would blur it with one. The post-flip claim is about which check
        /// spoke, so the kind is exactly the right resolution.
        pub(super) fn executor_verb_error_kind(
            &self,
            verb: &str,
        ) -> Option<crate::error::ErrorKind> {
            self.run_executor_verb(verb).err().map(|error| error.kind())
        }

        fn run_executor_verb(&self, verb: &str) -> Result<()> {
            match verb {
                "GuestTurnRef" => self
                    .witness_executor_utterance(
                        crate::off_record::ExecutorUtterance::Speak,
                        "guest turn ref probe",
                        Some(&EntityId::now()),
                    )
                    .map(|_| ()),
                "Speak" => self.run_executor_artifact_round(),
                _ => crate::code_run::SelfDispatcher::dispatch(
                    &self.session_dispatcher("oracle-executor-run")?,
                    self.executor_memory_call(verb, EntityId::now()),
                )
                .map(|_| ()),
            }
        }

        /// The executor's session-bound `self.*` dispatcher.
        pub(super) fn session_dispatcher(
            &self,
            run_ref: &str,
        ) -> Result<crate::code_run::HostSelfDispatcher<'_>> {
            crate::code_run::HostSelfDispatcher::for_off_record_session(
                &self.session,
                crate::WriteActor::new(
                    self.actor.unwrap_or_else(EntityId::now),
                    crate::edge::EdgeActorClass::Agent,
                ),
                run_ref,
            )
        }

        /// One durable-memory-write call per verb name. Bodies are minimal on
        /// purpose: off record the policy refuses before any of this is read,
        /// and on record the ordinary path validates it like any other write.
        /// ONE-1729: the ungated fixture write, reporting the claim id it
        /// used so a caller can prove THAT row reached base rather than
        /// counting rows other verbs may also have moved.
        pub(super) fn dispatch_fixture_write(&self) -> Result<EntityId> {
            let id = EntityId::now();
            crate::code_run::SelfDispatcher::dispatch(
                &self.session_dispatcher("oracle-fixture-write")?,
                self.executor_memory_call("MemoryWriteFixture", id),
            )?;
            Ok(id)
        }

        fn executor_memory_call(&self, verb: &str, id: EntityId) -> crate::SelfCall {
            use crate::{
                ClaimCandidate, ClaimSubject, SelfCall, SelfMemoryPutClaimCall,
                SelfMemoryPutEdgeCall, SelfMemorySupersedeClaimCall, SelfMemoryWriteFixtureCall,
            };

            let subject = self.actor.unwrap_or_else(EntityId::now);
            let candidate = || {
                ClaimCandidate::new(
                    "profile.favorite_drink",
                    ClaimSubject::Entity(subject),
                    rmpv::Value::from("matcha"),
                    0.8,
                )
            };
            let occurred = TimeRange { start: 3, end: 3 };
            match verb {
                "MemoryPutClaim" => SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                    id,
                    candidate(),
                    occurred,
                    4,
                )),
                "MemoryWriteFixture" => SelfCall::MemoryWriteFixture(
                    SelfMemoryWriteFixtureCall::new(id, candidate(), occurred, 4),
                ),
                "MemorySupersedeClaim" => SelfCall::MemorySupersedeClaim(
                    SelfMemorySupersedeClaimCall::new(id, EntityId::now(), 5),
                ),
                "MemoryPutEdge" => SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                    subject,
                    crate::edge::EdgeKind::Mentions,
                    EntityId::now(),
                    1.0,
                )),
                other => panic!("unknown executor verb: {other}"),
            }
        }

        /// ONE-1729: one executor turn through the session-side witness entry.
        pub(super) fn witness_executor_utterance(
            &self,
            kind: crate::off_record::ExecutorUtterance,
            text: &str,
            turn_ref: Option<&EntityId>,
        ) -> Result<crate::facade::WitnessReceipt> {
            let route = self.session.write_route()?;
            let container = self.session.routed_conversation_shell(&route)?;
            self.session.witness_executor_turn(
                &container,
                kind,
                text,
                7,
                turn_ref,
                &route,
                crate::WriteActor::new(
                    self.actor.ok_or(Error::InvariantViolation(
                        "witness_executor_utterance needs bind_actor() first",
                    ))?,
                    crate::edge::EdgeActorClass::Human,
                ),
            )
        }

        /// The artifact round one session-bound code run produces: a turn, a
        /// replay record, and a raw output — each through the bound storage,
        /// never through a canonical vault call.
        fn run_executor_artifact_round(&self) -> Result<()> {
            use crate::code_run::{
                CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord, ExecutorStorage,
            };

            self.witness_executor_utterance(
                crate::off_record::ExecutorUtterance::Speak,
                "executor speaks in the room",
                None,
            )?;
            let storage = ExecutorStorage::for_session(&self.session)?;
            let record = CodeRunReplayRecord::new(
                EntityId::now(),
                CodeRunDeterminism::new(1_719_000_004_000, [0xCE; 32]),
            );
            storage.put_code_run_replay_record_if_generation(&record, None)?;
            let raw = b"executor raw output".as_slice();
            let output = CodeRunRawOutput::from_bytes("executor/repl/000000.observation.txt", raw)?;
            storage.put_code_run_raw_output(&output, raw)
        }

        /// ONE-1729: the session-owned conversation shell a bound run's turns
        /// ride, read back through the dispatcher the executor holds.
        pub(super) fn dispatcher_container_id(&self) -> Result<Option<EntityId>> {
            Ok(self
                .session_dispatcher("oracle-container")?
                .session_container_id()
                .copied())
        }

        /// ONE-1729: the conversation every MESSAGE in the room belongs to.
        /// Exactly one, or the room shredded into a conversation per turn.
        pub(super) fn session_message_shells(&self) -> Result<Vec<EntityId>> {
            let view = self.session.read_view()?;
            let rtxn = self.vault.store.env.read_txn()?;
            let mut shells = Vec::new();
            for row in view
                .type_index
                .prefix_iter(&rtxn, &[crate::registry::ENTITY_TYPE_MESSAGE])?
            {
                let (key, _) = row?;
                let message =
                    EntityId::from_bytes(key[key.len() - 16..].try_into().expect("type index id"))?;
                for edge in view.edges_out.prefix_iter(&rtxn, message.as_bytes())? {
                    let (key, _) = edge?;
                    let (_, kind, target) = crate::edge::parse_strict_edge_record_key(&key)?;
                    if kind == crate::edge::EdgeKind::BelongsTo && !shells.contains(&target) {
                        shells.push(target);
                    }
                }
            }
            drop(rtxn);
            drop(view);
            Ok(shells)
        }
    }

    /// ONE-1726: overlay-vs-model harness. Applies the same (put/delete)
    /// script to a SessionOverlay keyspace over the given base rows and to a
    /// `BTreeMap` model, then returns both sides' full iteration for the
    /// requested window so tests can assert exact sequence equality.
    pub(super) struct OverlayModelHarness {
        env: Env,
        _dir: tempfile::TempDir,
        rows: OverlayDb,
        duplicates: OverlayDb,
        model: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl OverlayModelHarness {
        pub(super) fn new(base_rows: &[ModelRow], overlay_script: &[OverlayOp]) -> Self {
            let dir = tempfile::tempdir().expect("overlay harness temp dir");
            // SAFETY: the harness owns a unique temporary path and keeps its
            // sole environment handle alive until before the TempDir drops.
            let env = unsafe {
                EnvOpenOptions::new()
                    .map_size(10 * 1024 * 1024)
                    .max_dbs(2)
                    .open(dir.path())
                    .expect("open overlay harness env")
            };
            let mut wtxn = env.write_txn().expect("open overlay harness write txn");
            let base = env
                .create_database::<Bytes, Bytes>(&mut wtxn, Some("rows"))
                .expect("create harness row database");
            let duplicate_base = env
                .database_options()
                .types::<Bytes, Bytes>()
                .name("duplicates")
                .flags(DatabaseFlags::DUP_SORT)
                .create(&mut wtxn)
                .expect("create harness DUP_SORT database");
            for (key, value) in base_rows {
                base.put(&mut wtxn, key, value)
                    .expect("seed harness row database");
                duplicate_base
                    .put(&mut wtxn, key, value)
                    .expect("seed harness DUP_SORT database");
            }
            wtxn.commit().expect("commit harness base rows");

            let overlay = SessionOverlay::new(DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES);
            apply_overlay_script(&overlay, overlay_script).expect("apply overlay harness script");
            let snapshot = Arc::new(
                overlay
                    .snapshot()
                    .expect("capture overlay harness snapshot"),
            );

            let mut model = base_rows.iter().cloned().collect::<BTreeMap<_, _>>();
            for op in overlay_script {
                match op {
                    OverlayOp::Put(key, value) => {
                        model.insert(key.clone(), value.clone());
                    }
                    OverlayOp::Delete(key) => {
                        model.remove(key);
                    }
                    OverlayOp::DupAppend(_, _) => {}
                }
            }

            Self {
                env,
                _dir: dir,
                rows: OverlayDb::composed(
                    base,
                    overlay.clone(),
                    snapshot.clone(),
                    OverlayKeyspace::Entities,
                ),
                duplicates: OverlayDb::composed(
                    duplicate_base,
                    overlay,
                    snapshot,
                    OverlayKeyspace::TextPostings,
                ),
                model,
            }
        }

        pub(super) fn prefix_iter(&self, prefix: &[u8]) -> Result<Vec<ModelRow>> {
            let rtxn = self.env.read_txn()?;
            self.rows
                .prefix_iter(&rtxn, prefix)?
                .map(|row| row.map(|(key, value)| (key.into_owned(), value.into_owned())))
                .collect()
        }

        pub(super) fn rev_range(
            &self,
            bounds: (Bound<&[u8]>, Bound<&[u8]>),
        ) -> Result<Vec<ModelRow>> {
            let rtxn = self.env.read_txn()?;
            self.rows
                .rev_range(&rtxn, &bounds)?
                .map(|row| row.map(|(key, value)| (key.into_owned(), value.into_owned())))
                .collect()
        }

        pub(super) fn model_prefix_iter(&self, prefix: &[u8]) -> Vec<ModelRow> {
            self.model
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        }

        pub(super) fn model_rev_range(
            &self,
            bounds: (Bound<&[u8]>, Bound<&[u8]>),
        ) -> Vec<ModelRow> {
            self.model
                .iter()
                .filter(|(key, _)| key_in_bounds(key, bounds))
                .rev()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        }

        /// Merged DUP_SORT duplicate items for one `text_postings` term key.
        pub(super) fn dup_items(&self, term: &[u8]) -> Result<Vec<Vec<u8>>> {
            let rtxn = self.env.read_txn()?;
            let Some(iter) = self.duplicates.get_duplicates(&rtxn, term)? else {
                return Ok(Vec::new());
            };
            iter.map(|row| row.map(|(_, value)| value.into_owned()))
                .collect()
        }
    }

    /// ONE-1726 overlay mutation script entries.
    #[derive(Clone)]
    pub(super) enum OverlayOp {
        Put(Vec<u8>, Vec<u8>),
        Delete(Vec<u8>),
        /// Append one DUP_SORT duplicate item under a term key.
        DupAppend(Vec<u8>, Vec<u8>),
    }

    /// ONE-1726: run `script` inside ONE base write txn through the
    /// read-through txn segment; `probe` runs under the same live txn and
    /// must observe read-your-writes; returns what the probe read.
    pub(super) fn with_txn_segment_read_back(
        vault: &Vault,
        session: &SessionVault<'_>,
        script: &[OverlayOp],
        probe_key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let mut wtxn = vault.store.env.write_txn()?;
        let overlay = session.session.overlay();
        let segment = overlay.install_txn_segment()?;
        let view = session.session.read_view()?;
        apply_view_script(&view.entities, &mut wtxn, script)?;
        let read_view = session.session.read_view()?;
        let read_back = read_view
            .entities
            .get(&wtxn, probe_key)?
            .map(std::borrow::Cow::into_owned);
        wtxn.commit()?;
        segment.commit()?;
        Ok(read_back)
    }

    /// ONE-1726: abort the base txn after staging `script`; returns
    /// (overlay rows visible afterwards, typed-journal entries afterwards).
    pub(super) fn stage_then_abort(
        vault: &Vault,
        session: &SessionVault<'_>,
        script: &[OverlayOp],
    ) -> Result<(usize, usize)> {
        let mut wtxn = vault.store.env.write_txn()?;
        let overlay = session.session.overlay();
        let segment = overlay.install_txn_segment()?;
        let view = session.session.read_view()?;
        apply_view_script(&view.entities, &mut wtxn, script)?;
        let scope = JournalScope::new(EntityId::now(), EntityId::now());
        overlay.stage_journal_entry(seam_journal_entry(
            scope,
            BatchOp::Delete {
                id: EntityId::now(),
            },
        ))?;
        drop(segment);
        drop(wtxn);

        let snapshot = overlay.snapshot()?;
        Ok((
            snapshot.row_count(OverlayKeyspace::Entities),
            snapshot.journal_ops(scope).len(),
        ))
    }

    /// ONE-1727-native crash payload: populate multiple manifest slots and
    /// the typed journal through the substrate directly, without the
    /// ONE-1728 witness/retrieval surface.
    pub(super) fn stage_direct_crash_payload(
        session: &SessionVault<'_>,
    ) -> Result<(usize, usize, usize, usize)> {
        let overlay = session.session.overlay();
        let conversation = EntityId::now();
        let turn_a = EntityId::now();
        let turn_b = EntityId::now();
        let scope = JournalScope::new(conversation, turn_a);
        let segment = overlay.install_txn_segment()?;
        overlay.put(
            OverlayKeyspace::Entities,
            turn_a.as_bytes(),
            b"session entity a",
        )?;
        overlay.put(
            OverlayKeyspace::Entities,
            turn_b.as_bytes(),
            b"session entity b",
        )?;
        overlay.put(
            OverlayKeyspace::TypeIndex,
            b"session:type:turn",
            turn_a.as_bytes(),
        )?;
        overlay.put(
            OverlayKeyspace::TextForward,
            turn_a.as_bytes(),
            b"session-only text",
        )?;
        overlay.stage_journal_entry(seam_journal_entry(scope, BatchOp::Delete { id: turn_a }))?;
        overlay.stage_journal_entry(seam_journal_entry(scope, BatchOp::Delete { id: turn_b }))?;
        segment.commit()?;

        let snapshot = overlay.snapshot()?;
        Ok((
            snapshot.row_count(OverlayKeyspace::Entities),
            snapshot.row_count(OverlayKeyspace::TypeIndex),
            snapshot.row_count(OverlayKeyspace::TextForward),
            snapshot.journal_ops(scope).len(),
        ))
    }

    /// ONE-1726: byte budget configured to `budget` bytes; returns the typed
    /// error produced by the first over-budget insert.
    pub(super) fn overflow_budget(
        vault: &Vault,
        session: &SessionVault<'_>,
        budget: usize,
    ) -> SeamError {
        let mut wtxn = vault
            .store
            .env
            .write_txn()
            .expect("open budget oracle write txn");
        let overlay = session.session.overlay();
        let segment = overlay
            .install_txn_segment()
            .expect("install budget oracle segment");
        let view = session
            .session
            .read_view()
            .expect("capture budget oracle view");
        let value = vec![0_u8; budget.max(overlay.budget_bytes())];
        let error = match view.entities.put(&mut wtxn, b"overflow", &value) {
            Err(error) => map_overlay_error(error),
            Ok(()) => panic!("over-budget overlay insert unexpectedly succeeded"),
        };
        drop(segment);
        drop(wtxn);
        error
    }

    /// ONE-1726: take a read snapshot, apply `script` concurrently, then
    /// finish iterating the snapshot; returns (rows seen by the snapshot,
    /// rows a fresh read sees).
    pub(super) fn snapshot_vs_concurrent_apply(
        vault: &Vault,
        session: &SessionVault<'_>,
        script: &[OverlayOp],
        prefix: &[u8],
    ) -> Result<(Vec<ModelRow>, Vec<ModelRow>)> {
        let rtxn = vault.store.env.read_txn()?;
        let view = session.session.read_view()?;
        let snapshot_iter = view.entities.prefix_iter(&rtxn, prefix)?;
        let overlay = session.session.overlay();
        let apply_result = std::thread::scope(|scope| {
            scope
                .spawn(|| apply_overlay_script(&overlay, script))
                .join()
                .expect("overlay apply thread panicked")
        });
        apply_result?;
        let snapshot_rows = snapshot_iter
            .map(|row| row.map(|(key, value)| (key.into_owned(), value.into_owned())))
            .collect::<Result<Vec<_>>>()?;
        let fresh_view = session.session.read_view()?;
        let fresh_rows = fresh_view
            .entities
            .prefix_iter(&rtxn, prefix)?
            .map(|row| row.map(|(key, value)| (key.into_owned(), value.into_owned())))
            .collect::<Result<Vec<_>>>()?;
        Ok((snapshot_rows, fresh_rows))
    }

    /// ONE-1726: close the overlay, then attempt a lease-holding read.
    pub(super) fn read_after_close(vault: &Vault, session_ref: &str) -> SeamError {
        let session = SessionVault::enter(vault, session_ref).expect("enter session");
        let overlay = session.session.overlay();
        session.close().expect("close session");
        match vault
            .store
            .entities
            .with_overlay(overlay, OverlayKeyspace::Entities)
        {
            Err(error) => map_overlay_error(error),
            Ok(_) => panic!("closed overlay unexpectedly granted a read lease"),
        }
    }

    fn apply_view_script(
        view: &OverlayDb,
        wtxn: &mut RwTxn<'_>,
        script: &[OverlayOp],
    ) -> Result<()> {
        for op in script {
            match op {
                OverlayOp::Put(key, value) => view.put(wtxn, key, value)?,
                OverlayOp::Delete(key) => {
                    view.delete(wtxn, key)?;
                }
                OverlayOp::DupAppend(_, _) => {
                    return Err(Error::InvariantViolation(
                        "DUP_SORT op used with a single-value oracle view",
                    ));
                }
            }
        }
        Ok(())
    }

    fn apply_overlay_script(overlay: &Arc<SessionOverlay>, script: &[OverlayOp]) -> Result<()> {
        let segment = overlay.install_txn_segment()?;
        for op in script {
            match op {
                OverlayOp::Put(key, value) => {
                    overlay.put(OverlayKeyspace::Entities, key, value)?;
                }
                OverlayOp::Delete(key) => {
                    overlay.delete(OverlayKeyspace::Entities, key)?;
                }
                OverlayOp::DupAppend(key, value) => {
                    overlay.put(OverlayKeyspace::TextPostings, key, value)?;
                }
            }
        }
        segment.commit()
    }

    fn key_in_bounds(key: &[u8], bounds: (Bound<&[u8]>, Bound<&[u8]>)) -> bool {
        let above_start = match bounds.0 {
            Bound::Included(start) => key >= start,
            Bound::Excluded(start) => key > start,
            Bound::Unbounded => true,
        };
        let below_end = match bounds.1 {
            Bound::Included(end) => key <= end,
            Bound::Excluded(end) => key < end,
            Bound::Unbounded => true,
        };
        above_start && below_end
    }

    fn map_overlay_error(error: Error) -> SeamError {
        match error {
            Error::OffRecordOverlayFull { .. } => SeamError::OverlayFull,
            Error::OffRecordOverlayLeaseClosed { .. } => SeamError::LeaseClosed,
            other => panic!("unexpected overlay error: {other}"),
        }
    }

    fn map_session_error(error: Error) -> SeamError {
        match error {
            Error::KillSwitchDisabled => SeamError::KillSwitchDisabled,
            Error::OffRecordSessionAlreadyExists { .. } => SeamError::SessionRefLive,
            Error::OffRecordSessionNotFound { .. } => SeamError::SessionNotFound,
            Error::OffRecordSessionClosing { .. } => SeamError::SessionClosing,
            other => panic!("unexpected session error: {other}"),
        }
    }

    /// ONE-1729: production refusals on the session-bound EXECUTOR path,
    /// mapped ONE-TO-ONE. Anything unmapped panics with the production error
    /// rather than folding into a neighbouring variant — these tests assert
    /// exact variants, so a many-to-one fold here would silently weaken them.
    fn map_executor_error(error: Error) -> SeamError {
        match error {
            Error::OffRecordTalkOnly { .. } => SeamError::PolicyMemoryWrite,
            Error::OffRecordGuestTurnRefRejected { .. } => SeamError::GuestTurnRef,
            Error::OffRecordSessionNotFound { .. } => SeamError::SessionNotFound,
            Error::OffRecordSessionClosing { .. } => SeamError::SessionClosing,
            Error::OffRecordOverlayLeaseClosed { .. } => SeamError::LeaseClosed,
            other => panic!("unexpected executor error: {other}"),
        }
    }

    /// ONE-1728: simulated crash after witness population — drop every
    /// session handle WITHOUT close, then reopen the vault from disk.
    ///
    /// Takes the vault BY VALUE: the single-open registry refuses a second
    /// open of a live root (`DuplicateOpenRoot`), so the crashed handle must
    /// be dropped before the reopen, and the caller rebinds the return.
    ///
    /// The caller drops its `SessionVault` WITHOUT `close()` before calling —
    /// that drop IS the simulated crash. Nothing runs the close path, so any
    /// residue the reopen finds is residue a real crash would have left.
    /// The session borrows the vault, so it could not have outlived this
    /// call anyway: the by-value signature makes the ordering a type fact.
    pub(super) fn crash_and_reopen(dir: &std::path::Path, vault: Vault) -> Result<Vault> {
        drop(vault);
        Vault::open(dir, VaultConfig::default())
    }

    /// ONE-1728 (K6): the three background-job database row counts —
    /// (`attempt_records`, `attempt_ready`, `attempt_dedupe`).
    ///
    /// K6's rule is "session flows create ZERO background-job rows", which is
    /// a claim about all three tables, not just the record table: a job whose
    /// record row were suppressed but whose ready/dedupe rows landed would
    /// still be a room leaking into the background worker's view.
    pub(super) fn attempt_row_counts(vault: &Vault) -> Result<(u64, u64, u64)> {
        let rtxn = vault.store.env.read_txn()?;
        Ok((
            vault.store.attempt_records.len(&rtxn)?,
            vault.store.attempt_ready.len(&rtxn)?,
            vault.store.attempt_dedupe.len(&rtxn)?,
        ))
    }

    /// ONE-1728 (K6): every base job row whose key or value mentions one of
    /// `ids` — the reference half of the rule.
    ///
    /// Counting table LENGTHS alone would pass a vault that already held
    /// unrelated jobs; this asks the sharper question the done-means pins,
    /// "does any job row REFERENCE overlay content", across the embed queue
    /// (`sync_queue`), the `pe:` marker keyspace (`sync_state`), and all
    /// three attempt tables. Ids are matched as raw 16-byte needles, which is
    /// how every one of these keyspaces embeds an entity id.
    pub(super) fn job_rows_referencing(vault: &Vault, ids: &[EntityId]) -> Result<usize> {
        let rtxn = vault.store.env.read_txn()?;
        let mut hits = 0_usize;
        let mentions = |bytes: &[u8]| {
            ids.iter()
                .any(|id| bytes.windows(16).any(|window| window == id.as_bytes()))
        };
        for row in vault.store.sync_state.iter(&rtxn)? {
            let (key, value) = row?;
            if mentions(key.as_bytes()) || mentions(&value) {
                hits += 1;
            }
        }
        for db in [
            &vault.store.sync_queue,
            &vault.store.attempt_records,
            &vault.store.attempt_ready,
            &vault.store.attempt_dedupe,
        ] {
            for row in db.iter(&rtxn)? {
                let (key, value) = row?;
                if mentions(&key) || mentions(&value) {
                    hits += 1;
                }
            }
        }
        Ok(hits)
    }

    /// ONE-1728: submit a BASE batch containing one op referencing
    /// `overlay_id`; Err = the taint-guard rejection.
    /// `source` is a PRE-EXISTING base entity supplied by the caller, seeded
    /// before its census: the atomicity assertion is about the rejected
    /// batch's rows, and a probe that minted its own source would charge the
    /// guard for the probe's setup.
    pub(super) fn base_batch_referencing_overlay_id(
        vault: &Vault,
        source: &EntityId,
        overlay_id: &EntityId,
    ) -> SeamResult<()> {
        // An EDGE whose target is the room's turn: an edge endpoint
        // materializes nothing, so it is exactly the K4-owned ref class (D5's
        // door partition) rather than one delegated to the entity door.
        vault
            .batch()
            .edge(source, crate::edge::EdgeKind::PartOf, overlay_id, 1.0)
            .commit()
            .map_err(map_taint_error)
    }

    fn map_taint_error(error: Error) -> SeamError {
        match error {
            Error::OffRecordTaintedBaseWrite { .. } => SeamError::TaintedBaseWrite,
            other => panic!("unexpected base-write error: {other}"),
        }
    }

    /// The actor key every ScopedRead probe in this oracle reads under, so
    /// the base and session halves differ ONLY in their target.
    pub(super) fn scoped_read_actor_key() -> crate::claim::ScopedReadActorKey {
        crate::claim::ScopedReadActorKey::new("branch-store-oracle")
            .expect("oracle scoped-read actor key")
    }

    /// Counts the claims `read` surfaces whose subject is `subject`.
    pub(super) fn scoped_read_visible_claim_count(
        read: &crate::claim::ScopedRead<'_>,
        subject: &EntityId,
    ) -> Result<usize> {
        let mut count = 0_usize;
        for id in read
            .vault()
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
        {
            let Some(body) = read.get(&id)? else {
                continue;
            };
            // `ScopedRead::get` has ALREADY decoded this body under the same
            // permissive flag to answer the policy question (`claim.rs`'
            // `is_claim_raw_readable_with_policy_in`), and propagates the
            // failure — so on this codebase the decode below cannot fail and
            // the `continue` that stood here was unreachable. It is still the
            // wrong shape: the count is EVIDENCE, compared for EQUALITY
            // across the base and session halves of the R10 reader family, so
            // a census that silently drops a row it cannot read reports an
            // agreement it never observed. All-or-error, never partial.
            let body = crate::claim::decode_claim_body(&body, true)?;
            if body.subject == crate::claim::ClaimSubject::Entity(*subject) {
                count += 1;
            }
        }
        Ok(count)
    }

    /// ONE-1728: number of claims a BASE-side ScopedRead surfaces for
    /// `subject` (the ledger's ScopedRead reader family, R10).
    pub(super) fn base_scoped_read_visible_claim_count(
        vault: &Vault,
        subject: &EntityId,
    ) -> Result<usize> {
        scoped_read_visible_claim_count(&vault.scoped_read(scoped_read_actor_key()), subject)
    }

    /// ONE-1730: the crash-matrix sequence, OWNED by the seam end to end:
    /// enter -> witness one turn -> promote it with a crash injected
    /// immediately AFTER the single promote txn commits (the session is
    /// LIVE at promote time) -> reopen from disk. Returns the reopened
    /// vault, the promoted closure ids, and the `pm:` pickup-marker count.
    pub(super) fn promote_then_crash_post_commit(
        _dir: &std::path::Path,
    ) -> Result<(Vault, Vec<EntityId>, usize)> {
        unimplemented!("armed by ONE-1730: pm: markers commit in the promote txn")
    }

    /// ONE-1729: acquire a handle on a session ref, refusal mapped typed.
    pub(super) fn bind_session(vault: &Vault, session_ref: &str) -> SeamResult<()> {
        vault
            .off_record_session_vault()
            .bind(session_ref)
            .map(|_| ())
            .map_err(map_session_error)
    }

    /// ONE-1729: bind a handle while the room is LIVE, close the room through
    /// a different handle, then use the bound one.
    ///
    /// Returns (the stale handle's refusal, a fresh bind's refusal). The two
    /// must be DISTINCT: a handle that outlived its room is closing/gone, and
    /// a ref no registry entry answers is not found. Folding them would hide
    /// the difference between "you are too late" and "that never existed".
    pub(super) fn stale_handle_and_rebind_refusals(
        vault: &Vault,
        session_ref: &str,
    ) -> (SeamError, SeamError) {
        let session = vault
            .off_record_session_vault()
            .enter(session_ref, crate::off_record::OffRecordBackendClass::Local)
            .expect("enter session");
        let bound = vault
            .off_record_session_vault()
            .bind(session_ref)
            .expect("bind a live session");
        session.close().expect("close session");
        let stale = match bound.write_route() {
            Err(error) => map_executor_error(error),
            Ok(_) => panic!("a handle bound before close must not mint a route after it"),
        };
        (
            stale,
            bind_session(vault, session_ref).expect_err("rebinding a closed session"),
        )
    }

    /// ONE-1729: one storage/dispatcher pairing and what run entry did with it.
    pub(super) struct BindingMismatch {
        pub(super) name: &'static str,
        /// The `InvalidConfig` payload run entry refused with, or `None` when
        /// the run was allowed to proceed.
        pub(super) refusal: Option<String>,
    }

    /// Backend and runtime the binding oracle must never reach: run entry
    /// refuses before `load_or_create_record` and before any read or write, so
    /// arriving here at all IS the failure these probes look for.
    struct UnreachableBackend;

    impl crate::LlmBackend for UnreachableBackend {
        fn generate<'a>(
            &'a self,
            _request: crate::LlmRequest,
            _lease: &'a crate::BudgetLease,
        ) -> crate::LlmGenerateFuture<'a> {
            panic!("binding oracle reached the LLM backend")
        }

        fn stream<'a>(
            &'a self,
            _request: crate::LlmRequest,
            _lease: &'a crate::BudgetLease,
        ) -> crate::LlmStreamResult<'a> {
            panic!("binding oracle reached the LLM stream")
        }
    }

    struct UnreachableRuntime;

    impl crate::engine_executor::JsCodeModeRuntime for UnreachableRuntime {
        fn run_step(
            &mut self,
            _step: crate::engine_executor::JsCodeModeStep<'_>,
            _host: &mut dyn crate::engine_executor::JsCodeModeHost,
        ) -> Result<crate::engine_executor::JsCodeModeStepOutcome> {
            panic!("binding oracle reached the sandbox runtime")
        }
    }

    fn oracle_write_actor() -> crate::WriteActor {
        crate::WriteActor::new(EntityId::now(), crate::edge::EdgeActorClass::Agent)
    }

    fn binding_oracle_config() -> crate::engine_executor::EngineExecutorConfig {
        crate::engine_executor::EngineExecutorConfig {
            run_id: EntityId::now(),
            task: "binding oracle".to_owned(),
            model: crate::ModelId::new("test/binding@v1").expect("model id"),
            model_locality: crate::ModelLocality::OwnServer,
            global_tier: crate::ModelTierRef("binding-tier".to_owned()),
            determinism: crate::code_run::CodeRunDeterminism::new(1_719_000_005_000, [0xB7; 32]),
            limits: crate::engine_executor::EngineExecutorLimits::default(),
        }
    }

    fn run_entry_refusal(
        executor: &mut crate::engine_executor::EngineNativeExecutor<'_>,
        config: &crate::engine_executor::EngineExecutorConfig,
    ) -> Option<String> {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut run = std::pin::pin!(executor.run(config));
        let std::task::Poll::Ready(result) = std::future::Future::poll(run.as_mut(), &mut cx)
        else {
            panic!("run entry must settle before it awaits anything")
        };
        match result {
            Err(crate::engine_executor::EngineExecutorError::Engine(Error::InvalidConfig(
                message,
            ))) => Some(message),
            Err(other) => panic!("unexpected executor refusal: {other}"),
            Ok(_) => None,
        }
    }

    /// ONE-1729: every mismatched storage/dispatcher pairing, run to entry.
    ///
    /// The third direction is the one a `session_ref`-only check misses: two
    /// CANONICAL runs whose refs compare equal (`None == None`) across
    /// different vaults.
    pub(super) fn binding_mismatch_directions(
        vault: &Vault,
        session: &SessionVault<'_>,
        other_vault: &Vault,
    ) -> Result<Vec<BindingMismatch>> {
        let backend = UnreachableBackend;
        let lease = crate::BudgetLease::for_test("binding-oracle");
        let config = binding_oracle_config();
        let canonical = crate::code_run::HostSelfDispatcher::new(
            vault,
            oracle_write_actor(),
            "binding-canonical",
        )?;
        let bound = crate::code_run::HostSelfDispatcher::for_off_record_session(
            &session.session,
            oracle_write_actor(),
            "binding-session",
        )?;
        let foreign = crate::code_run::HostSelfDispatcher::new(
            other_vault,
            oracle_write_actor(),
            "binding-foreign",
        )?;

        let mut directions = Vec::with_capacity(3);
        for (name, dispatcher, session_storage) in [
            ("canonical storage + session dispatcher", &bound, false),
            ("session storage + canonical dispatcher", &canonical, true),
            (
                "two vaults whose session refs compare equal",
                &foreign,
                false,
            ),
        ] {
            let mut runtime = UnreachableRuntime;
            let mut executor = if session_storage {
                crate::engine_executor::EngineNativeExecutor::for_off_record_session(
                    &session.session,
                    &backend,
                    &lease,
                    &mut runtime,
                    dispatcher,
                )
                .expect("bind the executor to the live session")
            } else {
                crate::engine_executor::EngineNativeExecutor::new(
                    vault,
                    &backend,
                    &lease,
                    &mut runtime,
                    dispatcher,
                )
            };
            directions.push(BindingMismatch {
                name,
                refusal: run_entry_refusal(&mut executor, &config),
            });
        }
        Ok(directions)
    }

    /// ONE-1729 (R-20260807-02 rider 2): capture the run's route at RUN ENTRY,
    /// flip the room, then apply — through the STORED route, never a fresh one.
    pub(super) fn apply_through_a_route_captured_before_a_flip(
        session: &SessionVault<'_>,
    ) -> SeamResult<()> {
        let storage = crate::code_run::ExecutorStorage::for_session(&session.session)
            .expect("capture the run's route at run entry");
        session
            .session
            .flip_on_record()
            .expect("flip the room mid-run");
        let record = crate::code_run::CodeRunReplayRecord::new(
            EntityId::now(),
            crate::code_run::CodeRunDeterminism::new(1_719_000_006_000, [0xD1; 32]),
        );
        match storage.put_code_run_replay_record_if_generation(&record, None) {
            Err(error) => Err(map_executor_error(error)),
            Ok(_) => panic!("a route captured before the flip must not commit after it"),
        }
    }

    /// ONE-1729: the same run-entry route, exercised by session MEMORY SEARCH.
    ///
    /// Search registers a retrieval-run row, so it is an apply like any other
    /// and must refuse across the flip. A search door that minted its own
    /// route would sail through here — and land base telemetry for a run whose
    /// replay record sits in an overlay that is about to evaporate.
    pub(super) fn search_through_a_route_captured_before_a_flip(
        session: &SessionVault<'_>,
    ) -> SeamResult<()> {
        let storage = crate::code_run::ExecutorStorage::for_session(&session.session)
            .expect("capture the run's route at run entry");
        session
            .session
            .flip_on_record()
            .expect("flip the room mid-run");
        match storage.search_text("anything the room might hold", 5) {
            Err(error) => Err(map_executor_error(error)),
            Ok(_) => {
                panic!("a route captured before the flip must not register telemetry after it")
            }
        }
    }

    /// ONE-1729: `witness_turn` on a MISMATCHED storage/dispatcher pair.
    ///
    /// Returns the `InvalidConfig` payload the entry refused with, or `None`
    /// when the turn was allowed — the bypass this probe hunts, since
    /// `witness_turn` writes and would otherwise reach the session's room
    /// carrying the other binding's actor without the check `run` performs.
    pub(super) fn witness_turn_with_mismatched_binding(
        vault: &Vault,
        session: &SessionVault<'_>,
    ) -> Result<Option<String>> {
        let backend = UnreachableBackend;
        let lease = crate::BudgetLease::for_test("binding-oracle");
        let mut runtime = UnreachableRuntime;
        let canonical = crate::code_run::HostSelfDispatcher::new(
            vault,
            oracle_write_actor(),
            "witness-canonical",
        )?;
        let executor = crate::engine_executor::EngineNativeExecutor::for_off_record_session(
            &session.session,
            &backend,
            &lease,
            &mut runtime,
            &canonical,
        )
        .expect("bind the executor to the live session");
        match executor.witness_turn(
            crate::off_record::ExecutorUtterance::Speak,
            "a turn the mismatched pair must never land",
            9,
        ) {
            Err(crate::engine_executor::EngineExecutorError::Engine(Error::InvalidConfig(
                message,
            ))) => Ok(Some(message)),
            Err(other) => panic!("unexpected witness refusal: {other}"),
            Ok(_) => Ok(None),
        }
    }

    /// ONE-1729: force the ONE interleave a non-atomic compare-and-set loses —
    /// a competing mutation that commits after the run's compare and before
    /// its put — and report the run's verdict (`None` = it was told it won).
    ///
    /// The interleave is the base WRITE LOCK's doing, not luck: the competitor
    /// holds the single base writer before the run is released, so the run
    /// cannot reach its transaction until that mutation has committed. A
    /// compare taken outside the transaction is therefore guaranteed stale by
    /// the time the put lands; a compare taken inside it cannot be.
    pub(super) fn replay_put_racing_a_committed_change(
        vault: &Vault,
        session: &SessionVault<'_>,
    ) -> Result<Option<crate::error::ErrorKind>> {
        use crate::code_run::{CodeRunDeterminism, CodeRunReplayRecord, ExecutorStorage};

        let storage = ExecutorStorage::for_session(&session.session)?;
        let run_id = EntityId::now();
        let record = CodeRunReplayRecord::new(
            run_id,
            CodeRunDeterminism::new(1_719_000_007_000, [0xA1; 32]),
        );
        let generation = storage.put_code_run_replay_record_if_generation(&record, None)?;
        // Keyed exactly as `code_run.rs` keys it; the competitor removes the
        // row the run believes it is updating.
        let mut key = b"code_run:replay:v1:".to_vec();
        key.extend_from_slice(run_id.as_bytes());

        let writer_held = std::sync::Barrier::new(2);
        std::thread::scope(|scope| -> Result<Option<crate::error::ErrorKind>> {
            let run = scope.spawn(|| {
                writer_held.wait();
                storage.put_code_run_replay_record_if_generation(&record, Some(generation))
            });
            vault.with_write_txn(|wtxn| {
                writer_held.wait();
                // Long enough that a compare living outside the transaction has
                // certainly run: the run thread is queued on the writer this
                // closure holds, and only a compare INSIDE that transaction can
                // still see the deletion below.
                std::thread::sleep(std::time::Duration::from_millis(150));
                vault.store.vault_meta.delete(wtxn, &key)?;
                Ok(())
            })?;
            Ok(run
                .join()
                .expect("the bound run must not panic")
                .err()
                .map(|error| error.kind()))
        })
    }

    /// ONE-1732: open a vault whose stored ABI version is `stored` with an
    /// engine whose ABI version is `engine`; Err = the fail-closed gate.
    pub(super) fn open_with_abi_pair(
        _dir: &std::path::Path,
        _stored: u16,
        _engine: u16,
    ) -> SeamResult<Vault> {
        unimplemented!("armed by ONE-1732: STORAGE_ABI_VERSION 12->13 fail-closed gate")
    }
}

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn seed_base_turn(vault: &Vault, at: u64) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            b"branch-store oracle base turn",
        )
        .expect("seed base turn");
    id
}

/// Exact row counts across all 28 named databases — the zero-residue census.
fn full_db_census(vault: &Vault) -> Result<[u64; 28]> {
    let s = &vault.store;
    let rtxn = s.env.read_txn()?;
    Ok([
        s.entities.len(&rtxn)?,
        s.edges_out.len(&rtxn)?,
        s.edges_in.len(&rtxn)?,
        s.vectors.len(&rtxn)?,
        s.hnsw_neighbors.len(&rtxn)?,
        s.hnsw_meta.len(&rtxn)?,
        s.text_postings.len(&rtxn)?,
        s.text_meta.len(&rtxn)?,
        s.text_forward.len(&rtxn)?,
        s.text_bm25_field_stats.len(&rtxn)?,
        s.text_doc_field_lengths.len(&rtxn)?,
        s.vault_meta.len(&rtxn)?,
        s.ppr_cache.len(&rtxn)?,
        s.ppr_cache_deps.len(&rtxn)?,
        s.type_index.len(&rtxn)?,
        s.temporal_occurred_start.len(&rtxn)?,
        s.temporal_occurred_end.len(&rtxn)?,
        s.temporal_learned.len(&rtxn)?,
        s.temporal_long_intervals.len(&rtxn)?,
        s.phonetic_index.len(&rtxn)?,
        s.phonetic_forward.len(&rtxn)?,
        s.short_ids.len(&rtxn)?,
        s.short_ids_reverse.len(&rtxn)?,
        {
            let mut n = 0_u64;
            for row in s.sync_state.iter(&rtxn)? {
                row?;
                n += 1;
            }
            n
        },
        s.sync_queue.len(&rtxn)?,
        s.attempt_records.len(&rtxn)?,
        s.attempt_ready.len(&rtxn)?,
        s.attempt_dedupe.len(&rtxn)?,
    ])
}

// ─── P2 · ONE-1726 — SessionOverlay substrate ────────────────────────────

/// D2/R2: merged prefix iteration equals the model oracle's exact ordered
/// sequence (boundaries included; delete-markers subtract; overlay wins on
/// key collision).
#[test]
fn overlay_prefix_iter_matches_model_order_and_boundaries() -> Result<()> {
    let base: Vec<seam::ModelRow> = vec![
        (b"p:a".to_vec(), b"base-a".to_vec()),
        (b"p:c".to_vec(), b"base-c".to_vec()),
        (b"p:e".to_vec(), b"base-e".to_vec()),
        (b"q:x".to_vec(), b"outside".to_vec()),
    ];
    let script = vec![
        seam::OverlayOp::Put(b"p:b".to_vec(), b"ov-b".to_vec()),
        seam::OverlayOp::Put(b"p:c".to_vec(), b"ov-c-wins".to_vec()),
        seam::OverlayOp::Delete(b"p:e".to_vec()),
    ];
    let harness = seam::OverlayModelHarness::new(&base, &script);
    let merged = harness.prefix_iter(b"p:")?;
    let model = harness.model_prefix_iter(b"p:");
    assert_eq!(merged.len(), 3, "exactly a, b, c survive under prefix p:");
    assert_eq!(
        merged, model,
        "merged sequence must equal the model exactly"
    );
    Ok(())
}

/// D2/R2: reverse-range direction AND `RangeBounds` edge handling vs the
/// model — Included/Excluded/Unbounded each pinned as an exact ordered
/// sequence (codex F4: `(start, end)` slices could not express the edges).
#[test]
fn overlay_rev_range_matches_model_direction_and_bounds() -> Result<()> {
    let row = |k: &[u8], v: &[u8]| (k.to_vec(), v.to_vec());
    let base: Vec<seam::ModelRow> = vec![row(b"k1", b"v1"), row(b"k3", b"v3"), row(b"k5", b"v5")];
    let script = vec![
        seam::OverlayOp::Put(b"k2".to_vec(), b"v2".to_vec()),
        seam::OverlayOp::Put(b"k4".to_vec(), b"v4".to_vec()),
    ];
    let harness = seam::OverlayModelHarness::new(&base, &script);

    // Both bounds included: full merged set, reverse key order.
    let both = (Bound::Included(&b"k1"[..]), Bound::Included(&b"k5"[..]));
    let merged = harness.rev_range(both)?;
    assert_eq!(
        merged,
        vec![
            row(b"k5", b"v5"),
            row(b"k4", b"v4"),
            row(b"k3", b"v3"),
            row(b"k2", b"v2"),
            row(b"k1", b"v1"),
        ],
        "included/included must yield all five rows, newest key first"
    );
    assert_eq!(merged, harness.model_rev_range(both), "model agrees");

    // Excluded start bound: k1 itself must NOT surface (an overlay row k2
    // sits directly above the excluded edge — the merge must not readmit
    // the boundary key).
    let excl_start = (Bound::Excluded(&b"k1"[..]), Bound::Included(&b"k4"[..]));
    let merged = harness.rev_range(excl_start)?;
    assert_eq!(
        merged,
        vec![row(b"k4", b"v4"), row(b"k3", b"v3"), row(b"k2", b"v2")],
        "excluded start must drop exactly the boundary row"
    );
    assert_eq!(merged, harness.model_rev_range(excl_start), "model agrees");

    // Unbounded end: iteration runs to the last key in the union.
    let unbounded_end = (Bound::Included(&b"k3"[..]), Bound::Unbounded);
    let merged = harness.rev_range(unbounded_end)?;
    assert_eq!(
        merged,
        vec![row(b"k5", b"v5"), row(b"k4", b"v4"), row(b"k3", b"v3")],
        "unbounded end must run to the union's last key"
    );
    assert_eq!(
        merged,
        harness.model_rev_range(unbounded_end),
        "model agrees"
    );
    Ok(())
}

/// D2 (availability invariant, R2): merged `text_postings` duplicate items
/// stay strictly ascending by entity-id prefix per term — `search_text`
/// hard-errors the whole query on any violation, so this is availability,
/// not ranking quality.
#[test]
fn text_postings_merge_keeps_per_term_ascending_entity_id_order() -> Result<()> {
    // Base carries entities 02 and 04 for the term; overlay adds 01, 03, 05
    // — interleaved on both sides of every base item.
    let term = b"term".to_vec();
    let entry = |id: u8| -> Vec<u8> {
        let mut e = vec![0_u8; 16];
        e[15] = id;
        e.push(0); // field_count = 0 is enough for ordering shape
        e
    };
    let base: Vec<seam::ModelRow> = vec![(term.clone(), entry(2)), (term.clone(), entry(4))];
    let script = vec![
        seam::OverlayOp::DupAppend(term.clone(), entry(3)),
        seam::OverlayOp::DupAppend(term.clone(), entry(1)),
        seam::OverlayOp::DupAppend(term.clone(), entry(5)),
    ];
    let harness = seam::OverlayModelHarness::new(&base, &script);
    let items = harness.dup_items(&term)?;
    assert_eq!(items.len(), 5, "all five duplicate items must surface");
    let expected: Vec<Vec<u8>> = vec![entry(1), entry(2), entry(3), entry(4), entry(5)];
    assert_eq!(
        items, expected,
        "duplicate items must be strictly ascending by entity-id prefix"
    );
    Ok(())
}

/// D1 (txn segments): a write staged in the thread-local segment is visible
/// to reads under the SAME live base txn (segment -> snapshot -> base).
#[test]
fn overlay_read_your_writes_inside_txn_segment() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-ryw").expect("enter session");
    let script = vec![seam::OverlayOp::Put(
        b"ryw-key".to_vec(),
        b"ryw-val".to_vec(),
    )];
    let read_back = seam::with_txn_segment_read_back(&vault, &session, &script, b"ryw-key")?;
    assert_eq!(
        read_back.as_deref(),
        Some(&b"ryw-val"[..]),
        "batch code must read what it just wrote inside the live txn"
    );
    Ok(())
}

/// D1 (journal atomicity): a segment dropped on base-txn abort leaves ZERO
/// overlay rows and ZERO typed-journal entries.
#[test]
fn overlay_segment_and_journal_drop_together_on_abort() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-abort").expect("enter session");
    let script = vec![seam::OverlayOp::Put(b"aborted".to_vec(), b"x".to_vec())];
    let (overlay_rows, journal_entries) = seam::stage_then_abort(&vault, &session, &script)?;
    assert_eq!(
        overlay_rows, 0,
        "aborted segment must not apply to the overlay"
    );
    assert_eq!(
        journal_entries, 0,
        "journal is atomic with the overlay apply"
    );
    Ok(())
}

/// D1 (vault-safety fence): budget overflow returns the typed error, the
/// base vault is untouched, and the session stays alive for promote/close.
#[test]
fn overlay_budget_rejection_is_typed_and_never_crashes_vault() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let base_before = full_db_census(&vault)?;
    let session =
        seam::SessionVault::enter_with_budget(&vault, "oracle-budget", 64).expect("enter session");
    let error = seam::overflow_budget(&vault, &session, 64);
    assert_eq!(
        error,
        seam::SeamError::OverlayFull,
        "budget overflow must be the exact typed OffRecordOverlayFull refusal"
    );
    assert_eq!(
        full_db_census(&vault)?,
        base_before,
        "a rejected overlay insert must leave every base database untouched"
    );
    // Session survives: close still works and reports zero retained rows.
    let (transcript_deleted, receipts_deleted, _floor_kept) = session.close()?;
    assert_eq!(transcript_deleted, 0);
    assert_eq!(receipts_deleted, 0);
    Ok(())
}

/// D1 (snapshot isolation): a logical read iterates its Arc snapshot; a
/// concurrent overlay apply is invisible to it and visible to a fresh read.
#[test]
fn overlay_snapshot_read_never_sees_torn_union() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-snapshot").expect("enter session");
    let script = vec![seam::OverlayOp::Put(b"s:new".to_vec(), b"late".to_vec())];
    let (snapshot_rows, fresh_rows) =
        seam::snapshot_vs_concurrent_apply(&vault, &session, &script, b"s:")?;
    assert_eq!(snapshot_rows.len(), 0, "snapshot predates the apply");
    assert_eq!(
        fresh_rows,
        vec![(b"s:new".to_vec(), b"late".to_vec())],
        "fresh read sees exactly the applied (key, value) row — identity, \
         not just count (codex F5)"
    );
    Ok(())
}

/// D1 (close finality): generation-stamped leases refuse typed after close.
#[test]
fn overlay_lease_refused_after_close() {
    let (_tmp, vault) = temp_vault();
    assert_eq!(
        seam::read_after_close(&vault, "oracle-lease"),
        seam::SeamError::LeaseClosed,
        "stale handles must get the exact typed lease refusal"
    );
}

// ─── P3 · ONE-1727 — session lifecycle ────────────────────────────────────

/// R1: direct substrate writes and typed-journal entries are process-local.
/// Dropping every handle without close simulates a crash: reopening the same
/// path must show exact census equality across all 28 base DBs, and the
/// process-local session ref must be free for reuse.
#[test]
fn direct_substrate_crash_evaporation_leaves_zero_base_residue() -> Result<()> {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    let census_before = full_db_census(&vault)?;
    let session = seam::SessionVault::enter(&vault, "oracle-native-crash").expect("enter session");
    assert_eq!(
        seam::stage_direct_crash_payload(&session)?,
        (2, 1, 1, 2),
        "the crash fixture must contain exact overlay rows and journal ops"
    );

    drop(session);
    drop(vault);

    let reopened = Vault::open(tmp.path(), VaultConfig::default()).expect("reopen vault");
    assert_eq!(
        full_db_census(&reopened)?,
        census_before,
        "direct session writes must leave zero residue in all 28 base databases"
    );
    assert!(
        seam::SessionVault::enter(&reopened, "oracle-native-crash").is_ok(),
        "the evaporated session ref must read as free after reopen"
    );
    Ok(())
}

/// §4 master close test: transcript + context receipts deleted, floor
/// receipts kept (RECEIPTS-FOLLOW-TRANSCRIPT).
///
/// Both halves of the contract run in ONE room, because they are one
/// contract: close must delete the transcript AND spare the floor. A room
/// with no floor crossing proves only that close deletes — a close that
/// evaporated the floor along with everything else would pass it. So the
/// room makes exactly one durable crossing (`FloorWrites`, K1 op 1/3)
/// immediately before close, and the assertion is `floor_receipts_kept == 1`
/// while the transcript and receipt counts continue to hold.
#[test]
fn master_close_deletes_transcript_and_context_receipts_keeps_floor_receipts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-close").expect("enter session");
    // The witness door requires a base-resident actor, so bind it BEFORE the
    // baseline: the room must be charged for its own rows, not for its actor.
    session.bind_actor()?;
    let base_before = full_db_census(&vault)?;
    let (_turn, _msg, _summary) = session.witness_turn("close me")?;
    let _hits = session.search_text("close", 5)?;

    // ONE floor crossing, last thing before close: the row is durable by
    // design and is exactly what must NOT follow the transcript out.
    let floor_before = vault.store.gate_decisions(1_000)?.len();
    session.append_floor_egress_decision()?;
    assert_eq!(
        vault.store.gate_decisions(1_000)?.len(),
        floor_before + 1,
        "the crossing landed exactly one durable decision row"
    );

    let (transcript_deleted, context_receipts_deleted, floor_receipts_kept) = session.close()?;
    assert_eq!(transcript_deleted, 3, "turn + message + summary evaporate");
    assert_eq!(
        context_receipts_deleted, 1,
        "the retrieval-run receipt follows"
    );
    assert_eq!(
        floor_receipts_kept, 1,
        "the floor crossing SURVIVES the close that evaporated the room \
         around it — receipts follow the transcript, floor rows do not"
    );

    // Base is the baseline PLUS exactly the floor row: one `vault_meta` row
    // (this decision carries no grant_ref and no claim_id, so it writes no
    // index rows). Everything the room itself wrote is gone.
    let base_after = full_db_census(&vault)?;
    let mut expected = base_before;
    expected[11] += 1;
    assert_eq!(
        base_after, expected,
        "close leaves base as it was before the room, plus the one floor row"
    );
    Ok(())
}

/// §2/R4 crash = evaporation: dropping the process without close leaves
/// ZERO residue in any of the 28 base databases; the session reads as
/// not-found after reopen.
#[test]
fn crash_evaporation_leaves_zero_base_residue() -> Result<()> {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    let mut session = seam::SessionVault::enter(&vault, "oracle-crash").expect("enter session");
    session.bind_actor()?;
    let census_before = full_db_census(&vault)?;
    let (_turn, _msg, _summary) = session.witness_turn("evaporates")?;
    // THE CRASH: the session handle is dropped without `close()`, so no
    // close path, no evaporation bookkeeping, no receipt census runs.
    drop(session);
    let reopened = seam::crash_and_reopen(tmp.path(), vault)?;
    assert_eq!(
        full_db_census(&reopened)?,
        census_before,
        "no durable session trace may exist after a crash"
    );
    assert!(
        seam::SessionVault::enter(&reopened, "oracle-crash").is_ok(),
        "the session ref reads as free (not-found) after crash evaporation"
    );
    Ok(())
}

/// R10 kill-switch: `off_record_enabled = false` makes enter fail closed
/// with a typed error; no registry entry is created.
#[test]
fn kill_switch_makes_enter_fail_closed() {
    let (_tmp, vault) = temp_vault();
    let refused = seam::SessionVault::enter_with_kill_switch_off(&vault, "oracle-kill");
    assert_eq!(
        refused.err(),
        Some(seam::SeamError::KillSwitchDisabled),
        "enter must fail closed with the exact typed kill-switch refusal"
    );
}

/// §1a enter is single-shot per live session ref.
#[test]
fn enter_is_single_shot_per_session_ref() {
    let (_tmp, vault) = temp_vault();
    let _first = seam::SessionVault::enter(&vault, "oracle-single").expect("first enter");
    let second = seam::SessionVault::enter(&vault, "oracle-single");
    assert_eq!(
        second.err(),
        Some(seam::SeamError::SessionRefLive),
        "re-entering a live session ref must be the exact typed refusal"
    );
}

// ─── P4a · ONE-1728 — witness/retrieval, embedding rule, taint guard ─────

/// §4 base-leak sweep: every base reader family sees NOTHING of a populated
/// overlay. Family list mined from the wave-1 fence findings ledger:
/// `get_raw`-class raw reads FIRST (the R20 P1), then search/short-id (R14),
/// edge readers (R7), existence/enumeration + tree walks (R18),
/// `edge_exists` (R19), ScopedRead reads (R10), telemetry.
#[test]
fn base_leak_sweep_every_reader_family_sees_no_overlay_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let base_turn = seed_base_turn(&vault, 1_000);
    let mut session = seam::SessionVault::enter(&vault, "oracle-sweep").expect("enter session");
    let actor = session.bind_actor()?;
    let learned_before: std::collections::BTreeSet<_> = vault
        .entities_in_learned_range(0, u64::MAX)?
        .into_iter()
        .collect();
    let runs_before = vault.store.retrieval_runs(100)?.len();
    let short_id_rows_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.short_ids.len(&rtxn)?
    };
    let (turn, message, summary) = session.witness_turn("oraclesweepuniquetoken")?;

    // get_raw-class raw reads FIRST (ledger R20 P1: Vault::get_raw).
    assert_eq!(vault.get_raw(&turn)?, None, "get_raw must not see the room");
    assert_eq!(vault.get(&turn)?, None, "get must not see the room");
    assert!(vault.read_entity_header(&turn)?.is_none());

    // Existence / enumeration (ledger R18 family).
    assert!(!vault.entity_exists(&turn)?);
    assert!(vault.get_learned_at(&turn).is_err());
    let turns = vault.entities_by_type(crate::registry::ENTITY_TYPE_TURN)?;
    assert_eq!(
        turns,
        vec![base_turn],
        "type enumeration returns exactly the base turn"
    );
    // Baseline-relative, not absolute: `Vault::open` seeds its own rows (a
    // POLICY_MANIFEST among them), so the honest assertion is that the room
    // adds NOTHING to what base held before it — not that base holds some
    // hardcoded count.
    let learned: std::collections::BTreeSet<_> = vault
        .entities_in_learned_range(0, u64::MAX)?
        .into_iter()
        .collect();
    assert_eq!(
        learned, learned_before,
        "learned-range enumeration is unchanged by the room"
    );
    assert!(
        learned.contains(&actor) && learned.contains(&base_turn),
        "the baseline itself must still hold the seeded base rows"
    );

    // Edge readers + edge existence (ledger R7/R19 families).
    assert_eq!(
        vault
            .targets(&message, crate::edge::EdgeKind::PartOf, None)?
            .len(),
        0,
        "edge readers must not traverse session edges"
    );
    assert!(!vault.edge_exists(&message, crate::edge::EdgeKind::PartOf, &turn)?);

    // Tree walks (ledger R18: subtree/ancestors raw ChildOf walks).
    assert_eq!(vault.subtree(&turn, 4)?.len(), 0);
    assert_eq!(vault.ancestors(&turn)?.len(), 0);

    // Search (ledger R14 family). The token exists only in-room.
    assert_eq!(vault.search_text("oraclesweepuniquetoken", 10)?.len(), 0);

    // Short-id resolver (ledger R14 family): the room's session-local short
    // ref must not resolve through the BASE resolver, and the base
    // `short_ids` table must not have grown a row for it.
    let (session_short_id, session_hash) = session.session_short_ref(&turn)?;
    assert_eq!(
        vault
            .hydrate_short_id(&session_short_id, session_hash)?
            .map(|hydrated| hydrated.id),
        None,
        "session-local short ids must be invisible to the base resolver"
    );
    assert_eq!(
        {
            let rtxn = vault.store.env.read_txn()?;
            vault.store.short_ids.len(&rtxn)?
        },
        short_id_rows_before,
        "the base short_ids table must not grow from session allocations"
    );

    // ScopedRead family (ledger R10): a base-side scoped read surfaces zero
    // claims for the room's subject. The session side is asserted too — the
    // sweep's contract is "canonical sees base only, session sees the union",
    // and only checking the base half would also pass if the session handle
    // were blind.
    assert_eq!(
        seam::base_scoped_read_visible_claim_count(&vault, &turn)?,
        0,
        "base ScopedRead must surface zero claims for session content"
    );
    assert_eq!(
        session.session_scoped_read_visible_claim_count(&turn)?,
        0,
        "the room staged no claims, so its own ScopedRead surfaces none either"
    );

    // Telemetry: the base retrieval-run ledger gained EXACTLY the probe's
    // own row and nothing from the room. Base `search_text` persists one
    // retrieval-run row even for zero hits (pre-existing design oracle:
    // pipeline/tests.rs:973); ONE-1728's "retrieval-run rows land in the
    // overlay" governs SESSION-side reads only.
    assert_eq!(
        vault.store.retrieval_runs(100)?.len(),
        runs_before + 1,
        "base ledger delta must be exactly the base probe's own telemetry row"
    );

    // The union half: an IN-ROOM retrieval registers a row the room can read
    // back, while the base ledger above stays flat. Both directions matter —
    // "base gains nothing" alone would also hold if the row were dropped.
    let room_runs_before = session.retrieval_run_count()?;
    let _ = session.search_text("oraclesweepuniquetoken", 5)?;
    assert_eq!(
        session.retrieval_run_count()?,
        room_runs_before + 1,
        "a session retrieval registers exactly one overlay-local run row"
    );
    assert_eq!(
        vault.store.retrieval_runs(100)?.len(),
        runs_before + 1,
        "and the base telemetry ledger gains NOTHING from the in-room run"
    );

    // The summary carrier is equally invisible (fence transitivity class).
    assert_eq!(vault.get(&summary)?, None);

    session.close()?;
    Ok(())
}

/// Writes a CLAIM entity row plus its type-index row straight into base.
///
/// Bypassing every write door is the point: after the session door learned to
/// validate claim bodies (S1), a raw plant is the only way left to put a body
/// in the store that the validators would have refused — which is exactly the
/// state the census below has to be honest about.
fn plant_raw_claim_row(vault: &Vault, id: &EntityId, body: &[u8]) -> Result<()> {
    let mut raw = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + body.len());
    raw.push(crate::registry::ENTITY_TYPE_CLAIM);
    raw.extend_from_slice(&1_u64.to_be_bytes()); // occurred.start
    raw.extend_from_slice(&1_u64.to_be_bytes()); // occurred.end
    raw.extend_from_slice(&1_u64.to_be_bytes()); // learned_at
    raw.extend_from_slice(body);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &raw)?;
        let type_key = crate::store::Store::encode_type_key(crate::registry::ENTITY_TYPE_CLAIM, id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

/// The ScopedRead census SURFACES a claim body it cannot decode; it never
/// quietly lowers the count.
///
/// The count is EVIDENCE — the base and session halves of the R10 reader
/// family are compared for EQUALITY — so a silently partial count is worse
/// than no count at all: two halves that both drop the same unreadable row
/// report an agreement neither of them observed. `Err` is the only honest
/// answer to "how many claims are visible" when one of the rows cannot be
/// read at all.
#[test]
fn scoped_read_claim_census_surfaces_an_undecodable_body() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = seed_base_turn(&vault, 10);

    // Positive control FIRST: the census really does read bodies, so the
    // refusal below cannot pass vacuously on an empty enumeration.
    let legal = crate::claim::encode_claim_body(&crate::claim::ClaimBody::new(
        "dream.symbol",
        crate::claim::ClaimSubject::Entity(subject),
        rmpv::Value::from("a blue door"),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    ))?;
    plant_raw_claim_row(&vault, &EntityId::now(), &legal)?;
    assert_eq!(
        seam::base_scoped_read_visible_claim_count(&vault, &subject)?,
        1,
        "the census must count a legal planted claim"
    );

    // A row whose header and type byte are both perfectly well formed and
    // whose BODY is not MessagePack at all.
    plant_raw_claim_row(&vault, &EntityId::now(), b"not a claim body")?;
    let refused = seam::base_scoped_read_visible_claim_count(&vault, &subject)
        .expect_err("an undecodable claim body must surface, never lower the count");
    assert_eq!(refused.kind(), crate::error::ErrorKind::InvalidClaimBody);
    Ok(())
}

/// D3 embedding rule: session flows never enqueue `pe:` markers or embed
/// job rows (base rows carrying raw text); generalized — no background
/// attempt rows reference overlay content.
///
/// The room stages a CLAIM, because CLAIM is the ONLY entity class the base
/// apply marks pending-embed (`batch.rs` op-loop CLAIM arm). A TURN/MESSAGE
/// witness alone would satisfy every assertion below even if the session path
/// enqueued freely, since neither type ever reaches the marker branch on
/// EITHER path — the test would be green for the wrong reason.
#[test]
fn no_pe_markers_or_embed_job_rows_for_session_content() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-embed").expect("enter session");
    session.bind_actor()?;
    let attempts_before = seam::attempt_row_counts(&vault)?;
    // No summary: the smallest witness program that still drives the session
    // write path, so nothing about this assertion rides on a second Text op.
    let (turn, message) = session.witness_turn_without_summary("embed me inline only")?;
    // The op the rule is actually about. Staged against the turn as subject
    // so the claim is genuine turn-scoped room content.
    let claim = session.stage_session_claim(&turn)?;
    // The claim REALLY landed in the room and nowhere else. Without this, a
    // staging call that silently wrote nothing would make every assertion
    // below trivially true — the failure mode this whole oracle exists to
    // catch, inverted.
    assert!(
        session.session_sees_entity(&claim)?,
        "the staged CLAIM is readable through the room's composed view"
    );
    assert_eq!(
        vault.get(&claim)?,
        None,
        "and base sees nothing of it — the claim is room content, so K6's \
         'zero jobs' claim below is about a row that actually exists"
    );

    let rtxn = vault.store.env.read_txn()?;
    let mut pe_rows = 0_usize;
    for row in vault.store.sync_state.prefix_iter(&rtxn, "pe:")? {
        row?;
        pe_rows += 1;
    }
    drop(rtxn);
    assert_eq!(
        pe_rows, 0,
        "no pe: pending-embedding marker for session content, INCLUDING the \
         staged CLAIM — the one op class base would have marked"
    );

    // All three background-job tables, not just `attempt_records`: a job whose
    // record row were suppressed while its ready/dedupe rows landed would
    // still be the room reaching the background worker.
    assert_eq!(
        seam::attempt_row_counts(&vault)?,
        attempts_before,
        "session flows create zero rows in attempt_records / attempt_ready / \
         attempt_dedupe"
    );

    // The reference half of the done-means: table counts alone would also pass
    // on a vault that merely held no jobs. This asks whether ANY job row —
    // embed queue, pe: marker, or attempt table — names one of the room's ids.
    assert_eq!(
        seam::job_rows_referencing(&vault, &[turn, message, claim])?,
        0,
        "no background job row may reference an overlay id"
    );

    session.close()?;
    Ok(())
}

/// D2 taint guard: a BASE batch op referencing a live-overlay id is
/// rejected atomically at the batch preflight (ports the spirit of
/// `production_summary_batch_rejects_a_live_fenced_source_atomically`).
#[test]
fn taint_guard_rejects_base_write_referencing_live_overlay_id() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-taint").expect("enter session");
    session.bind_actor()?;
    let (turn, _msg, _summary) = session.witness_turn("tainted")?;
    // The probe's own source is base setup, seeded before the census so the
    // census measures ONLY what the rejected batch would have written.
    let probe_source = seed_base_turn(&vault, 2_000);
    let census_before = full_db_census(&vault)?;
    let refused = seam::base_batch_referencing_overlay_id(&vault, &probe_source, &turn);
    assert_eq!(
        refused,
        Err(seam::SeamError::TaintedBaseWrite),
        "taint guard must reject with the exact typed refusal"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "the rejected batch must be atomic — zero base rows written"
    );
    session.close()?;
    Ok(())
}

/// D6: write-path gate decisions for session content stay overlay-local —
/// the base gate-decision ledger gains zero rows from the room.
#[test]
fn session_gate_decisions_never_persist_in_base() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let ledger_before = vault.store.gate_decisions(1_000)?.len();
    let mut session = seam::SessionVault::enter(&vault, "oracle-gate").expect("enter session");
    session.bind_actor()?;
    let (_turn, _msg, _summary) = session.witness_turn("gated in-room")?;
    session.close()?;
    assert_eq!(
        vault.store.gate_decisions(1_000)?.len(),
        ledger_before,
        "session write-path decisions must never reach the base ledger"
    );
    Ok(())
}

/// D5 mode flip: earlier off-record turns stay unextractable through base
/// readers AFTER flipping on-record (reads stay composed in-session only).
#[test]
fn off_record_turns_stay_unextractable_after_mode_flip() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-flip").expect("enter session");
    session.bind_actor()?;
    let (turn, _msg, _summary) = session.witness_turn("preflipsecret")?;

    // A route minted while OFF record names the pre-flip mode epoch.
    let stale_route = session.write_route()?;

    session.flip_on_record()?;
    assert_eq!(vault.get(&turn)?, None, "pre-flip turn stays out of base");
    assert_eq!(vault.search_text("preflipsecret", 10)?.len(), 0);

    // K10: the pre-flip route is refused by its OWN revalidation, with the
    // typed stale-route family — not silently honored against a mode the
    // caller no longer believes it is in.
    assert!(
        matches!(
            stale_route.revalidate(),
            Err(crate::error::Error::OffRecordOverlayLeaseClosed { .. })
        ),
        "a route minted before the flip must be refused by revalidate"
    );

    // Post-flip witness lands in BASE under the continuation shell, carrying
    // zero overlay references.
    let base_entities_after_flip = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.entities.len(&rtxn)?
    };
    let (base_turn, _, _) = session.witness_turn("postflippublic")?;
    assert!(
        vault.get(&base_turn)?.is_some(),
        "an on-record session witness lands in base"
    );
    assert!(
        {
            let rtxn = vault.store.env.read_txn()?;
            vault.store.entities.len(&rtxn)? > base_entities_after_flip
        },
        "the post-flip witness grew the base entity table"
    );

    // Flip BACK: new writes route to the overlay again, and the pre-flip
    // turns are still base-invisible.
    session.flip_off_record()?;
    let (reflip_turn, _, _) = session.witness_turn("postflipbacksecret")?;
    assert_eq!(
        vault.get(&reflip_turn)?,
        None,
        "after flip-back, new writes route to the overlay again"
    );
    assert_eq!(
        vault.get(&turn)?,
        None,
        "pre-flip turn is STILL out of base"
    );
    assert_eq!(vault.search_text("preflipsecret", 10)?.len(), 0);
    assert_eq!(vault.search_text("postflipbacksecret", 10)?.len(), 0);

    session.close()?;
    Ok(())
}

// ─── P4b · ONE-1729 — executor binding keeps effect-level policy ─────────

/// Every durable memory verb ONE-1729's effect policy names.
const DURABLE_MEMORY_WRITE_VERBS: [&str; 4] = [
    "MemoryPutClaim",
    "MemorySupersedeClaim",
    "MemoryPutEdge",
    "MemoryWriteFixture",
];

/// D6: durable-memory-write verbs stay POLICY-rejected off-record — a plain
/// overlay-backed dispatcher would wrongly allow them ephemerally.
///
/// Each probe brackets the PUBLIC dispatch call: the census is captured
/// immediately before and immediately after the refusal, so the delta names
/// exactly what the forbidden effect did — base rows, gate decisions, pending
/// consent, and replay rows alike, since `full_db_census` counts `vault_meta`
/// where all three live. The check itself is module-private; bracketing
/// dispatch is the observable equivalent.
#[test]
fn durable_memory_write_verbs_stay_policy_rejected_off_record() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-policy").expect("enter session");
    session.bind_actor()?;
    for verb in DURABLE_MEMORY_WRITE_VERBS {
        let census_before = full_db_census(&vault)?;
        let session_before = session.session_artifact_census()?;
        assert_eq!(
            session.dispatch_executor_verb(verb),
            Err(seam::SeamError::PolicyMemoryWrite),
            "durable-memory verb {verb} must reject as the exact typed policy \
             refusal, not routing"
        );
        assert_eq!(
            full_db_census(&vault)?,
            census_before,
            "{verb} rejected off-record must leave zero base delta"
        );
        assert_eq!(
            session.session_artifact_census()?,
            session_before,
            "{verb} rejected off-record must leave zero OVERLAY delta either — \
             the answer is refusal, not ephemeral acceptance"
        );
    }
    session.close()?;
    Ok(())
}

/// D6, the other half: the same four verbs take the ORDINARY path once the
/// bound live session is on record, which is what makes the rejection above
/// mode-scoped POLICY rather than a permanent property of the dispatcher or a
/// side effect of overlay routing.
///
/// ONE-1936's stale-target guard is NOT on this merge base (implement-time
/// census: `dispatch_memory_supersede_claim` reaches
/// `supersede_claim_for_code_run_trap` with no target walk), so the partition
/// is asserted STRUCTURALLY: off record, the effect-policy refusal fires
/// before the supersede write transaction is ever entered, which the
/// zero-delta brackets above already prove.
#[test]
fn durable_memory_write_verbs_take_the_ordinary_path_after_flip() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-policy-flip").expect("enter");
    let actor = session.bind_actor()?;
    session.flip_on_record()?;

    // NOT ONE of the four still meets the effect policy. What answers now is
    // whatever the ORDINARY path answers — for the three gated verbs that is
    // the write gate, whose verdict is not an off-record concern and must not
    // be read as one.
    let claims_before = vault
        .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
        .len();
    for verb in DURABLE_MEMORY_WRITE_VERBS {
        assert_ne!(
            session.executor_verb_error_kind(verb),
            Some(crate::error::ErrorKind::OffRecordTalkOnly),
            "{verb} must no longer meet the off-record effect policy on record"
        );
    }
    // `MemoryWriteFixture` takes the ungated batch path, so it is the verb
    // that shows the ordinary route COMPLETING through the bound Session
    // storage rather than through `self.vault`. Asserted by IDENTITY, not by
    // a count: the gated verbs above also moved rows, and a count would let
    // one of them stand in for the row actually under test.
    let fixture_claim = session.dispatch_fixture_write()?;
    assert!(
        vault.get_claim(&fixture_claim)?.is_some(),
        "the on-record fixture write landed in base through the bound storage"
    );
    assert!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
            .len()
            > claims_before,
        "and the base claim table grew rather than staying ephemeral"
    );
    assert!(
        vault.get(&actor)?.is_some(),
        "the bound actor is a base row throughout"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729 (R-20260807-02): guest-supplied turn_ref is rejected typed,
/// BEFORE construction, in both modes.
#[test]
fn guest_supplied_turn_ref_rejected() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-guest").expect("enter session");
    session.bind_actor()?;

    for mode in ["off-record", "post-flip on-record"] {
        let census_before = full_db_census(&vault)?;
        let session_before = session.session_artifact_census()?;
        let refused = session.dispatch_executor_verb("GuestTurnRef");
        assert_eq!(
            refused,
            Err(seam::SeamError::GuestTurnRef),
            "guest turn_ref must reject with the exact typed refusal ({mode})"
        );
        // Pre-CONSTRUCTION: no WitnessTurn was formed, so there is nothing to
        // roll back — not in base, not in the room.
        assert_eq!(
            full_db_census(&vault)?,
            census_before,
            "the refusal must precede every base write ({mode})"
        );
        assert_eq!(
            session.session_artifact_census()?,
            session_before,
            "the refusal must precede every overlay write ({mode})"
        );
        session.flip_on_record()?;
    }
    session.close()?;
    Ok(())
}

/// ONE-1729: executor speak-turns and code-run artifacts are overlay
/// members — present in-session, absent from base.
///
/// `bind_actor` runs BEFORE the census: the witness door proves its actor
/// exists in base before it writes, so that one row is baseline rather than
/// residue the executor appears to have left behind.
#[test]
fn executor_artifacts_and_speak_turns_live_in_overlay_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-exec").expect("enter session");
    session.bind_actor()?;
    let census_before = full_db_census(&vault)?;
    session
        .dispatch_executor_verb("Speak")
        .expect("speak is talk-only-legal off-record");
    // Positive half (codex F8): the artifacts EXIST through the session
    // view — a no-op dispatcher must fail here.
    assert_eq!(
        session.session_artifact_census()?,
        (1, 1, 1),
        "exactly one speak turn, one replay record, one raw-output row \
         must exist through the session view"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "speak turns / replay records / raw outputs must not land in base"
    );
    // The shell is a fresh 32-hex EntityId owned by the session, never the
    // reusable `session_ref` string, and the dispatcher READS it rather than
    // minting one per bind.
    let shells = session.session_message_shells()?;
    assert_eq!(shells.len(), 1, "the room is ONE conversation");
    assert_eq!(
        session.dispatcher_container_id()?,
        Some(shells[0]),
        "the executor's container is the session-owned shell"
    );
    assert_ne!(
        shells[0].to_hex(),
        "oracle-exec",
        "the shell is an entity id, not the session ref"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729 K-EXEC: all three utterance kinds go through the SAME session-side
/// witness entry and reuse exactly one session-bound shell across verbs and
/// across executor runs — the door is the only place turn events are formed.
#[test]
fn executor_utterances_share_one_session_shell() -> Result<()> {
    use crate::off_record::ExecutorUtterance;

    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-utterance").expect("enter");
    session.bind_actor()?;
    let census_before = full_db_census(&vault)?;

    for kind in [
        ExecutorUtterance::Speak,
        ExecutorUtterance::Think,
        ExecutorUtterance::Express,
    ] {
        session.witness_executor_utterance(kind, "in-room utterance", None)?;
    }
    // A second bound run, to prove the shell is the SESSION's and not the
    // run's: a per-run shell would show up as a second conversation here.
    session.dispatch_executor_verb("Speak").expect("second run");

    assert_eq!(
        session.session_artifact_census()?.0,
        4,
        "three utterances plus the second run's turn, all in-room"
    );
    assert_eq!(
        session.session_message_shells()?.len(),
        1,
        "one shell across every utterance kind and both runs"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "no utterance reaches base, and none is visible to a canonical reader"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729: an unknown ref and a handle that outlived its room fail with
/// DISTINCT typed refusals, and neither leaves anything behind.
#[test]
fn binding_a_dead_session_refuses_distinctly() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let census_before = full_db_census(&vault)?;
    assert_eq!(
        seam::bind_session(&vault, "never-entered"),
        Err(seam::SeamError::SessionNotFound),
        "an unknown session ref must name itself as not found"
    );
    let (stale, rebind) = seam::stale_handle_and_rebind_refusals(&vault, "oracle-bind-closed");
    assert_eq!(
        stale,
        seam::SeamError::SessionClosing,
        "a handle bound before close must refuse as closing, never write into a dead room"
    );
    assert_eq!(
        rebind,
        seam::SeamError::SessionNotFound,
        "and rebinding the same ref afterwards is a DIFFERENT refusal"
    );
    assert_ne!(
        stale, rebind,
        "the two bind refusals must stay variant-discriminable"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "a refused bind creates no registry entry, overlay, replay row, raw \
         output, turn, or gate decision"
    );
    Ok(())
}

/// ONE-1729: the executor refuses a mismatched storage/dispatcher pair at RUN
/// ENTRY, before `load_or_create_record` and before any read or write — in
/// BOTH directions, and even when the session refs compare equal because two
/// different vaults answer to the same binding.
#[test]
fn executor_refuses_mismatched_storage_dispatcher_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_other_tmp, other_vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-binding").expect("enter session");
    let census_before = full_db_census(&vault)?;

    for direction in seam::binding_mismatch_directions(&vault, &session, &other_vault)? {
        assert_eq!(
            direction.refusal.as_deref(),
            Some("executor storage/dispatcher binding mismatch"),
            "{} must refuse at run entry with the typed binding error",
            direction.name
        );
    }
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "a refused binding writes nothing"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729 (R-20260807-02 rider 2): the run's route is captured ONCE at run
/// entry; a flip before the apply is refused by that route's OWN revalidation
/// with the typed stale-route family, leaving the pre-flip room intact.
///
/// A path that silently re-minted a route per apply would pass the write here
/// and split the record across the flip; that is precisely what this refuses.
#[test]
fn run_entry_route_refuses_an_apply_across_a_mid_run_flip() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session = seam::SessionVault::enter(&vault, "oracle-route").expect("enter session");
    session.bind_actor()?;
    session
        .dispatch_executor_verb("Speak")
        .expect("pre-flip run");
    let room_before = session.session_artifact_census()?;
    let census_before = full_db_census(&vault)?;

    let refused = seam::apply_through_a_route_captured_before_a_flip(&session);
    assert_eq!(
        refused,
        Err(seam::SeamError::LeaseClosed),
        "the run-entry route must refuse its own apply after a mode flip"
    );
    assert_eq!(
        session.session_artifact_census()?,
        room_before,
        "the pre-flip room is intact — not split state"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "and nothing crossed into base under the stale route"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729: session `MemorySearch` applies through the run's captured route
/// too — its retrieval-run row is a durable write, so a mid-run flip refuses
/// it exactly as it refuses a replay write.
///
/// A search door that minted its own route would pass here while every
/// neighbouring apply on the same run refused, and would leave base telemetry
/// behind for a run whose record evaporates.
#[test]
fn run_entry_route_refuses_a_search_across_a_mid_run_flip() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-search-route").expect("enter session");
    let census_before = full_db_census(&vault)?;

    let refused = seam::search_through_a_route_captured_before_a_flip(&session);
    assert_eq!(
        refused,
        Err(seam::SeamError::LeaseClosed),
        "the run-entry route must refuse its own search after a mode flip"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "and no retrieval telemetry crossed into base under the stale route"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729: `witness_turn` refuses a mismatched storage/dispatcher pair
/// before it writes, because it is a write-capable entry point in its own
/// right — a pair that never calls `run` must not be able to land a turn.
#[test]
fn executor_witness_turn_refuses_a_mismatched_binding() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut session =
        seam::SessionVault::enter(&vault, "oracle-witness-binding").expect("enter session");
    session.bind_actor()?;
    let room_before = session.session_artifact_census()?;
    let census_before = full_db_census(&vault)?;

    assert_eq!(
        seam::witness_turn_with_mismatched_binding(&vault, &session)?.as_deref(),
        Some("executor storage/dispatcher binding mismatch"),
        "a write-capable entry point must run the binding check itself"
    );
    assert_eq!(
        session.session_artifact_census()?,
        room_before,
        "a refused witness leaves the room untouched"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_before,
        "and writes nothing to base"
    );
    session.close()?;
    Ok(())
}

/// ONE-1729: the session replay compare-and-set is ATOMIC, like its canonical
/// sibling — the compare reads inside the transaction that writes.
///
/// Two bound runs holding the same expected generation must not both be told
/// they won: a row that changed under a run is refused with the existing
/// concurrent-write error rather than silently overwritten.
#[test]
fn session_replay_compare_and_set_refuses_a_row_that_moved() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-replay-cas").expect("enter session");
    // On record, so the competing mutation reaches the same row the routed
    // put targets; the compare protocol under test is route-independent.
    session.flip_on_record()?;

    assert_eq!(
        seam::replay_put_racing_a_committed_change(&vault, &session)?,
        Some(crate::error::ErrorKind::ConcurrentWrite),
        "a replay row that moved between compare and put must refuse, not lose the update"
    );
    session.close()?;
    Ok(())
}

// ─── P5 · ONE-1730 — promote: typed-journal replay in one txn ────────────

/// §4 master promote: exactly ONE turn's subgraph replays into base;
/// sibling turns stay evaporable.
#[test]
#[ignore = "armed by ONE-1730"]
fn promote_replays_exactly_one_turn_subgraph() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-promote").expect("enter session");
    let (turn_a, msg_a, summary_a) = session.witness_turn("promoted turn")?;
    let (turn_b, _msg_b, _summary_b) = session.witness_turn("stays in the room")?;
    let shell_a = session.session_shell_for_turn(&turn_a)?;
    let outcome = session.promote_turn(&turn_a)?;
    // Exact closure IDENTITY (codex F9): the turn, its PartOf MESSAGE, its
    // DerivedFrom SUMMARY, and the fresh conversation shell — these four
    // ids and no others.
    let mut replayed = outcome.replayed;
    replayed.sort_unstable();
    let mut expected_closure = vec![turn_a, msg_a, summary_a, shell_a];
    expected_closure.sort_unstable();
    assert_eq!(
        replayed, expected_closure,
        "promoted closure must be exactly {{turn, message, summary, shell}}"
    );
    // Every promoted entity lands with its journaled KIND.
    assert_eq!(
        vault.get_entity_type(&turn_a)?,
        Some(crate::registry::ENTITY_TYPE_TURN)
    );
    assert_eq!(
        vault.get_entity_type(&msg_a)?,
        Some(crate::registry::ENTITY_TYPE_MESSAGE)
    );
    assert_eq!(
        vault.get_entity_type(&summary_a)?,
        Some(crate::registry::ENTITY_TYPE_SUMMARY)
    );
    assert_eq!(
        vault.get_entity_type(&shell_a)?,
        Some(crate::registry::ENTITY_TYPE_CONVERSATION)
    );
    assert!(!vault.entity_exists(&turn_b)?, "sibling stays in-room");
    session.close()?;
    assert!(
        vault.entity_exists(&turn_a)?,
        "promoted content survives close"
    );
    Ok(())
}

/// §4 exact attribution-edge set: base gains exactly the promoted turn's
/// journal edges — no extras, none missing.
#[test]
#[ignore = "armed by ONE-1730"]
fn promote_attribution_edge_set_is_exact() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let edges_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.edges_out.len(&rtxn)?
    };
    let entities_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault.store.entities.len(&rtxn)?
    };
    let session = seam::SessionVault::enter(&vault, "oracle-edges").expect("enter session");
    let (turn, msg, summary) = session.witness_turn("edge closure")?;
    let shell = session.session_shell_for_turn(&turn)?;
    session.promote_turn(&turn)?;
    let rtxn = vault.store.env.read_txn()?;
    // The FULL attribution-edge set, every edge with exact endpoints
    // (codex F9): PartOf(msg -> turn), DerivedFrom(summary -> turn),
    // BelongsTo(msg -> shell) — and nothing else.
    assert_eq!(
        vault.store.edges_out.len(&rtxn)? - edges_before,
        3,
        "exactly the journal's attribution edges replay — no extras"
    );
    // Base census delta == exactly the promoted subgraph: 4 entities in,
    // 3 edges each direction, nothing else entity/edge-shaped.
    assert_eq!(
        vault.store.entities.len(&rtxn)? - entities_before,
        4,
        "exactly the four closure entities persist"
    );
    assert_eq!(
        vault.store.edges_in.len(&rtxn)? - edges_before,
        3,
        "the reverse-edge mirror carries the same three edges"
    );
    drop(rtxn);
    assert_eq!(
        vault.targets(&msg, crate::edge::EdgeKind::PartOf, None)?,
        vec![turn]
    );
    assert_eq!(
        vault.targets(&summary, crate::edge::EdgeKind::DerivedFrom, None)?,
        vec![turn]
    );
    assert_eq!(
        vault.targets(&msg, crate::edge::EdgeKind::BelongsTo, None)?,
        vec![shell],
        "the message belongs to exactly the fresh conversation shell"
    );
    session.close()?;
    Ok(())
}

/// D4: promote selects from the TYPED journal, never raw index keys —
/// shared index keys (a term both turns used) must not drag the sibling.
#[test]
#[ignore = "armed by ONE-1730"]
fn promote_selects_from_typed_journal_not_raw_index_keys() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-journal").expect("enter session");
    let (turn_a, _m, _s) = session.witness_turn("sharedterm alpha")?;
    let (turn_b, _m2, _s2) = session.witness_turn("sharedterm beta")?;
    session.promote_turn(&turn_a)?;
    let hits = vault.search_text("sharedterm", 10)?;
    assert_eq!(
        hits.len(),
        1,
        "the shared term must surface exactly the promoted turn's doc"
    );
    assert!(!vault.entity_exists(&turn_b)?);
    session.close()?;
    Ok(())
}

/// ONE-1730: promote retry is idempotent — a second promote of the same
/// turn changes nothing in base.
#[test]
#[ignore = "armed by ONE-1730"]
fn promote_is_idempotent_on_retry() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-retry").expect("enter session");
    let (turn, _m, _s) = session.witness_turn("promote twice")?;
    let first = session.promote_turn(&turn)?;
    let census_after_first = full_db_census(&vault)?;
    // ONE-1730 acceptance "idempotent retry": the SECOND promote must
    // succeed (an impl that errors on retry fails here) and return the
    // identical outcome — same closure, same temp->canonical mapping.
    let second = session
        .promote_turn(&turn)
        .expect("idempotent retry must return Ok, not an error");
    assert_eq!(
        second, first,
        "the retry must return the first call's exact outcome"
    );
    assert_eq!(
        full_db_census(&vault)?,
        census_after_first,
        "a promote retry must not duplicate a single base row"
    );
    session.close()?;
    Ok(())
}

/// D4: learned_at is preserved from the journal (correct month window).
#[test]
#[ignore = "armed by ONE-1730"]
fn promote_preserves_learned_at_from_journal() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let session = seam::SessionVault::enter(&vault, "oracle-learned").expect("enter session");
    let (turn, _m, _s) = session.witness_turn("timestamped in-room")?;
    let in_room_learned_at = 1_234_567; // the seam pins the room clock here
    session.promote_turn(&turn)?;
    assert_eq!(
        vault.get_learned_at(&turn)?,
        in_room_learned_at,
        "learned_at must ride the journal into base unchanged"
    );
    session.close()?;
    Ok(())
}

/// D4/R6: the promote txn commits subgraph + receipt + pm: markers as ONE
/// transaction — a crash right after commit still leaves the pickup marker
/// AND the full promoted subgraph (single-txn contract). The seam owns the
/// whole sequence so the session is LIVE at promote time (grok F6).
#[test]
#[ignore = "armed by ONE-1730"]
fn promote_crash_post_commit_leaves_pm_pickup_marker() -> Result<()> {
    let tmp = tempfile::tempdir().expect("temp dir");
    let (reopened, closure, pm_markers) = seam::promote_then_crash_post_commit(tmp.path())?;
    assert_eq!(
        pm_markers, 1,
        "exactly one pm: marker per source window survives the crash"
    );
    assert_eq!(
        closure.len(),
        4,
        "the promote txn carried the full four-entity closure"
    );
    for id in &closure {
        assert!(
            reopened.entity_exists(id)?,
            "single-txn contract: every closure entity survives the crash"
        );
    }
    Ok(())
}

// ─── P6 · ONE-1731 — fence deletion sweep ────────────────────────────────

/// Acceptance: the fence-symbol census over the crate source returns ZERO
/// hits once the sweep lands. Grep-shaped by design (the census IS the
/// contract); the count assertion lists every hit on failure.
#[test]
#[ignore = "armed by ONE-1731"]
fn fence_symbol_census_returns_zero_hits() {
    const FENCE_SYMBOLS: [&str; 8] = [
        "offrecord_fence:",
        "offrecord_inherited_fence",
        "off_record_fence_active",
        "off_record_visibility_hidden",
        "guard_off_record_",
        "off_record_fences_present",
        "OFF_RECORD_SESSION_MARKER_LINE",
        "scrub_off_record_fenced_carriers",
    ];
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits: Vec<String> = Vec::new();
    let mut stack = vec![src_root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // The census excludes this oracle file itself: its symbol list
            // must not count as fence residue.
            if path.ends_with("branch_store_oracle.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source file");
            for symbol in FENCE_SYMBOLS {
                let count = text.matches(symbol).count();
                if count > 0 {
                    hits.push(format!("{}: {symbol} x{count}", path.display()));
                }
            }
        }
    }
    assert_eq!(
        hits.len(),
        0,
        "fence symbols must be fully deleted by the P6 sweep:\n{}",
        hits.join("\n")
    );
}

// ─── P7 · ONE-1732 — ABI v13 fails closed ────────────────────────────────

/// D9: a v12 vault fails CLOSED on a v13 engine — no silent migration, no
/// legacy decode; typed ABI-gate error.
#[test]
#[ignore = "armed by ONE-1732"]
fn storage_abi_v12_vault_fails_closed_on_v13_engine() {
    let tmp = tempfile::tempdir().expect("temp dir");
    // Create at stored ABI 12, reopen with engine ABI 13.
    let created = seam::open_with_abi_pair(tmp.path(), 12, 12);
    assert!(created.is_ok(), "fixture vault must open at v12");
    drop(created);
    let reopened = seam::open_with_abi_pair(tmp.path(), 12, 13);
    assert_eq!(
        reopened.err(),
        Some(seam::SeamError::AbiFailClosed),
        "a v12 vault must fail closed at the v13 ABI gate (rebuild policy)"
    );
}
