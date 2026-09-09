//! Seam: executor verbs on the session handle, the overlay-vs-model harness, and the txn-segment/crash/budget/snapshot substrate helpers.

use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Arc;

use heed::types::Bytes;
use heed::{DatabaseFlags, Env, EnvOpenOptions, RwTxn};

use crate::batch::BatchOp;
use crate::config::DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::overlay_db::OverlayDb;
use crate::session_overlay::{JournalScope, OverlayKeyspace, SessionOverlay};
use crate::temporal::TimeRange;
use crate::vault::Vault;

use super::binding::{map_executor_error, map_overlay_error};
use super::session::{ModelRow, SeamError, SeamResult, SessionVault, seam_journal_entry};

impl SessionVault<'_> {
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
    pub(in crate::branch_store_oracle) fn dispatch_executor_verb(
        &self,
        verb: &str,
    ) -> SeamResult<()> {
        self.run_executor_verb(verb).map_err(map_executor_error)
    }

    /// ONE-1729: the same dispatch, reported as the PRODUCTION error kind.
    ///
    /// Once the room is on record these verbs take the ordinary path, and
    /// the ordinary path's answer is the write GATE's — which is not an
    /// off-record concern and must not be folded into a [`SeamError`] that
    /// would blur it with one. The post-flip claim is about which check
    /// spoke, so the kind is exactly the right resolution.
    pub(in crate::branch_store_oracle) fn executor_verb_error_kind(
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
    fn session_dispatcher(&self, run_ref: &str) -> Result<crate::code_run::HostSelfDispatcher<'_>> {
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
    pub(in crate::branch_store_oracle) fn dispatch_fixture_write(&self) -> Result<EntityId> {
        let id = EntityId::now();
        crate::code_run::SelfDispatcher::dispatch(
            &self.session_dispatcher("oracle-fixture-write")?,
            self.executor_memory_call("MemoryWriteFixture", id),
        )?;
        Ok(id)
    }

    fn executor_memory_call(&self, verb: &str, id: EntityId) -> crate::code_run::SelfCall {
        use crate::{
            ClaimCandidate, ClaimSubject, code_run::SelfCall, code_run::SelfMemoryPutClaimCall,
            code_run::SelfMemoryPutEdgeCall, code_run::SelfMemorySupersedeClaimCall,
            code_run::SelfMemoryWriteFixtureCall,
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
            "MemoryPutClaim" => {
                SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(id, candidate(), occurred, 4))
            }
            "MemoryWriteFixture" => SelfCall::MemoryWriteFixture(SelfMemoryWriteFixtureCall::new(
                id,
                candidate(),
                occurred,
                4,
            )),
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
    pub(crate) fn witness_executor_utterance(
        &self,
        kind: crate::off_record::ExecutorUtterance,
        text: &str,
        turn_ref: Option<&EntityId>,
    ) -> Result<crate::memory::WitnessReceipt> {
        let route = self.session.write_route()?;
        let container = self.session.routed_conversation_shell(&route)?;
        self.session.witness_executor_turn(
            &container,
            kind,
            text,
            7,
            0,
            None,
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
    pub(in crate::branch_store_oracle) fn dispatcher_container_id(
        &self,
    ) -> Result<Option<EntityId>> {
        Ok(self
            .session_dispatcher("oracle-container")?
            .session_container_id()
            .copied())
    }

    /// ONE-1729: the conversation every MESSAGE in the room belongs to.
    /// Exactly one, or the room shredded into a conversation per turn.
    pub(in crate::branch_store_oracle) fn session_message_shells(&self) -> Result<Vec<EntityId>> {
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
pub(in crate::branch_store_oracle) struct OverlayModelHarness {
    env: Env,
    _dir: tempfile::TempDir,
    rows: OverlayDb,
    duplicates: OverlayDb,
    model: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl OverlayModelHarness {
    pub(crate) fn new(base_rows: &[ModelRow], overlay_script: &[OverlayOp]) -> Self {
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

    pub(crate) fn prefix_iter(&self, prefix: &[u8]) -> Result<Vec<ModelRow>> {
        let rtxn = self.env.read_txn()?;
        self.rows
            .prefix_iter(&rtxn, prefix)?
            .map(|row| row.map(|(key, value)| (key.into_owned(), value.into_owned())))
            .collect()
    }

    pub(crate) fn rev_range(&self, bounds: (Bound<&[u8]>, Bound<&[u8]>)) -> Result<Vec<ModelRow>> {
        let rtxn = self.env.read_txn()?;
        self.rows
            .rev_range(&rtxn, &bounds)?
            .map(|row| row.map(|(key, value)| (key.into_owned(), value.into_owned())))
            .collect()
    }

    pub(in crate::branch_store_oracle) fn model_prefix_iter(&self, prefix: &[u8]) -> Vec<ModelRow> {
        self.model
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    pub(in crate::branch_store_oracle) fn model_rev_range(
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
    pub(in crate::branch_store_oracle) fn dup_items(&self, term: &[u8]) -> Result<Vec<Vec<u8>>> {
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
pub(in crate::branch_store_oracle) enum OverlayOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    /// Append one DUP_SORT duplicate item under a term key.
    DupAppend(Vec<u8>, Vec<u8>),
}

/// ONE-1726: run `script` inside ONE base write txn through the
/// read-through txn segment; `probe` runs under the same live txn and
/// must observe read-your-writes; returns what the probe read.
pub(in crate::branch_store_oracle) fn with_txn_segment_read_back(
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
pub(in crate::branch_store_oracle) fn stage_then_abort(
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
pub(in crate::branch_store_oracle) fn stage_direct_crash_payload(
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
pub(in crate::branch_store_oracle) fn overflow_budget(
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
pub(in crate::branch_store_oracle) fn snapshot_vs_concurrent_apply(
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
pub(in crate::branch_store_oracle) fn read_after_close(
    vault: &Vault,
    session_ref: &str,
) -> SeamError {
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

fn apply_view_script(view: &OverlayDb, wtxn: &mut RwTxn<'_>, script: &[OverlayOp]) -> Result<()> {
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
