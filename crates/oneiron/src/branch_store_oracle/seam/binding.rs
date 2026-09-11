//! Seam: error mappers, crash/reopen, job/taint/scoped-read probes, executor binding-mismatch and route-flip probes, the replay CAS race and the ABI-pair opener.

use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

use super::session::{SeamError, SeamResult, SessionVault};
use crate::error::{OffRecordError, StoreError};

pub(super) fn map_overlay_error(error: Error) -> SeamError {
    match error {
        Error::OffRecord(OffRecordError::OffRecordOverlayFull { .. }) => SeamError::OverlayFull,
        Error::OffRecord(OffRecordError::OffRecordOverlayLeaseClosed { .. }) => {
            SeamError::LeaseClosed
        }
        other => panic!("unexpected overlay error: {other}"),
    }
}

pub(super) fn map_session_error(error: Error) -> SeamError {
    match error {
        Error::OffRecord(OffRecordError::KillSwitchDisabled) => SeamError::KillSwitchDisabled,
        Error::OffRecord(OffRecordError::OffRecordSessionAlreadyExists { .. }) => {
            SeamError::SessionRefLive
        }
        Error::OffRecord(OffRecordError::OffRecordSessionNotFound { .. }) => {
            SeamError::SessionNotFound
        }
        Error::OffRecord(OffRecordError::OffRecordSessionClosing { .. }) => {
            SeamError::SessionClosing
        }
        other => panic!("unexpected session error: {other}"),
    }
}

/// ONE-1729: production refusals on the session-bound EXECUTOR path,
/// mapped ONE-TO-ONE. Anything unmapped panics with the production error
/// rather than folding into a neighbouring variant — these tests assert
/// exact variants, so a many-to-one fold here would silently weaken them.
pub(super) fn map_executor_error(error: Error) -> SeamError {
    match error {
        Error::OffRecord(OffRecordError::OffRecordTalkOnly { .. }) => SeamError::PolicyMemoryWrite,
        Error::OffRecord(OffRecordError::OffRecordGuestTurnRefRejected { .. }) => {
            SeamError::GuestTurnRef
        }
        Error::OffRecord(OffRecordError::OffRecordSessionNotFound { .. }) => {
            SeamError::SessionNotFound
        }
        Error::OffRecord(OffRecordError::OffRecordSessionClosing { .. }) => {
            SeamError::SessionClosing
        }
        Error::OffRecord(OffRecordError::OffRecordOverlayLeaseClosed { .. }) => {
            SeamError::LeaseClosed
        }
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
pub(in crate::branch_store_oracle) fn crash_and_reopen(
    dir: &std::path::Path,
    vault: Vault,
) -> Result<Vault> {
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
pub(in crate::branch_store_oracle) fn attempt_row_counts(vault: &Vault) -> Result<(u64, u64, u64)> {
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
pub(in crate::branch_store_oracle) fn job_rows_referencing(
    vault: &Vault,
    ids: &[EntityId],
) -> Result<usize> {
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
pub(in crate::branch_store_oracle) fn base_batch_referencing_overlay_id(
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
        Error::OffRecord(OffRecordError::OffRecordTaintedBaseWrite { .. }) => {
            SeamError::TaintedBaseWrite
        }
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
pub(in crate::branch_store_oracle) fn base_scoped_read_visible_claim_count(
    vault: &Vault,
    subject: &EntityId,
) -> Result<usize> {
    scoped_read_visible_claim_count(&vault.scoped_read(scoped_read_actor_key()), subject)
}

/// ONE-1730 ARMED: the crash-matrix sequence, OWNED by the seam end to
/// end: enter -> witness one turn -> promote it with a crash injected
/// immediately AFTER the single promote txn commits (the session is
/// LIVE at promote time) -> reopen from disk. Returns the reopened
/// vault, the promoted closure ids, and the `pm:` pickup-marker count.
///
/// The "crash" is every handle dropping WITHOUT close, inside the block
/// below — the same residue a killed process leaves, and the reason the
/// session never gets to clean up after itself.
#[cfg(feature = "sync")]
pub(in crate::branch_store_oracle) fn promote_then_crash_post_commit(
    dir: &std::path::Path,
) -> Result<(Vault, Vec<EntityId>, usize)> {
    let closure = {
        let vault = Vault::open(dir, VaultConfig::default()).expect("open crash-matrix vault");
        let mut session =
            SessionVault::enter(&vault, "oracle-crash").expect("enter crash-matrix session");
        session.bind_actor()?;
        let (turn, _message, _summary) = session.witness_turn("crashes after commit")?;
        let outcome = session.promote_turn(&turn)?;
        outcome.replayed
        // `session` then `vault` drop here, unclosed: the crash.
    };

    let reopened = Vault::open(dir, VaultConfig::default()).expect("reopen crash-matrix vault");
    let rtxn = reopened.store.env.read_txn()?;
    let mut pm_markers = 0_usize;
    for row in reopened.store.sync_state.prefix_iter(&rtxn, "pm:")? {
        row?;
        pm_markers += 1;
    }
    drop(rtxn);
    Ok((reopened, closure, pm_markers))
}

/// ONE-1729: acquire a handle on a session ref, refusal mapped typed.
pub(in crate::branch_store_oracle) fn bind_session(
    vault: &Vault,
    session_ref: &str,
) -> SeamResult<()> {
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
pub(in crate::branch_store_oracle) fn stale_handle_and_rebind_refusals(
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
pub(in crate::branch_store_oracle) struct BindingMismatch {
    pub(crate) name: &'static str,
    /// The `InvalidConfig` payload run entry refused with, or `None` when
    /// the run was allowed to proceed.
    pub(crate) refusal: Option<String>,
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
        prompt_package_root: crate::prompt::workspace_prompt_package_root()
            .expect("workspace prompt package"),
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
    let std::task::Poll::Ready(result) = std::future::Future::poll(run.as_mut(), &mut cx) else {
        panic!("run entry must settle before it awaits anything")
    };
    match result {
        Err(crate::engine_executor::EngineExecutorError::Engine(Error::InvalidConfig(message))) => {
            Some(message)
        }
        Err(other) => panic!("unexpected executor refusal: {other}"),
        Ok(_) => None,
    }
}

/// ONE-1729: every mismatched storage/dispatcher pairing, run to entry.
///
/// The third direction is the one a `session_ref`-only check misses: two
/// CANONICAL runs whose refs compare equal (`None == None`) across
/// different vaults.
pub(in crate::branch_store_oracle) fn binding_mismatch_directions(
    vault: &Vault,
    session: &SessionVault<'_>,
    other_vault: &Vault,
) -> Result<Vec<BindingMismatch>> {
    let backend = UnreachableBackend;
    let lease = crate::BudgetLease::for_test("binding-oracle");
    let config = binding_oracle_config();
    let canonical =
        crate::code_run::HostSelfDispatcher::new(vault, oracle_write_actor(), "binding-canonical")?;
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
pub(in crate::branch_store_oracle) fn apply_through_a_route_captured_before_a_flip(
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
pub(in crate::branch_store_oracle) fn search_through_a_route_captured_before_a_flip(
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
pub(in crate::branch_store_oracle) fn witness_turn_with_mismatched_binding(
    vault: &Vault,
    session: &SessionVault<'_>,
) -> Result<Option<String>> {
    let backend = UnreachableBackend;
    let lease = crate::BudgetLease::for_test("binding-oracle");
    let mut runtime = UnreachableRuntime;
    let canonical =
        crate::code_run::HostSelfDispatcher::new(vault, oracle_write_actor(), "witness-canonical")?;
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
        Err(crate::engine_executor::EngineExecutorError::Engine(Error::InvalidConfig(message))) => {
            Ok(Some(message))
        }
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
pub(in crate::branch_store_oracle) fn replay_put_racing_a_committed_change(
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
///
/// An EMPTY directory (or one that cannot be listed yet) is a new vault:
/// the ABI gate stamps whatever version the opening engine carries, so
/// opening at `stored` is exactly how a fixture acquires that stamp. A
/// populated directory already carries its stamp, so the reopen runs at
/// `engine` and the gate compares the two.
pub(in crate::branch_store_oracle) fn open_with_abi_pair(
    dir: &std::path::Path,
    stored: u16,
    engine: u16,
) -> SeamResult<Vault> {
    let creating = std::fs::read_dir(dir).map_or(true, |mut entries| entries.next().is_none());
    let engine_abi = if creating { stored } else { engine };
    Vault::open_with_storage_abi_version_for_test(dir, VaultConfig::default(), engine_abi).map_err(
        |error| match error {
            Error::Store(StoreError::StorageAbiVersionChanged { .. }) => SeamError::AbiFailClosed,
            // Only the ABI mismatch is the fail-closed verdict this oracle
            // measures: folding any other open failure into `AbiFailClosed`
            // would let an unrelated gate satisfy the assertion.
            other => panic!("unexpected vault-open error: {other}"),
        },
    )
}
