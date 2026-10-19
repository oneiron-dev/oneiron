//! Where one verb hook chain reads content and keeps its records (WILL L11-01
//! S01-2c): the vault, or a session-only call's own store.
//!
//! A chain's authority is the vault's wherever it runs: its bindings, their
//! code and body hash, `hooks.enabled`, each binding's blocking dial, its
//! grant, and the caller's membership and credential. A session changes only
//! where its hooks read and where their records go. In an off-record room a
//! hook reads the room's view under the caller's key (capped by its grant
//! reader's), and its receipt, saved run and run index stage in the room's
//! own store (`OffRecordSession::stage_hook_records`). A session-only call
//! with no room overlay (a roomless anonymous session, a `no_record` row)
//! reads the vault and keeps its records in RAM under its session or the
//! process ([`SessionHookKeep`]). None of them reaches base. Such a call's
//! hook may ask (L13 PR-D, FIX 4283): the call it paused waits in the same
//! keep, under the same key, and only its caller's retry there resumes it,
//! using the answer up once; it goes with its session. While
//! `KEPT_CALL_HOOK_CONSEQUENCES_RUN` holds (FIX 5525), its hooks' blocks,
//! proposals, queued tasks and effects land in the vault as on any call;
//! only their receipts and saved runs stay in the keep.
//!
//! A session-only call's records are held from its pre chain, riding the
//! [`VerbHookPre`], through its post chain, and kept together once its own
//! read is done, in ONE segment of their own ([`SessionHooks::keep`]): the
//! read's own budgeted rows (its search telemetry) never meet a budget its
//! hooks spent first, and a store that refuses the hooks' segment drops it
//! whole. A pre chain that stops the call keeps its records at once.
//!
//! A session does no canonical work for a hook: an outcome that needs it (an
//! ask, a block, a proposal, a queued task or an effect) is that hook's own
//! typed, terminal outcome, [`SESSION_HOOK_UNAVAILABLE`], recorded before any
//! ask, block, lineage or apply would run, and the read answers. Everything
//! else runs as on base (CALLS-1 `session_hook_unavailable_policy`): a hook
//! that skips stops the read, a redact narrows its view, a blocking hook that
//! fails hides the read's result, one that does not block fails open, and
//! with no sandbox installed, hooks off or none matching the call passes
//! through. When a session keeps no records for a call, its hooks' outcomes
//! apply all the same and each hook's disposition says why the receipt was
//! not kept.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use serde_json::Value;

use crate::code_run::{
    SessionHookDisposition, SessionHookNotKept, SessionHookPhase, SessionHookReceipt,
    SessionHookState,
};
use crate::error::{Error, GateError, OffRecordError};
use crate::off_record::{OffRecordSession, SessionWriteRoute};
use crate::receipt::ReceiptRecord;
use crate::runtime_hooks::runner::bounded;
use crate::runtime_hooks::store::{self, RunKey};
use crate::session_overlay::{SessionOverlay, TxnSegmentGuard};
use crate::side_table::{RoutedDbs, SideTableDbs};
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::store::SessionStoreView;
use crate::work_line::TaskWorkTurn;
use crate::{EntityId, Result, Vault};

use super::record::{self, HookVerbRunRecord};
use super::{VerbArgsCheck, VerbCall, VerbHookPre, VerbHookStop, chain};

/// The one reason a hook's outcome that needs canonical work gives in a
/// session (CALLS-3 `session_hook_consequence_support`): its receipt's
/// reason, with the work it named after a colon, and its disposition's.
pub(super) const SESSION_HOOK_UNAVAILABLE: &str = "session_hook_unavailable";

/// Where a chain reads content and keeps its records.
#[derive(Clone, Copy)]
pub(crate) enum VerbHookStorage<'s> {
    /// The vault: content and records in base, as for every call outside a
    /// session.
    Canonical,
    /// A session-only call: an off-record room, or the in-memory keep.
    Session(&'s SessionHooks<'s>),
}

/// One chain, or one call's pre and post chains, of a session-only call:
/// where its hooks read and keep, the runs it holds, and what each hook did
/// once kept.
pub(crate) struct SessionHooks<'s> {
    target: HooksTarget<'s>,
    /// Whether the call answers when its hooks cannot be read
    /// ([`Self::answering_unread`]).
    answers_unread: bool,
    /// Why its hooks could not be read, once a read failed.
    unread: RefCell<Option<String>>,
    held: RefCell<Vec<HeldRun>>,
    /// Dispositions no receipt goes with: a phase whose hooks went unread.
    notes: RefCell<Vec<SessionHookDisposition>>,
    dispositions: RefCell<Vec<SessionHookDisposition>>,
    /// The pause an explicit resume names, by its ask handle, on a call
    /// with no room overlay ([`Self::resuming`]); `None` for a new call.
    resume: Option<EntityId>,
    /// Set once this call used its resumed answer up in the keep.
    answer_taken: Cell<bool>,
}

/// Where one session-only call's hooks read and keep.
enum HooksTarget<'s> {
    /// An off-record room: its view, and its store along the route its run
    /// captured at entry.
    Room {
        session: &'s OffRecordSession<'s>,
        route: &'s SessionWriteRoute,
    },
    /// A call with no room overlay: the vault's content, and the in-memory
    /// keep under `key`.
    Kept {
        vault: &'s Vault,
        key: SessionHookKey,
    },
}

/// What a session-only call's pre chain hands its post chain inside the
/// [`VerbHookPre`]: the runs it holds, what it notes beside them, and the
/// in-memory keep's key when it ran on one, so a post on another thread
/// finds the same store.
#[derive(Debug)]
pub(crate) struct SessionCarry {
    key: Option<SessionHookKey>,
    runs: Vec<HeldRun>,
    notes: Vec<SessionHookDisposition>,
}

/// One run as a session keeps it: its receipt and its saved copy under its
/// run key, and what the call's answer says of it, but for its receipt.
#[derive(Debug)]
pub(super) struct HeldRun {
    pub(super) key: RunKey,
    pub(super) receipt: ReceiptRecord,
    pub(super) saved: HookVerbRunRecord,
    pub(super) hook: String,
    pub(super) phase: SessionHookPhase,
    pub(super) state: SessionHookState,
}

/// What became of one call's records in a session's store.
pub(crate) enum HookRecordsKept {
    Kept,
    NotKept(SessionHookNotKept),
}

impl HookRecordsKept {
    /// What `staged`, one call's records staged in a segment of their own,
    /// leaves of them (CALLS-4 `session_receipt_budget_policy`): hook records
    /// are ordinary budgeted bytes, and a session holds no custody door, so
    /// a budget or a side-row wall that refuses the segment keeps none of
    /// them and fails nothing. Every other error, a refusal of the session's
    /// authority included, is the call's.
    ///
    /// # Errors
    ///
    /// `staged`'s error, unless it is one of those two.
    pub(crate) fn of(staged: Result<()>) -> Result<Self> {
        match staged {
            Ok(()) => Ok(Self::Kept),
            Err(Error::OffRecord(OffRecordError::OffRecordOverlayFull { .. })) => {
                Ok(Self::NotKept(SessionHookNotKept::BudgetFull))
            }
            Err(Error::Gate(GateError::GateWriteRejected { .. })) => {
                Ok(Self::NotKept(SessionHookNotKept::Custody))
            }
            Err(error) => Err(error),
        }
    }
}

/// What a session-only call with no room overlay keeps its hook records
/// under (Engine 10-19): its session, or the process.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum SessionHookKey {
    /// A session, by its registry key and when it was entered: a ref
    /// entered again keeps apart.
    Session { key: String, entered_at: u64 },
    /// The process: kept until it ends.
    Process,
}

impl SessionHookKey {
    /// Whether this key's session is the live one: the process always is;
    /// a session while the registry holds the stretch entered then, not
    /// closing. Close publishes `closing` before it drops the key's keep, so
    /// a writer that finds the key live under the keep's lock is dropped
    /// with it, and one after finds it closing.
    fn live(&self, vault: &Vault) -> bool {
        match self {
            Self::Process => true,
            Self::Session { key, entered_at } => vault
                .store
                .off_record_sessions
                .record(key)
                .is_some_and(|record| record.entered_at == *entered_at && !record.closing),
        }
    }
}

/// The in-memory keep of session-only hook records and pauses: per key, a
/// standalone overlay that stages a call's records as a room's overlay
/// does, under a room's byte budget, and the calls its hooks' asks paused,
/// in RAM only. Nothing in it reaches base; it goes with its session's
/// [`Self::drop_session`], or with the vault's process. A key whose session
/// is closing or gone is never kept again.
#[derive(Default)]
pub(crate) struct SessionHookKeep {
    kept: Mutex<HashMap<SessionHookKey, Kept>>,
    /// The key that hides a session-only call's invocation in the intent
    /// key of the ask its hook opens: drawn once per process, never stored.
    hiding: OnceLock<[u8; 32]>,
}

/// What the keep holds under one key: its records and its paused calls.
struct Kept {
    overlay: Arc<SessionOverlay>,
    /// The calls its hooks' asks paused, by invocation.
    asks: HashMap<[u8; 16], SessionVerbAsk>,
}

/// A call a session-only call's hook ask paused (L13 PR-D, FIX 4283): what
/// a retry of its invocation under the same key reads. Its args stay here,
/// never in the vault's ask.
#[derive(Debug, Clone)]
pub(super) struct SessionVerbAsk {
    pub(super) verb: String,
    pub(super) actor: EntityId,
    pub(super) class: HookActorClass,
    /// The args the asking hook saw, re-validated.
    pub(super) args: Value,
    /// The asking hook's place in the pre chain.
    pub(super) position: usize,
    pub(super) binding: EntityId,
    /// `<pack>/<hook>`.
    pub(super) hook: String,
    /// The hook's author, who asked and reads the answer.
    pub(super) author: EntityId,
    pub(super) author_class: HookActorClass,
    /// The ask's group: its handle.
    pub(super) ask: EntityId,
    /// Set once a retry resumed the call on a proceed answer it used up.
    pub(super) used: bool,
}

impl SessionHookKeep {
    /// Stages one call's records under `key`: `rows` reads through the
    /// keep's composed view and puts or deletes in it, in one segment. A key
    /// whose session closed meanwhile keeps none of them.
    ///
    /// # Errors
    ///
    /// Storage errors; a keep that refuses the segment answers
    /// [`HookRecordsKept::NotKept`] instead.
    pub(crate) fn stage(
        &self,
        vault: &Vault,
        key: &SessionHookKey,
        rows: impl FnOnce(&mut heed::RwTxn<'_>, RoutedDbs<'_>, RoutedDbs<'_>) -> Result<()>,
    ) -> Result<HookRecordsKept> {
        let Some(overlay) = self.with_live(vault, key, |kept| Arc::clone(&kept.overlay)) else {
            return Ok(HookRecordsKept::NotKept(SessionHookNotKept::NoRetention));
        };
        HookRecordsKept::of(
            vault
                .with_write_txn_grouped(|wtxn| {
                    let segment = overlay.install_txn_segment()?;
                    let view = vault.store.session_view(Arc::clone(&overlay))?;
                    rows(wtxn, RoutedDbs::Session(&view), RoutedDbs::Session(&view))?;
                    Ok(segment)
                })
                .and_then(TxnSegmentGuard::commit),
        )
    }

    /// Reads `key`'s kept records through the keep's composed view; `None`
    /// while it keeps none.
    #[expect(
        dead_code,
        reason = "a projector of a session's kept hook records reads them here; none does yet"
    )]
    pub(crate) fn read<T>(
        &self,
        vault: &Vault,
        key: &SessionHookKey,
        f: impl FnOnce(&heed::RoTxn<'_>, RoutedDbs<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        let Some(overlay) = self
            .kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .map(|kept| Arc::clone(&kept.overlay))
        else {
            return Ok(None);
        };
        let view = vault.store.session_view(overlay)?;
        let rtxn = vault.store.env.read_txn()?;
        f(&rtxn, RoutedDbs::Session(&view)).map(Some)
    }

    /// Drops every record and paused call kept under `key`, as its session
    /// ends: nothing resumes a call it paused.
    pub(crate) fn drop_session(&self, key: &SessionHookKey) {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }

    /// Saves the call `invocation`'s hook ask paused under `key`, over any
    /// earlier one: false, saving nothing, once its session is closing or
    /// gone.
    pub(super) fn save_ask(
        &self,
        vault: &Vault,
        key: &SessionHookKey,
        invocation: [u8; 16],
        ask: SessionVerbAsk,
    ) -> bool {
        self.with_live(vault, key, |kept| {
            kept.asks.insert(invocation, ask);
        })
        .is_some()
    }

    /// The call `invocation`'s hook ask paused under `key`, if this process
    /// holds one.
    pub(super) fn ask(&self, key: &SessionHookKey, invocation: [u8; 16]) -> Option<SessionVerbAsk> {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .and_then(|kept| kept.asks.get(&invocation).cloned())
    }

    /// Uses ask `ask`'s proceed answer up for `invocation` under `key`,
    /// once: false when no unused call of that ask stands there (used
    /// already, a newer ask's call, or its session gone).
    pub(super) fn use_ask(
        &self,
        key: &SessionHookKey,
        invocation: [u8; 16],
        ask: EntityId,
    ) -> bool {
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        match kept
            .get_mut(key)
            .and_then(|kept| kept.asks.get_mut(&invocation))
        {
            Some(row) if row.ask == ask && !row.used => {
                row.used = true;
                true
            }
            _ => false,
        }
    }

    /// The id that stands for `invocation` under `key` wherever the vault
    /// would name a session-only call (FIX 5382, FIX 5383): a hash keyed by
    /// this process's own key over the session, when it was entered and the
    /// invocation, so the vault never carries the caller's invocation, and a
    /// retry in this process meets the ask it opened.
    pub(crate) fn hidden_invocation(&self, key: &SessionHookKey, invocation: [u8; 16]) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new_keyed(self.hiding.get_or_init(rand::random));
        match key {
            SessionHookKey::Session { key, entered_at } => {
                hasher.update(b"session");
                hasher.update(&u64::try_from(key.len()).unwrap_or(u64::MAX).to_le_bytes());
                hasher.update(key.as_bytes());
                hasher.update(&entered_at.to_le_bytes());
            }
            SessionHookKey::Process => {
                hasher.update(b"process");
            }
        }
        hasher.update(&invocation);
        let mut id = [0; 16];
        id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        id
    }

    /// Runs `f` on what `key` keeps, made empty when it keeps nothing yet,
    /// while its session is live, under the keep's lock: `None` once it is
    /// closing or gone, so a late writer never makes it again.
    fn with_live<T>(
        &self,
        vault: &Vault,
        key: &SessionHookKey,
        f: impl FnOnce(&mut Kept) -> T,
    ) -> Option<T> {
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        if !key.live(vault) {
            return None;
        }
        Some(f(kept.entry(key.clone()).or_insert_with(|| Kept {
            overlay: SessionOverlay::new(vault.config.off_record_overlay_budget_bytes),
            asks: HashMap::new(),
        })))
    }
}

impl<'s> SessionHooks<'s> {
    /// The hooks of a call in `session`'s room, on `route`, the route its
    /// run captured.
    pub(crate) fn new(session: &'s OffRecordSession<'s>, route: &'s SessionWriteRoute) -> Self {
        Self::on(HooksTarget::Room { session, route })
    }

    /// The hooks of a session-only call with no room overlay: they read
    /// `vault` and keep their records under `key` in its in-memory keep.
    pub(crate) fn session_only(vault: &'s Vault, key: SessionHookKey) -> Self {
        Self::on(HooksTarget::Kept { vault, key })
    }

    fn on(target: HooksTarget<'s>) -> Self {
        Self {
            target,
            answers_unread: false,
            unread: RefCell::new(None),
            held: RefCell::new(Vec::new()),
            notes: RefCell::new(Vec::new()),
            dispositions: RefCell::new(Vec::new()),
            resume: None,
            answer_taken: Cell::new(false),
        }
    }

    /// These hooks, for a call that names `ask`, the handle of the pause it
    /// resumes (L13 PR-D, FIX 4283): its retry reads that pause in the keep,
    /// and one the keep no longer holds (its session ended, or the server
    /// restarted) refuses, never running as a new call. `None` is a new
    /// call. Only a call with no room overlay reads it.
    #[must_use]
    pub(crate) fn resuming(mut self, ask: Option<EntityId>) -> Self {
        self.resume = ask;
        self
    }

    /// The pause these hooks' call names as the one it resumes.
    pub(super) fn resumed_ask(&self) -> Option<EntityId> {
        self.resume
    }

    /// The in-memory keep's key of a call with no room overlay; `None` in a
    /// room.
    pub(super) fn kept_key(&self) -> Option<&SessionHookKey> {
        match &self.target {
            HooksTarget::Kept { key, .. } => Some(key),
            HooksTarget::Room { .. } => None,
        }
    }

    /// Whether this call used its resumed answer up already; marks it used
    /// from now on, so a chain that commits twice (once before its ask
    /// opens, once as it ends) uses it once.
    pub(super) fn take_answer(&self) -> bool {
        self.answer_taken.replace(true)
    }

    /// These hooks, for a call that answers when they cannot be read (the
    /// run's search with no key, Engine 10-19 17:1x): a failed read of the
    /// bindings, a binding's scope or its grant runs none of the phase's
    /// hooks, refuses nothing, and leaves a [`SessionHookState::Unread`]
    /// disposition naming it. Every other error is the call's, as before.
    #[must_use]
    pub(crate) fn answering_unread(mut self) -> Self {
        self.answers_unread = true;
        self
    }

    /// Notes `error`, the failed read of the hooks' `what`, on hooks that
    /// answer with them unread; the first failure names the phase.
    pub(super) fn note_unread(&self, what: &str, error: &Error) {
        if self.answers_unread {
            self.unread
                .borrow_mut()
                .get_or_insert_with(|| bounded(&format!("the hook {what} did not read: {error}")));
        }
    }

    /// The disposition of `phase` when a read of its hooks failed on hooks
    /// that answer with them unread; `None` otherwise.
    fn unread_in(&self, phase: SessionHookPhase) -> Option<SessionHookDisposition> {
        self.unread.take().map(|reason| SessionHookDisposition {
            hook: None,
            phase,
            state: SessionHookState::Unread { reason },
            receipt: SessionHookReceipt::NoRun,
        })
    }

    /// What each hook kept here did, in the order they ran.
    pub(crate) fn into_dispositions(self) -> Vec<SessionHookDisposition> {
        self.dispositions.into_inner()
    }

    /// The room's view a call's hooks read content through; `None` for a
    /// call with no room overlay, whose hooks read the vault.
    pub(super) fn view(&self) -> Result<Option<SessionStoreView<'s>>> {
        match &self.target {
            HooksTarget::Room { session, .. } => (*session).read_view().map(Some),
            HooksTarget::Kept { .. } => Ok(None),
        }
    }

    /// Holds a chain's runs until the call keeps them.
    pub(super) fn hold(&self, runs: impl IntoIterator<Item = HeldRun>) {
        self.held.borrow_mut().extend(runs);
    }

    /// The runs held so far, for a pre chain's [`VerbHookPre`] to carry.
    fn carry(&self) -> SessionCarry {
        SessionCarry {
            key: match &self.target {
                HooksTarget::Kept { key, .. } => Some(key.clone()),
                HooksTarget::Room { .. } => None,
            },
            runs: self.held.take(),
            notes: self.notes.take(),
        }
    }

    /// Holds the runs `pre`'s chain held, and what it noted, ahead of this
    /// chain's own.
    fn resume(&self, pre: &mut VerbHookPre) {
        if let Some(carry) = pre.session.take() {
            self.hold(carry.runs);
            self.notes.borrow_mut().extend(carry.notes);
        }
    }

    /// Keeps every run held, in one segment of their own, and records what
    /// each hook did, then what the call noted. A store that keeps none
    /// fails nothing.
    fn keep(&self) -> Result<()> {
        let runs = self.held.take();
        if runs.is_empty() {
            self.dispositions.borrow_mut().extend(self.notes.take());
            return Ok(());
        }
        let rows = |txn: &mut heed::RwTxn<'_>, read: RoutedDbs<'_>, write: RoutedDbs<'_>| {
            runs.iter()
                .try_for_each(|run| put_run(&read, &write, txn, run))
        };
        let kept = match &self.target {
            HooksTarget::Room { session, route } => session.stage_hook_records(route, rows)?,
            HooksTarget::Kept { vault, key } => {
                vault.verb_hook_state.session.stage(vault, key, rows)?
            }
        };
        self.dispositions
            .borrow_mut()
            .extend(runs.into_iter().map(|run| SessionHookDisposition {
                hook: Some(run.hook),
                phase: run.phase,
                state: run.state,
                receipt: match &kept {
                    HookRecordsKept::Kept => SessionHookReceipt::Kept {
                        id: store::receipt_id(&run.key),
                    },
                    HookRecordsKept::NotKept(why) => SessionHookReceipt::NotKept { why: *why },
                },
            }));
        self.dispositions.borrow_mut().extend(self.notes.take());
        Ok(())
    }
}

/// One run's receipt and saved copy: its earlier saved copy read through
/// `read`, and its rows written along `write`.
fn put_run(
    read: &impl SideTableDbs,
    write: &impl SideTableDbs,
    txn: &mut heed::RwTxn<'_>,
    run: &HeldRun,
) -> Result<()> {
    store::RECEIPTS.put(write, txn, &run.key, &run.receipt)?;
    record::put_in_txn(read, write, txn, &run.key, &run.saved)
}

impl VerbHookPre {
    /// The in-memory keep's key a session-only call's pre chain ran on, so
    /// its post chain, on whatever thread, keeps on the same store; `None`
    /// on the vault and in a room, whose caller holds its room.
    pub(crate) fn session(&self) -> Option<&SessionHookKey> {
        self.session.as_ref().and_then(|carry| carry.key.as_ref())
    }
}

impl Vault {
    /// [`Self::pre_verb_hooks`] reading and keeping on `storage`, on `turn`,
    /// the task-work turn the calling operation holds, if any. A session's
    /// call saves no resume target and opens no ask, so the turn is only
    /// carried. A session-only call's records ride the pre to its post
    /// chain; one its pre chain stops keeps them at once. On hooks that
    /// answer with them unread, a failed read of the hooks passes the call
    /// through with its own args, noting why ([`SessionHooks::answering_unread`]).
    ///
    /// # Errors
    ///
    /// Storage and authority errors as they occur; a hook's own failure, or
    /// a session that keeps no record of it, is never one.
    pub(crate) fn pre_verb_hooks_in(
        &self,
        storage: VerbHookStorage<'_>,
        call: VerbCall,
        args: Value,
        check: VerbArgsCheck<'_>,
        turn: Option<Arc<TaskWorkTurn>>,
    ) -> Result<std::result::Result<VerbHookPre, VerbHookStop>> {
        let VerbHookStorage::Session(hooks) = storage else {
            return chain::pre(self, storage, call, args, check, None, turn);
        };
        let own = hooks.answers_unread.then(|| (call.clone(), args.clone()));
        let ended = match chain::pre(self, storage, call, args, check, None, turn) {
            Ok(ended) => ended,
            Err(error) => {
                let (Some((call, args)), Some(note)) =
                    (own, hooks.unread_in(SessionHookPhase::Pre))
                else {
                    return Err(error);
                };
                hooks.notes.borrow_mut().push(note);
                return Ok(Ok(VerbHookPre {
                    call,
                    args,
                    carry: None,
                    landing: None,
                    session: Some(hooks.carry()),
                }));
            }
        };
        match ended {
            Ok(mut pre) => {
                pre.session = Some(hooks.carry());
                Ok(Ok(pre))
            }
            Err(stop) => {
                hooks.keep()?;
                Ok(Err(stop))
            }
        }
    }

    /// [`Self::post_verb_hooks`] reading and keeping on `storage`, the one
    /// its pre chain ran on: the call's records, its pre chain's first, are
    /// kept once it ends. On hooks that answer with them unread, a failed
    /// read of the hooks leaves `result` as it is, noting why.
    ///
    /// # Errors
    ///
    /// As [`Self::pre_verb_hooks_in`].
    pub(crate) fn post_verb_hooks_in(
        &self,
        storage: VerbHookStorage<'_>,
        mut pre: VerbHookPre,
        result: Value,
    ) -> Result<std::result::Result<Value, VerbHookStop>> {
        let VerbHookStorage::Session(hooks) = storage else {
            return chain::post(self, storage, pre, result);
        };
        hooks.resume(&mut pre);
        let own = hooks.answers_unread.then(|| result.clone());
        let ended = match chain::post(self, storage, pre, result) {
            Ok(ended) => ended,
            Err(error) => {
                let (Some(result), Some(note)) = (own, hooks.unread_in(SessionHookPhase::Post))
                else {
                    return Err(error);
                };
                hooks.notes.borrow_mut().push(note);
                Ok(result)
            }
        };
        hooks.keep()?;
        Ok(ended)
    }

    /// Keeps what `pre`'s chain held for a session-only call that ended with
    /// no result for a post chain to read (refused, failed or parked).
    ///
    /// # Errors
    ///
    /// As [`Self::pre_verb_hooks_in`].
    pub(crate) fn keep_verb_hooks_in(
        &self,
        storage: VerbHookStorage<'_>,
        mut pre: VerbHookPre,
    ) -> Result<()> {
        let VerbHookStorage::Session(hooks) = storage else {
            return Ok(());
        };
        hooks.resume(&mut pre);
        hooks.keep()
    }
}
