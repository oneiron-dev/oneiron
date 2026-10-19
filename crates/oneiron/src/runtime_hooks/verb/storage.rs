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
//! process ([`SessionHookKeep`]). None of them reaches base.
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

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

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
use crate::store::SessionStoreView;
use crate::work_line::TaskWorkTurn;
use crate::{Result, Vault};

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
#[expect(
    dead_code,
    reason = "L13 PR-D (FIX 4283) names the key of a roomless or no_record call; a room keeps its own"
)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum SessionHookKey {
    /// A session, by its ref and when it was entered: a ref entered again
    /// keeps apart.
    Session { key: String, entered_at: u64 },
    /// The process: kept until it ends.
    Process,
}

/// The in-memory keep of session-only hook records: per key, a standalone
/// overlay that stages a call's records as a room's overlay does, under a
/// room's byte budget, in RAM only. Nothing in it reaches base; it goes with
/// its session's [`Self::drop_session`], or with the vault's process.
#[derive(Default)]
pub(crate) struct SessionHookKeep {
    kept: Mutex<HashMap<SessionHookKey, Arc<SessionOverlay>>>,
}

impl SessionHookKeep {
    /// Stages one call's records under `key`: `rows` reads through the
    /// keep's composed view and puts or deletes in it, in one segment.
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
        let overlay = Arc::clone(
            self.kept
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(key.clone())
                .or_insert_with(|| {
                    SessionOverlay::new(vault.config.off_record_overlay_budget_bytes)
                }),
        );
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
}

#[expect(
    dead_code,
    reason = "L13 PR-D (FIX 4283) reads a session's kept hook records and drops them with it"
)]
impl SessionHookKeep {
    /// Reads `key`'s kept records through the keep's composed view; `None`
    /// while it keeps none.
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
            .cloned()
        else {
            return Ok(None);
        };
        let view = vault.store.session_view(overlay)?;
        let rtxn = vault.store.env.read_txn()?;
        f(&rtxn, RoutedDbs::Session(&view)).map(Some)
    }

    /// Drops every record kept under `key`, as its session ends.
    pub(crate) fn drop_session(&self, key: &SessionHookKey) {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
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
    #[expect(
        dead_code,
        reason = "L13 PR-D (FIX 4283) passes a roomless or no_record call's hooks here"
    )]
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
        }
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
    #[expect(
        dead_code,
        reason = "L13 PR-D (FIX 4283) posts a roomless call's hooks from its pre alone"
    )]
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
