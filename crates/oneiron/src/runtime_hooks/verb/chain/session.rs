//! A chain of a session-only call (WILL L11-01 S01-2c): the lanes its hooks
//! read through, over a room's view; the session rule for an outcome that
//! needs canonical work; and its runs held for the call to keep, each with
//! what the call's answer will say of it. A hook's ask pauses its call in the
//! in-memory keep (L13 PR-D, FIX 4283), a room's under its stretch (FIX 5524).

use serde_json::Value;

use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadActorKey};
use crate::code_run::{SessionHookPhase, SessionHookState};
use crate::runtime_hooks::{HookGrant, HookOutcome, VerbHookStop, filter};
use crate::skill_hub::pack_catalog::HookPhase;
use crate::store::SessionStoreView;
use crate::{Result, Vault};

use super::super::ask;
use super::super::storage::{
    HeldRun, SESSION_HOOK_UNAVAILABLE, SessionHookKey, SessionHooks, VerbHookStorage,
};
use super::{Chain, Hook, RunRecord, hook_name};

/// The receipt word of a run whose outcome its room could not carry out.
const UNAVAILABLE: &str = "unavailable";

/// Whether a hook's AddBlock, Propose, Enqueue or Effect on a session-only
/// call with no room overlay (a `no_record` row, an anonymous roomless
/// call) runs in the vault as on any call, only its receipts and saved runs
/// going to the in-memory keep (FIX 5525; the Engine asks whether such a
/// call's consequences should instead be its hook's terminal
/// `session_hook_unavailable:<work>`, as in a room). `true` holds today's
/// behaviour; `false` applies 2c's room rule to it. A room keeps 2c's rule
/// either way.
pub(crate) const KEPT_CALL_HOOK_CONSEQUENCES_RUN: bool = true;

/// The canonical work `outcome` needs, which a room does not do (CALLS-3
/// `session_hook_consequence_support`): an ask, a block, or a post chain's
/// proposal, queued task or effect. Each would land a TASK, a job, an
/// intent, a block or lineage in base from what the room read. `None` for
/// an outcome that runs in the room as on base.
fn canonical_work(outcome: &HookOutcome) -> Option<&'static str> {
    match outcome {
        HookOutcome::Ask { .. } => Some("ask"),
        HookOutcome::AddBlock { .. } => Some("add_block"),
        HookOutcome::Propose { .. } => Some("propose"),
        HookOutcome::Enqueue { .. } => Some("enqueue"),
        HookOutcome::Effect { .. } => Some("effect"),
        HookOutcome::Nothing
        | HookOutcome::Continue
        | HookOutcome::Rewrite { .. }
        | HookOutcome::Skip { .. }
        | HookOutcome::Annotate { .. }
        | HookOutcome::Redact { .. } => None,
    }
}

impl<'c> Chain<'c> {
    /// The room's view this chain's hooks read through; `None` on the vault,
    /// and for a session-only call with no room overlay.
    pub(super) fn view(&self) -> Result<Option<SessionStoreView<'c>>> {
        match self.storage {
            VerbHookStorage::Canonical => Ok(None),
            VerbHookStorage::Session(hooks) => hooks.view(),
        }
    }

    /// The lanes a hook reads through: the caller's, under the key its door
    /// carried, or its own; and, when the hook's grant reads as someone
    /// else, that reader's own, as a cap. In a room both read `view`, and a
    /// call with no key reads on its actor's own key, never on a key newly
    /// admitted for its hooks. A key that does not build gives no lane.
    pub(super) fn lanes<'v>(
        &self,
        grant: &HookGrant,
        view: Option<&'v SessionStoreView<'v>>,
    ) -> (Option<ScopedRead<'v>>, Option<Option<ScopedRead<'v>>>)
    where
        'c: 'v,
    {
        let vault: &'v Vault = self.vault;
        let key = match &self.call.reader {
            Some(key) => Some(key.clone()),
            None => vault
                .memory(self.call.actor, filter::edge_class(self.call.class))
                .read_key()
                .ok(),
        };
        let cap = (grant.reader != self.call.actor).then(|| {
            vault
                .memory(grant.reader, filter::edge_class(grant.reader_class))
                .read_key()
                .ok()
                .map(|key| lane(vault, view, key))
        });
        (key.map(|key| lane(vault, view, key)), cap)
    }

    /// The canonical work a run's `outcome` needs that this chain's room
    /// does not do; `None` on the vault, which does it. Every session-only
    /// call keeps its hook's ask in the keep (L13 PR-D; a room's under its
    /// stretch, FIX 5524). One with no room overlay runs its other
    /// consequences in the vault while [`KEPT_CALL_HOOK_CONSEQUENCES_RUN`]
    /// holds; a room keeps 2c's rule for them.
    pub(super) fn room_cannot(&self, outcome: Option<&HookOutcome>) -> Option<&'static str> {
        match self.storage {
            VerbHookStorage::Canonical => None,
            VerbHookStorage::Session(hooks) if hooks.kept_key().is_some() => outcome
                .filter(|_| !KEPT_CALL_HOOK_CONSEQUENCES_RUN)
                .and_then(canonical_work)
                .filter(|work| *work != "ask"),
            VerbHookStorage::Session(_) => outcome
                .and_then(canonical_work)
                .filter(|work| *work != "ask"),
        }
    }

    /// Opens the asking hook's ask for a session-only call (L13 PR-D, FIX
    /// 4283; a room's, FIX 5524): its resumed answer used up first, as on
    /// the vault, so one another try used meanwhile opens no ask; then the
    /// ask, its paused call kept under `key` (a room's with the route its
    /// run captured) and the chain's blocks and intents written in the ask's
    /// own write ([`Self::consequences_in_txn`]; a room's chain holds none);
    /// then the chain's runs held for the call to keep. A refused ask keeps
    /// and writes nothing, and the chain goes on as after any ask that did
    /// not open.
    pub(super) fn ask_in_session(
        &self,
        hooks: &SessionHooks<'_>,
        key: &SessionHookKey,
        index: usize,
        hook: Hook<'c>,
        args: &Value,
        label: &str,
    ) -> Result<std::result::Result<VerbHookStop, String>> {
        if let Err(error) = self.take_session_answer(hooks) {
            return if self.used.get() {
                Ok(Ok(self.used_stop()))
            } else {
                Err(error)
            };
        }
        let group = match ask::session::open(
            self.vault,
            key,
            self.call,
            hook,
            index,
            args,
            label,
            self.turn.as_ref(),
            hooks.paused_route(),
            &|txn: &mut heed::RwTxn<'_>| self.consequences_in_txn(txn),
        )? {
            Ok(group) => group,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.hold_in_session(hooks);
        Ok(Ok(ask::pending(self.call.invocation, group)))
    }

    /// Uses a resumed session-only call's answer up in the keep, once per
    /// call, in its pre commit before the verb runs, also when no hook runs
    /// after the asking one (L13 PR-D; a room's call too, FIX 5524). When
    /// another try used it meanwhile, the chain commits nothing and ends
    /// Skipped, as on the vault. A call that resumes none passes.
    pub(super) fn take_session_answer(&self, hooks: &SessionHooks<'_>) -> Result<()> {
        let Some(token) = &self.token else {
            return Ok(());
        };
        if hooks.take_answer() || ask::session::take(self.vault, hooks.pause_key(), token) {
            return Ok(());
        }
        self.used.set(true);
        Err(ask::used_error())
    }

    /// Holds the chain's receipts and saved runs, each with what the call's
    /// answer will say of it, for the call to keep in its session's own
    /// store once its read is done.
    pub(super) fn hold_in_session(&self, hooks: &SessionHooks<'_>) {
        let at = self
            .vault
            .store
            .clock
            .now_recorded_at()
            .saturating_mul(1_000);
        let phase = if self.phase == HookPhase::Post {
            SessionHookPhase::Post
        } else {
            SessionHookPhase::Pre
        };
        hooks.hold(self.runs.iter().map(|run| HeldRun {
            key: run.key,
            receipt: self.receipt(run),
            saved: self.saved(run, at),
            hook: hook_name(run.binding),
            phase,
            state: state(run),
        }));
    }
}

/// `read`, the vault's read of a call's hook `what` (its bindings, a
/// binding's scopes or its grant): its error noted on hooks that answer with
/// them unread ([`SessionHooks::answering_unread`]; Engine 10-19 17:1x), and
/// returned all the same.
pub(super) fn hook_read<T>(storage: VerbHookStorage<'_>, what: &str, read: Result<T>) -> Result<T> {
    if let (VerbHookStorage::Session(hooks), Err(error)) = (storage, &read) {
        hooks.note_unread(what, error);
    }
    read
}

/// What came of `run`, as the call's answer tells it (CALLS-9
/// `session_hook_meta_shape`).
fn state(run: &RunRecord<'_>) -> SessionHookState {
    match (run.unavailable, run.token.as_str()) {
        (Some(work), _) => SessionHookState::Unavailable {
            reason: SESSION_HOOK_UNAVAILABLE.to_owned(),
            consequence: work.to_owned(),
        },
        (None, "refused" | "failed") => SessionHookState::Refused {
            outcome: run.token.clone(),
            reason: run.reason.clone(),
            fail_safe: run.fail_safe.map(str::to_owned),
        },
        (None, outcome) => SessionHookState::Applied {
            outcome: outcome.to_owned(),
        },
    }
}

impl RunRecord<'_> {
    /// Marks this run's outcome as one its room could not carry out, `work`
    /// naming what it needed: terminal, and before any ask, block, lineage
    /// or apply runs.
    pub(super) fn unavailable(&mut self, work: &'static str) {
        self.token = UNAVAILABLE.to_owned();
        self.reason = Some(format!("{SESSION_HOOK_UNAVAILABLE}:{work}"));
        self.unavailable = Some(work);
    }
}

/// `key`'s lane over `view`, or over the vault with no room, serving every
/// claim status as a hook's reads do.
fn lane<'v>(
    vault: &'v Vault,
    view: Option<&'v SessionStoreView<'v>>,
    key: ScopedReadActorKey,
) -> ScopedRead<'v> {
    match view {
        Some(view) => vault.scoped_read_in_session(key, view),
        None => vault.scoped_read(key),
    }
    .with_claim_status(ClaimReadStatus::Recorded)
}
