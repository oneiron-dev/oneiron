//! A chain of a session-only call (WILL L11-01 S01-2c): the lanes its hooks
//! read through, over a room's view; the session rule for an outcome that
//! needs canonical work; and its runs held for the call to keep, each with
//! what the call's answer will say of it.

use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadActorKey};
use crate::code_run::{SessionHookPhase, SessionHookState};
use crate::runtime_hooks::{HookGrant, HookOutcome, filter};
use crate::skill_hub::pack_catalog::HookPhase;
use crate::store::SessionStoreView;
use crate::{Result, Vault};

use super::super::storage::{HeldRun, SESSION_HOOK_UNAVAILABLE, SessionHooks, VerbHookStorage};
use super::{Chain, RunRecord, hook_name};

/// The receipt word of a run whose outcome its room could not carry out.
const UNAVAILABLE: &str = "unavailable";

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
    /// does not do; `None` on the vault, which does it.
    pub(super) fn room_cannot(&self, outcome: Option<&HookOutcome>) -> Option<&'static str> {
        match self.storage {
            VerbHookStorage::Canonical => None,
            VerbHookStorage::Session(_) => outcome.and_then(canonical_work),
        }
    }

    /// A room opens no ask: the refusal a write's failed blocking hook
    /// meets there, as when its ask does not open on the vault. `None` on
    /// the vault.
    pub(super) fn room_ask_refusal(&self) -> Option<String> {
        matches!(self.storage, VerbHookStorage::Session(_))
            .then(|| format!("{SESSION_HOOK_UNAVAILABLE}:ask"))
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
        (None, "refused" | "failed" | "timed_out") => SessionHookState::Refused {
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
