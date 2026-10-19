//! The one session-only store of runtime-hook records (WILL L11-01 S01-2c;
//! Engine 10-19): where a verb hook chain that runs in a room keeps what its
//! runs leave.
//!
//! A hook bound to a verb runs in a room as it runs on base, under the
//! vault's authority: its binding, code, grant and `hooks.enabled`, and the
//! caller's membership and credential. Its content reads go through the
//! room's view, and its records stage here, never in base by a side door.
//!
//! The store is row-generic: [`OffRecordSession::stage_hook_records`] stages,
//! reads and drops any declared side-table rows of a chain's record families
//! (receipts, saved runs and their index today; blocks, lineage and intents
//! are the same kind of row) in ONE segment of their own, apart from the
//! read's telemetry and the run's replay records. Its writer reads each row
//! through the room's composed view and puts or deletes it along the run's
//! captured route, so a saved run replaces its last with the same keys as on
//! base. A standing record is read back through
//! [`OffRecordSession::routed_side_read`], as every room side row is. The
//! route decides where the segment goes (CALLS-2 `session_hook_write_target`):
//!
//! - off record, into the room's overlay, as ordinary budgeted bytes;
//! - on record, into base under the saver's check, unless the room holds
//!   unsaved rows a hook may have read: then, as the room's retrieval
//!   telemetry does, nothing lands in base, and the landing's checks still
//!   run;
//! - anonymous, into the in-memory keep (`SessionHookKeep`) under the room's
//!   own session-instance key, never the room's overlay or base: the room
//!   retains no record, and the room's close drops the keep's (FIX 5431).
//!
//! A room that keeps no record of a chain (its budget refused the segment, a
//! record held a secret only a vault's custody door could mint, an anonymous
//! room's stretch is closing or gone, or it withheld the records from base)
//! answers which, and the hook's outcome applies all the same (CALLS-4
//! `session_receipt_budget_policy`, `HookRecordsKept::of`). A refusal of the
//! room's own authority (a route that flipped, a participant who left, a
//! saver who no longer holds, a room that is closing) fails the call, as on
//! every room write. A session-only call with no room overlay keeps its
//! records in the in-memory keep instead (`SessionHookKeep`, on the vault's
//! verb-hook state), keyed by its session or the process
//! ([`Vault::session_hook_key`], L13 PR-D); the session's close drops them.

use serde_json::Value;

use crate::code_run::{SessionHookDisposition, SessionHookNotKept};
use crate::error::Result;
use crate::runtime_hooks::verb::{
    HookRecordsKept, RoomHookCall, SessionHookKey, SessionHooks, VerbArgsCheck, VerbHookStorage,
};
use crate::runtime_hooks::{VerbCall, VerbHookPre, VerbHookStop};
use crate::session_overlay::{RouteTarget, SessionWriteRoute};
use crate::side_table::RoutedDbs;
use crate::{EntityId, Vault};

use super::registry::session_entry_state;
use super::session::OffRecordSession;

/// The pre or post chain's end in a room, and what each hook did.
type InRoom<T> = (
    std::result::Result<T, VerbHookStop>,
    Vec<SessionHookDisposition>,
);

impl OffRecordSession<'_> {
    /// This stretch's key in the in-memory keep: its registry key and when
    /// it was entered. An anonymous room's hook records wait there (FIX
    /// 5431), and every room's hook pauses (FIX 5524); its close drops it.
    ///
    /// # Errors
    ///
    /// A poisoned session lock.
    pub(crate) fn hook_key(&self) -> Result<SessionHookKey> {
        Ok(SessionHookKey::Session {
            key: self.session_ref.clone(),
            entered_at: session_entry_state(&self.entry)?.record.entered_at,
        })
    }

    /// Stages one chain's records along `route`, the route the call's run
    /// captured: `rows` reads through the room's composed view and puts or
    /// deletes along the route, in one segment of its own.
    ///
    /// # Errors
    ///
    /// The room's authority refusals; storage errors. A room that keeps no
    /// record answers [`HookRecordsKept::NotKept`] instead.
    pub(crate) fn stage_hook_records(
        &self,
        route: &SessionWriteRoute,
        rows: impl FnOnce(&mut heed::RwTxn<'_>, RoutedDbs<'_>, RoutedDbs<'_>) -> Result<()>,
    ) -> Result<HookRecordsKept> {
        match route.target() {
            RouteTarget::Discard => {
                // An anonymous room's chain keeps its records in RAM only,
                // under this stretch's own key, which its close drops
                // (FIX 5431); one closing or gone keeps none.
                route.revalidate()?;
                let key = self.hook_key()?;
                return self
                    .vault
                    .verb_hook_state
                    .session
                    .stage(self.vault, &key, rows);
            }
            RouteTarget::Base if self.read_view()?.read().holds_room_rows() => {
                let landing = self.landing(route)?;
                let txn = self.vault.store.env.read_txn()?;
                landing.in_txn(&txn)?;
                return Ok(HookRecordsKept::NotKept(
                    SessionHookNotKept::WithheldFromBase,
                ));
            }
            RouteTarget::Base | RouteTarget::Overlay => {}
        }
        HookRecordsKept::of(self.routed_side_txn(route, rows))
    }

    /// The pre chain of `call` over `args` in this room, on `route`, the
    /// route the call's run captured: as on base, with the room's view for
    /// content and this store for records. A room saves no resume target
    /// for settlement; a hook's ask pauses the call in RAM under this
    /// stretch, with `route`, and its caller's retry here resumes it (FIX
    /// 5524). The pre carries its records to the call's post chain, or to
    /// [`Self::keep_verb_hooks_in_room`]; one that stops the call keeps them
    /// now. `how` says whether a failed read of the hooks passes the call
    /// through and notes why (`SessionHooks::answering_unread`), the
    /// task-work turn the calling operation holds, which a hook's ask runs
    /// on, and the pause the call names as the one it resumes. The chain's
    /// entry points for a room live here, beside its store, since the vault
    /// a chain runs on never leaves this module's handle.
    ///
    /// # Errors
    ///
    /// As [`Self::stage_hook_records`], and the vault's own storage errors;
    /// a resume where the room's route or the run's place in it no longer
    /// holds.
    pub(crate) fn pre_verb_hooks_in_room(
        &self,
        route: &SessionWriteRoute,
        call: VerbCall,
        args: Value,
        check: VerbArgsCheck<'_>,
        how: RoomHookCall,
    ) -> Result<InRoom<VerbHookPre>> {
        let hooks = room_hooks(self, route, how.answers_unread)?.resuming(how.resume);
        let ended = self.vault.pre_verb_hooks_in(
            VerbHookStorage::Session(&hooks),
            call,
            args,
            check,
            how.turn,
        )?;
        Ok((ended, hooks.into_dispositions()))
    }

    /// The post chain over the verb's `result` in this room, for a call
    /// whose pre chain ran here on `route`: it keeps the call's records,
    /// the pre chain's first, once it ends. `answers_unread` as for its pre
    /// chain.
    ///
    /// # Errors
    ///
    /// As [`Self::pre_verb_hooks_in_room`].
    pub(crate) fn post_verb_hooks_in_room(
        &self,
        route: &SessionWriteRoute,
        pre: VerbHookPre,
        result: Value,
        answers_unread: bool,
    ) -> Result<InRoom<Value>> {
        let hooks = room_hooks(self, route, answers_unread)?;
        let ended = self
            .vault
            .post_verb_hooks_in(VerbHookStorage::Session(&hooks), pre, result)?;
        Ok((ended, hooks.into_dispositions()))
    }

    /// Keeps the records `pre`'s chain holds for a call in this room that
    /// ended with no result for a post chain to read: refused, failed or
    /// parked.
    ///
    /// # Errors
    ///
    /// As [`Self::pre_verb_hooks_in_room`].
    pub(crate) fn keep_verb_hooks_in_room(
        &self,
        route: &SessionWriteRoute,
        pre: VerbHookPre,
    ) -> Result<Vec<SessionHookDisposition>> {
        let hooks = SessionHooks::new(self, route, self.hook_key()?);
        self.vault
            .keep_verb_hooks_in(VerbHookStorage::Session(&hooks), pre)?;
        Ok(hooks.into_dispositions())
    }
}

/// The hooks of a call in `session`'s room on `route`, its hooks' pauses
/// kept under the stretch's own key; with `answers_unread`, a call that
/// answers when they cannot be read.
fn room_hooks<'s>(
    session: &'s OffRecordSession<'s>,
    route: &'s SessionWriteRoute,
    answers_unread: bool,
) -> Result<SessionHooks<'s>> {
    let hooks = SessionHooks::new(session, route, session.hook_key()?);
    Ok(if answers_unread {
        hooks.answering_unread()
    } else {
        hooks
    })
}

impl Vault {
    /// The in-memory keep's key of a session-only call with no room overlay
    /// whose surface binds `binding`, its off-record session and the
    /// principal it binds it for (`Memory::off_record_binding`; L13 PR-D,
    /// FIX 4283): the live stretch that binding names, by its registry key
    /// and when it was entered, read as
    /// [`Self::off_record_session_is_anonymous_for`] reads it (a creator's
    /// name resolves to its instance). The process when the surface binds
    /// none, or names no live stretch: a `no_record` row called before its
    /// session starts, or a session header that names no off-record stretch,
    /// keeps working as today. A stretch that is closing keeps its own key,
    /// which the keep no longer takes anything under, so the call answers as
    /// today and nothing of it outlives the stretch. The close drops a
    /// session's key ([`Self::close_off_record_entry`]).
    pub(crate) fn session_hook_key(
        &self,
        binding: Option<(&str, Option<EntityId>)>,
    ) -> SessionHookKey {
        let Some((session, principal)) = binding else {
            return SessionHookKey::Process;
        };
        let session = session.trim();
        let registry = &self.store.off_record_sessions;
        let key = principal
            .and_then(|principal| registry.created_key(session, principal))
            .unwrap_or_else(|| session.to_owned());
        match registry.record(&key) {
            Some(record) => SessionHookKey::Session {
                key,
                entered_at: record.entered_at,
            },
            None => SessionHookKey::Process,
        }
    }
}
