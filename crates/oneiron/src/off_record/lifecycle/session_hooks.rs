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
//! - anonymous, nowhere: the room retains no record.
//!
//! A room that keeps no record of a chain (its budget refused the segment, a
//! record held a secret only a vault's custody door could mint, it is
//! anonymous, or it withheld the records from base) answers which, and the
//! hook's outcome applies all the same (CALLS-4
//! `session_receipt_budget_policy`, `HookRecordsKept::of`). A refusal of the
//! room's own authority (a route that flipped, a participant who left, a
//! saver who no longer holds, a room that is closing) fails the call, as on
//! every room write. A session-only call with no room overlay keeps its
//! records in the in-memory keep instead (`SessionHookKeep`, on the vault's
//! verb-hook state), keyed by its session or the process.

use serde_json::Value;

use crate::code_run::{SessionHookDisposition, SessionHookNotKept};
use crate::error::Result;
use crate::runtime_hooks::verb::{HookRecordsKept, SessionHooks, VerbArgsCheck, VerbHookStorage};
use crate::runtime_hooks::{VerbCall, VerbHookPre, VerbHookStop};
use crate::session_overlay::{RouteTarget, SessionWriteRoute};
use crate::side_table::RoutedDbs;

use super::session::OffRecordSession;

/// The pre or post chain's end in a room, and what each hook did.
type InRoom<T> = (
    std::result::Result<T, VerbHookStop>,
    Vec<SessionHookDisposition>,
);

impl OffRecordSession<'_> {
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
                route.revalidate()?;
                return Ok(HookRecordsKept::NotKept(SessionHookNotKept::NoRetention));
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
    /// and opens no ask. The pre carries its records to the call's post
    /// chain, or to [`Self::keep_verb_hooks_in_room`]; one that stops the
    /// call keeps them now. The chain's entry points for a room live here,
    /// beside its store, since the vault a chain runs on never leaves this
    /// module's handle.
    ///
    /// # Errors
    ///
    /// As [`Self::stage_hook_records`], and the vault's own storage errors.
    pub(crate) fn pre_verb_hooks_in_room(
        &self,
        route: &SessionWriteRoute,
        call: VerbCall,
        args: Value,
        check: VerbArgsCheck<'_>,
    ) -> Result<InRoom<VerbHookPre>> {
        let hooks = SessionHooks::new(self, route);
        let ended = self.vault.pre_verb_hooks_in(
            VerbHookStorage::Session(&hooks),
            call,
            args,
            check,
            None,
        )?;
        Ok((ended, hooks.into_dispositions()))
    }

    /// The post chain over the verb's `result` in this room, for a call
    /// whose pre chain ran here on `route`: it keeps the call's records,
    /// the pre chain's first, once it ends.
    ///
    /// # Errors
    ///
    /// As [`Self::pre_verb_hooks_in_room`].
    pub(crate) fn post_verb_hooks_in_room(
        &self,
        route: &SessionWriteRoute,
        pre: VerbHookPre,
        result: Value,
    ) -> Result<InRoom<Value>> {
        let hooks = SessionHooks::new(self, route);
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
        let hooks = SessionHooks::new(self, route);
        self.vault
            .keep_verb_hooks_in(VerbHookStorage::Session(&hooks), pre)?;
        Ok(hooks.into_dispositions())
    }
}
