//! A run's read-world capture as its host serves it (FIX 6130). The executor
//! holds one capture epoch of the run's ledger open for each entry of the run
//! ([`ReadWorldEntry`]). Every answer the run's host releases meets
//! [`HostSelfDispatcher::read_worlds_answered`] first: an answer that carries
//! no row of the vault ([`serves_no_rows`]), or one its own capture already
//! noted, passes; any other marks the ledger unknown. A ledger write that
//! fails leaves the epoch open, so the ledger never reads complete past it.
//! A blocked report the run files freezes its ledger only under a clean epoch
//! ([`HostSelfDispatcher::read_world_seal`]). Instrumentation never refuses or
//! fails the call it watches. A search also freezes each served row's Scope
//! at its bridge position for a later step-capsule projection (FIX 7162).
//! A descriptor of one of the run's results that another run reads freezes
//! the ledger's origins under the same clean epoch, and a read of another
//! run's result notes the origins its descriptor froze, or, with none,
//! marks the ledger unknown (FIX 7084). A delivered wait's reply notes the
//! origins its settler froze with it, at the position of the call parked on
//! the wait, or, with none, marks the ledger unknown (FIX 7083).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::code_run::ResultOrigins;
use crate::code_run::storage::{ReadWorldSeal, ReadWorldUnknown};
use crate::code_run::types::{AgentVerbAnswer, SelfDispatchOutcome};
use crate::federation::Scope;
use crate::memory::read_capture::CapturedRead;
use crate::{EntityId, ScoredEntity, Vault};

/// The capture epoch a dispatcher holds for one run.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ReadWorldLive {
    run: Option<EntityId>,
    epoch: Option<EntityId>,
    /// Every ledger write of the epoch landed.
    clean: bool,
    /// The ledger already holds a cause it misses rows for, so it can never
    /// read complete again: a later cause adds nothing it needs written.
    marked: bool,
    /// The last call's own capture noted its answer's worlds.
    covered: bool,
}

/// A served row's worlds and scope as the read that served it proves them;
/// either is `None` when that read cannot prove it.
pub(super) struct ServedRow {
    worlds: Option<BTreeSet<EntityId>>,
    scope: Option<Scope>,
}

/// Each served row's proof, or `None` where the row itself did not read.
pub(super) type ServedRows = HashMap<EntityId, Option<ServedRow>>;

/// One entry's capture epoch, closed as the entry ends when every ledger
/// write of it landed. An entry that unwinds leaves it open.
pub(crate) struct ReadWorldEntry<'d, 'a> {
    dispatcher: &'d HostSelfDispatcher<'a>,
}

impl Drop for ReadWorldEntry<'_, '_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.dispatcher.leave_read_worlds();
        }
    }
}

impl<'a> HostSelfDispatcher<'a> {
    /// Declares `task` the caller's own text for `run` (FIX 6130, FIX 7087),
    /// as an MCP `execute_code` caller's is: no row of the vault wrote it.
    /// The declaration covers that exact text only. An entry of `run` whose
    /// task is not exactly `task`, such as one its host added to, still marks
    /// the host task. A run whose host builds its task declares nothing, and
    /// its ledger never reads complete, since that task may carry rows no
    /// capture noted. Every other cause the run meets marks the ledger as
    /// before. A self-written summary that wore the run's home marks it when
    /// it lands (FIX 7087).
    #[must_use]
    pub fn with_caller_task(mut self, run: EntityId, task: &str) -> Self {
        self.caller_task = Some((run, task.to_owned()));
        self
    }

    /// Enters a capture epoch of `run`'s ledger for one entry of the run,
    /// which runs `task`. Only a task its host declared the caller's own,
    /// byte for byte, is spared the host-task mark (FIX 7087).
    pub(crate) fn enter_read_worlds(&self, run: EntityId, task: &str) -> ReadWorldEntry<'_, 'a> {
        self.read_worlds.set(self.opened(run));
        let declared = self
            .caller_task
            .as_ref()
            .is_some_and(|(caller_run, caller_task)| *caller_run == run && caller_task == task);
        if !declared {
            self.read_worlds_unknown(run, ReadWorldUnknown::HostTask);
        }
        ReadWorldEntry { dispatcher: self }
    }
}

impl HostSelfDispatcher<'_> {
    /// A fresh epoch of `run`'s ledger, opened on the run's storage.
    fn opened(&self, run: EntityId) -> ReadWorldLive {
        let epoch = EntityId::now();
        ReadWorldLive {
            run: Some(run),
            epoch: Some(epoch),
            clean: self.storage.open_read_world_epoch(run, epoch).is_ok(),
            marked: false,
            covered: false,
        }
    }

    /// The epoch held for `run`: its entry's, or, for a run no entry holds,
    /// one opened now, which nothing closes.
    fn live_for(&self, run: EntityId) -> ReadWorldLive {
        let live = self.read_worlds.get();
        if live.run == Some(run) {
            live
        } else {
            self.opened(run)
        }
    }

    /// Ends the entry: its epoch closes when every ledger write of it
    /// landed, and stays open otherwise.
    fn leave_read_worlds(&self) {
        let live = self.read_worlds.take();
        if let (Some(run), Some(epoch), true) = (live.run, live.epoch, live.clean) {
            // A close that fails leaves the epoch open, as a failed write
            // does: the ledger then never reads complete.
            let _ = self.storage.close_read_world_epoch(run, epoch);
        }
    }

    /// Marks `run`'s ledger as missing rows it was served, for `cause`, once
    /// per epoch. A mark that fails leaves the epoch open.
    pub(crate) fn read_worlds_unknown(&self, run: EntityId, cause: ReadWorldUnknown) {
        let mut live = self.live_for(run);
        if !live.marked {
            match self.storage.mark_read_world_unknown(run, cause) {
                Ok(()) => live.marked = true,
                Err(_) => live.clean = false,
            }
        }
        self.read_worlds.set(live);
    }

    /// The guard every answer the host of `run` releases meets first (FIX
    /// 6130): a verb hook's own view of the answer, or an answer that may
    /// carry a row no capture noted, marks the run's ledger unknown.
    pub(crate) fn read_worlds_answered(
        &self,
        run: EntityId,
        outcome: &SelfDispatchOutcome,
        hook_view: bool,
    ) {
        let mut live = self.read_worlds.get();
        let covered = std::mem::take(&mut live.covered);
        self.read_worlds.set(live);
        let noted = covered
            && matches!(
                outcome,
                SelfDispatchOutcome::MemorySearch(_) | SelfDispatchOutcome::AgentVerb(_)
            );
        if hook_view {
            self.read_worlds_unknown(run, ReadWorldUnknown::HookView);
        } else if !noted && !serves_no_rows(outcome) {
            self.read_worlds_unknown(run, ReadWorldUnknown::Uncaptured);
        }
    }

    /// Forgets an earlier call's capture: an answer is covered by its own
    /// call's capture only.
    pub(super) fn uncover_read_worlds(&self) {
        let mut live = self.read_worlds.get();
        live.covered = false;
        self.read_worlds.set(live);
    }

    /// The seal a blocked report of the run `run` freezes its ledger under:
    /// the entry's epoch, while every ledger write of it landed.
    pub(super) fn read_world_seal(&self, run: Option<EntityId>) -> Option<ReadWorldSeal> {
        let live = self.read_worlds.get();
        let epoch = live
            .epoch
            .filter(|_| live.clean && run.is_some() && live.run == run)?;
        Some(ReadWorldSeal { epoch })
    }

    /// The origins of `run`'s results as its ledger stands now, frozen for a
    /// descriptor another run reads one of them by (FIX 7084): read under the
    /// entry's seal, while every ledger write of the entry landed. `None`
    /// when the ledger is not complete, or cannot be read.
    pub(crate) fn frozen_result_origins(&self, run: EntityId) -> Option<ResultOrigins> {
        let seal = self.read_world_seal(Some(run))?;
        self.storage.result_origins(run, seal).ok().flatten()
    }

    /// Notes what a read of another run's result serves `run` at bridge
    /// position `at` (FIX 7084): the worlds and row scopes its descriptor
    /// froze, and a proof of no scope for each row it froze as conflicted,
    /// so no other proof gives that row a scope. A result whose origins are
    /// unknown marks the ledger `RetainedResult`. The source run's ledger as
    /// it stands now is never read here.
    pub(crate) fn read_worlds_retained(
        &self,
        run: EntityId,
        at: u64,
        origins: Option<&ResultOrigins>,
    ) {
        self.note_served_origins(run, at, origins, ReadWorldUnknown::RetainedResult);
    }

    /// Notes what a delivered wait's reply serves `run` at bridge position
    /// `at`, the position of the call parked on the wait (FIX 7083): the
    /// worlds and row scopes its settler froze with it, and a proof of no
    /// scope for each row they hold as conflicted. A reply whose origins are
    /// unknown marks the ledger `WaitReply`. A ledger write that fails marks
    /// it unknown and never fails the resume.
    pub(crate) fn read_worlds_wait_reply(
        &self,
        run: EntityId,
        at: u64,
        origins: Option<&ResultOrigins>,
    ) {
        self.note_served_origins(run, at, origins, ReadWorldUnknown::WaitReply);
    }

    /// Notes `origins` as served to `run` at bridge position `at`: their
    /// worlds, then their row scopes and conflicted rows once the worlds
    /// landed. Unknown origins mark the ledger for `unknown`.
    fn note_served_origins(
        &self,
        run: EntityId,
        at: u64,
        origins: Option<&ResultOrigins>,
        unknown: ReadWorldUnknown,
    ) {
        let Some(origins) = origins else {
            self.read_worlds_unknown(run, unknown);
            return;
        };
        if self.read_worlds_noted(run, at, &origins.worlds) {
            self.read_rows_noted(run, at, &origins.row_scopes, &origins.conflicted_rows);
        }
    }

    /// Notes the worlds of `hits`, the hits a canonical executor run's search
    /// serves at `site`, in the run's ledger: each as `scored` proves it in
    /// the read that scored it and, for a keyed search, as `admitted` proves
    /// it in the read that admitted it. A hit whose worlds either read
    /// cannot prove marks the ledger unknown instead. A scope gap leaves only
    /// that row's scope proof missing; it never takes away proved worlds.
    pub(super) fn note_search_worlds(
        &self,
        site: ExecutorCallSite<'_>,
        hits: &[ScoredEntity],
        scored: &ServedRows,
        admitted: Option<&ServedRows>,
    ) {
        let mut worlds = BTreeSet::new();
        let mut rows = BTreeMap::new();
        let mut unproved_rows = BTreeSet::new();
        for hit in hits {
            for proofs in std::iter::once(scored).chain(admitted) {
                let Some(served) = proofs.get(&hit.id).and_then(Option::as_ref) else {
                    self.read_worlds_unknown(site.run_id, ReadWorldUnknown::Unproved);
                    return;
                };
                let Some(served_worlds) = served.worlds.as_ref() else {
                    self.read_worlds_unknown(site.run_id, ReadWorldUnknown::Unproved);
                    return;
                };
                worlds.extend(served_worlds.iter().copied());
                if unproved_rows.contains(&hit.id) {
                    continue;
                }
                if let Some(scope) = served.scope.as_ref() {
                    if rows
                        .insert(hit.id, scope.clone())
                        .is_some_and(|prior| prior != *scope)
                    {
                        rows.remove(&hit.id);
                        unproved_rows.insert(hit.id);
                    }
                } else {
                    rows.remove(&hit.id);
                    unproved_rows.insert(hit.id);
                }
            }
        }
        let worlds_noted = self.read_worlds_noted(site.run_id, site.seq, &worlds);
        let rows_noted = self.read_rows_noted(site.run_id, site.seq, &rows, &BTreeSet::new());
        if worlds_noted && rows_noted {
            let mut live = self.read_worlds.get();
            live.covered = true;
            self.read_worlds.set(live);
        }
    }

    /// Notes a live native point-read only from its own successful projections.
    /// Every additional row the answer releases must have the same-call proof.
    pub(super) fn note_verb_read_worlds(
        &self,
        site: ExecutorCallSite<'_>,
        answer: &AgentVerbAnswer,
        captured: Option<CapturedRead>,
    ) {
        let Some(captured) = captured else {
            return;
        };
        if captured.changed {
            self.read_worlds_unknown(site.run_id, ReadWorldUnknown::HookView);
            return;
        }
        if captured.views.is_empty() {
            return;
        }
        let Some(released) = answer.released_rows() else {
            return;
        };
        let proved: BTreeSet<_> = captured.views.iter().map(|(id, _)| *id).collect();
        if released.iter().any(|id| !proved.contains(id)) {
            self.read_worlds_unknown(site.run_id, ReadWorldUnknown::Unproved);
            return;
        }
        let mut worlds = BTreeSet::new();
        let mut rows = BTreeMap::new();
        let mut unproved_rows = BTreeSet::new();
        for (id, view) in captured.views {
            let Some(served_worlds) = view.worlds else {
                self.read_worlds_unknown(site.run_id, ReadWorldUnknown::Unproved);
                return;
            };
            worlds.extend(served_worlds);
            if unproved_rows.contains(&id) {
                continue;
            }
            if let Some(scope) = view.scope {
                if rows
                    .insert(id, scope.clone())
                    .is_some_and(|prior| prior != scope)
                {
                    rows.remove(&id);
                    unproved_rows.insert(id);
                }
            } else {
                rows.remove(&id);
                unproved_rows.insert(id);
            }
        }
        let worlds_noted = self.read_worlds_noted(site.run_id, site.seq, &worlds);
        let rows_noted = self.read_rows_noted(site.run_id, site.seq, &rows, &BTreeSet::new());
        if worlds_noted && rows_noted {
            let mut live = self.read_worlds.get();
            live.covered = true;
            self.read_worlds.set(live);
        }
    }

    /// Notes `worlds` as served to `run` at bridge position `at`: `true` once
    /// the ledger holds them. A write that fails marks the ledger unknown
    /// and leaves the epoch open.
    fn read_worlds_noted(&self, run: EntityId, at: u64, worlds: &BTreeSet<EntityId>) -> bool {
        if worlds.is_empty() {
            return true;
        }
        let mut live = self.live_for(run);
        let noted = self.storage.note_read_worlds(run, at, worlds).is_ok();
        live.clean &= noted;
        self.read_worlds.set(live);
        if !noted {
            self.read_worlds_unknown(run, ReadWorldUnknown::WriteFailed);
        }
        noted
    }

    /// Notes `rows` and their scopes as served to `run` at bridge position
    /// `at`, and each row of `conflicted` with a proof of no scope (FIX
    /// 7084): `true` once the ledger holds them. A write that fails marks the
    /// ledger unknown and leaves the epoch open.
    fn read_rows_noted(
        &self,
        run: EntityId,
        at: u64,
        rows: &BTreeMap<EntityId, Scope>,
        conflicted: &BTreeSet<EntityId>,
    ) -> bool {
        if rows.is_empty() && conflicted.is_empty() {
            return true;
        }
        let mut live = self.live_for(run);
        let noted = self
            .storage
            .note_read_rows(run, at, rows, conflicted)
            .is_ok();
        live.clean &= noted;
        self.read_worlds.set(live);
        if !noted {
            self.read_worlds_unknown(run, ReadWorldUnknown::WriteFailed);
        }
        noted
    }
}

/// The worlds and scope of the row `id` as the read `txn` serves it, base
/// reality by its own id; either is `None` where that read cannot prove it
/// (FIX 6130, FIX 7162). A NOTE in several worlds outside base notes every
/// one (FIX-LIST 9433).
pub(super) fn served_row_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Option<ServedRow> {
    use crate::ports::EntityStore;
    let row = vault.port_entity_get(txn, &id).ok()??;
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id).ok()??;
    let worlds = crate::federation::record_scope::note_world::served_worlds_in(
        &vault.store,
        txn,
        id,
        row.entity_type,
        &row.body,
    )
    .ok()
    .flatten();
    let scope = crate::federation::record_scope::scope_for_blob(&vault.store, txn, id, &raw)
        .ok()
        .flatten();
    Some(ServedRow { worlds, scope })
}

/// Whether `outcome` carries no row of the vault (FIX 6130): a speech
/// receipt, a context descriptor, a blocked report's receipt, an own write's
/// id, a failure in engine words, or a refusal that carries no reason of its
/// own. Any other answer marks its run's ledger unknown unless its own
/// capture noted it: a refusal's reasons may be a hook's own words.
fn serves_no_rows(outcome: &SelfDispatchOutcome) -> bool {
    match outcome {
        SelfDispatchOutcome::Speech(_)
        | SelfDispatchOutcome::Context(_)
        | SelfDispatchOutcome::ReportBlocked { .. }
        | SelfDispatchOutcome::MemoryWrite(_)
        | SelfDispatchOutcome::Failed(_) => true,
        SelfDispatchOutcome::Denied(denied) => denied.reason_codes.is_empty(),
        _ => false,
    }
}
