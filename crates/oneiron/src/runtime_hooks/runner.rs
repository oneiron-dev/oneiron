//! The fact-hook runner (ARCH-0080 §4 Delivery). It reads each source after
//! its bindings' cursors, filters in Rust, runs each matching body once per
//! run key, and commits the run's memo, its run index row, local outcomes,
//! receipt, intents and cursor in one write. Delivery is at least once, in
//! commit order, per hook and per source. Due watcher TASKs tick on the
//! runner's own wake: each pass on the vault's home releases them into the
//! tick feed, hooks on or off, with a binding to take a tick or none, and the
//! [`HOOK_RUNNER_TICK`] re-read bounds how late a tick runs (FIX 4749, 22180).

mod body;
mod commit;
mod evaluation;
mod hook_feeds;
mod retained;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::receipt::hex_lower;
use crate::skill_hub::pack_catalog::{HookActorClass, HookPhase, PackHookBinding};
use crate::{EntityId, Error, Result, Vault};

use super::apply;
use super::block;
use super::body::{HookBodyRuntime, HookVerdict};
use super::filter;
use super::grant::{self, HookGrant};
use super::read::{self, SeenFact};
use super::source::{self, FactEntry, FactKind, FactPosition, FactSource};
use super::store::{self, HookRunState, RunKey};

pub(super) use body::{Verdict, ask_verdict, judge, verdict_context};
pub(crate) use hook_feeds::prune_hook_feeds;
use retained::RetainedPass;

/// Entries one pass reads from each source: the in-memory cap. A source with
/// more is read again from its cursors on the next pass.
pub const HOOK_PASS_ENTRIES: usize = 256;
/// How often the runner re-reads its cursors without a change notice: not
/// every claim write notifies.
pub const HOOK_RUNNER_TICK: Duration = Duration::from_secs(2);
/// Admits one runner pass, or refuses it with `None`; the pass holds what it
/// returns until it ends. Managed serve hands in its reap freeze, so a frozen
/// vault runs no hook and a pass in flight keeps it from reading quiescent.
pub type HookPassAdmission = std::sync::Arc<dyn Fn() -> Option<Box<dyn Send>> + Send + Sync>;
/// The largest input a memo row pins.
pub(super) const MAX_PINNED_INPUT: usize = 256 * 1024;
/// The longest reason or error a receipt field carries.
const MAX_FIELD: usize = 512;

/// The fact-hook runner. One per vault.
#[derive(Default)]
pub struct FactHookRunner {
    /// Pending intents were drained since start (or since the last failed
    /// pass).
    drained: AtomicBool,
    /// Answers `ai.verdict` for generative hooks; without it none is.
    verdict: Option<std::sync::Arc<dyn HookVerdict>>,
}

impl std::fmt::Debug for FactHookRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactHookRunner")
            .field("drained", &self.drained)
            .field("verdict", &self.verdict.is_some())
            .finish()
    }
}

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookPassReport {
    /// `hooks.enabled` is off; the pass released due ticks and read nothing.
    pub disabled: bool,
    pub entries_read: usize,
    pub runs: usize,
    pub memo_hits: usize,
    /// Facts a hook did not take: filtered, or withheld from its grant.
    pub skipped: usize,
    pub refused: usize,
    pub failed: usize,
    pub intents_applied: usize,
    pub intents_refused: usize,
    /// Owner checks raised for cycles and deep chains.
    pub checks: usize,
    /// A source held more entries than this pass read, or due ticks remain.
    pub more: bool,
}

impl HookPassReport {
    fn append(&mut self, next: Self) {
        self.disabled |= next.disabled;
        self.entries_read += next.entries_read;
        self.runs += next.runs;
        self.memo_hits += next.memo_hits;
        self.skipped += next.skipped;
        self.refused += next.refused;
        self.failed += next.failed;
        self.intents_applied += next.intents_applied;
        self.intents_refused += next.intents_refused;
        self.checks += next.checks;
        self.more |= next.more;
    }

    fn count(&mut self, verdict: &Verdict) {
        self.runs += 1;
        match verdict.state {
            HookRunState::Completed => {}
            HookRunState::Refused => self.refused += 1,
            HookRunState::Failed => self.failed += 1,
        }
    }
}

/// Enabled fact bindings from the caller's live-binding snapshot, in run order.
pub(crate) fn fact_bindings(
    all: &[(EntityId, PackHookBinding)],
) -> Vec<(EntityId, PackHookBinding)> {
    let mut bindings: Vec<(EntityId, PackHookBinding)> = all
        .iter()
        .filter(|(_, binding)| binding.enabled && binding.selector.phase == HookPhase::Fact)
        .cloned()
        .collect();
    bindings.sort_by(|(_, a), (_, b)| {
        b.selector
            .priority
            .cmp(&a.selector.priority)
            .then_with(|| a.body_hash.cmp(&b.body_hash))
    });
    bindings
}

impl FactHookRunner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The runner whose generative hooks ask `ai.verdict` of `verdict`.
    #[must_use]
    pub fn with_verdict(mut self, verdict: std::sync::Arc<dyn HookVerdict>) -> Self {
        self.verdict = Some(verdict);
        self
    }

    /// One pass over every source for every enabled fact binding, in
    /// priority order (higher first, ties by body hash). With hooks off or no
    /// binding it runs no hook, and still releases the due watcher ticks (FIX
    /// 22180) and prunes the hook feeds (FIX 22178).
    pub fn run_pass(
        &self,
        vault: &Vault,
        runtime: &dyn HookBodyRuntime,
        max_entries: usize,
    ) -> Result<HookPassReport> {
        let result = self.pass(vault, runtime, max_entries.max(1));
        if result.is_err() {
            self.drained.store(false, Ordering::Release);
        }
        result
    }

    fn pass(
        &self,
        vault: &Vault,
        runtime: &dyn HookBodyRuntime,
        max_entries: usize,
    ) -> Result<HookPassReport> {
        self.pass_with(vault, runtime, max_entries, None)
    }

    fn pass_with(
        &self,
        vault: &Vault,
        runtime: &dyn HookBodyRuntime,
        max_entries: usize,
        mut retained: Option<RetainedPass<'_>>,
    ) -> Result<HookPassReport> {
        let mut report = HookPassReport::default();
        // Due watcher TASKs tick first, hooks on or off and with or without a
        // binding to take a tick, as a watch TASK settles with it (FIX 22180).
        // A binding whose cursor this node first places below is bound after
        // these ticks: it runs an open TASK's (`open_tick_start_in_txn`), and
        // never a watch TASK's they settled (`enabled_before_tick_in_txn`).
        let now = vault.store.clock.now_recorded_at();
        match source::release_due_ticks(vault, now) {
            Ok(more) => report.more = more,
            Err(error) => tracing::warn!(%error, "due watcher ticks wait for the next pass"),
        }
        // Timer and feed turn programs are released beside the ticks, hooks on
        // or off (untangle slice 6.8c); no loop of their own runs.
        crate::dreamer_runner::release_program_wakes(vault, now);
        if !vault.hooks_enabled()? {
            report.disabled = true;
            return hook_feeds::prune_hook_feeds(vault, max_entries).map(|()| report);
        }
        // Calls a settled verb hook ask made ready run here, the first pass
        // at start included: outside any write, at hook depth 0. A failed
        // drain leaves its calls for the next pass.
        if let Err(error) = vault.drain_verb_asks() {
            tracing::warn!(%error, "settled verb hook asks wait for the next pass");
        }
        if !self.drained.load(Ordering::Acquire) {
            if apply::drain_pending(vault, &mut report)? {
                report.more = true;
            } else {
                self.drained.store(true, Ordering::Release);
            }
        }
        let all = vault.pack_hook_bindings()?;
        pause_disabled(vault, &all)?;
        let bindings = fact_bindings(&all);
        if bindings.is_empty() {
            return hook_feeds::prune_hook_feeds(vault, max_entries).map(|()| report);
        }
        if let Some(pass) = &mut retained {
            pass.runs.keep_source_order_for(&bindings);
        }
        let blocked = retained
            .as_ref()
            .map_or_else(HashSet::new, |pass| pass.runs.bindings());
        let mut pass = Pass {
            vault,
            runtime,
            verdict: self.verdict.as_deref(),
            all: &all,
            bodies: HashMap::new(),
            classes: HashMap::new(),
            report,
            retained,
            blocked,
        };
        if pass.retained.is_some() {
            for binding in &bindings {
                let sources = pass
                    .retained
                    .as_ref()
                    .expect("retained pass")
                    .runs
                    .sources(binding.0);
                for source in sources {
                    pass.run_source(source, max_entries, std::slice::from_ref(binding))?;
                }
            }
        } else {
            for source in FactSource::ALL {
                pass.run_source(source, max_entries, &bindings)?;
            }
        }
        hook_feeds::prune_hook_feeds(vault, max_entries)?;
        Ok(pass.report)
    }

    /// Runs passes until `shutdown` turns true, then finishes retained runs. It subscribes to the vault's
    /// change notice before the first pass, catches up from every cursor at
    /// start, then wakes on a notice or every [`HOOK_RUNNER_TICK`]. Each pass
    /// runs on a blocking thread, under one `admit`; owned evaluations keep
    /// that admission until their completion tail lands. A waiting callback
    /// holds its own binding's cursor, not other bindings or the pass caller.
    /// A refused pass starts no new evaluation. `verdict` answers generative
    /// hooks' `ai.verdict`.
    #[cfg(feature = "sync")]
    pub fn spawn(
        vault: std::sync::Arc<Vault>,
        runtime: std::sync::Arc<dyn HookBodyRuntime>,
        verdict: Option<std::sync::Arc<dyn HookVerdict>>,
        admit: HookPassAdmission,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        use std::sync::Arc;
        use tokio::sync::oneshot::{self, error::TryRecvError};

        // Subscribed before the first pass, so a commit between that pass and
        // the first wait still wakes the loop.
        let mut changes = vault.subscribe_proactivity_changes();
        let runner = Arc::new(match verdict {
            Some(verdict) => Self::new().with_verdict(verdict),
            None => Self::new(),
        });
        let completed = Arc::new(tokio::sync::Notify::new());
        let wake = Arc::clone(&completed);
        let retained = Arc::new(std::sync::Mutex::new(retained::RetainedRuns::new(
            Arc::clone(&vault),
            Arc::clone(&runtime),
            runner.verdict.clone(),
            Arc::new(move || wake.notify_one()),
        )));
        let (coordinator, mut coordinator_closed) = oneshot::channel::<()>();
        let completion = tokio::spawn(async move {
            let mut shutdown_closed = false;
            loop {
                if matches!(
                    coordinator_closed.try_recv(),
                    Ok(()) | Err(TryRecvError::Closed)
                ) {
                    shutdown_closed = true;
                }
                let stopping = shutdown_closed || *shutdown.borrow();
                let pending = retained
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .is_pending();
                if stopping && !pending {
                    break;
                }
                let admission = if stopping { None } else { admit() };
                let (pass_runner, pass_retained) = (Arc::clone(&runner), Arc::clone(&retained));
                let pass = tokio::task::spawn_blocking(move || {
                    pass_retained
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .drive(&pass_runner, admission)
                })
                .await;
                let more = match pass {
                    Ok(Ok(report)) => report.more,
                    Ok(Err(error)) => {
                        runner.drained.store(false, Ordering::Release);
                        tracing::warn!(%error, "fact hook pass failed");
                        false
                    }
                    Err(error) => {
                        tracing::warn!(%error, "fact hook pass did not finish");
                        false
                    }
                };
                let pending = retained
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .is_pending();
                if stopping && !pending {
                    break;
                }
                if more && !pending {
                    continue;
                }
                tokio::select! {
                    _ = &mut coordinator_closed, if !stopping => {
                        shutdown_closed = true;
                    }
                    changed = shutdown.changed(), if !stopping => {
                        if changed.is_err() {
                            shutdown_closed = true;
                        }
                    }
                    _ = completed.notified() => {}
                    _ = changes.changed(), if !stopping => {}
                    () = tokio::time::sleep(HOOK_RUNNER_TICK) => {}
                }
            }
        });
        // Aborting the coordinator stops admission without aborting owned
        // completions. Capture the sender before the coordinator's first poll.
        tokio::spawn(async move {
            let result = completion.await;
            drop(coordinator);
            result.expect("fact hook completion task failed");
        })
    }
}

/// Marks the cursors of disabled fact bindings paused, so a re-enabled hook
/// starts where it was re-enabled rather than replaying the gap.
fn pause_disabled(vault: &Vault, all: &[(EntityId, PackHookBinding)]) -> Result<()> {
    let mut pause = Vec::new();
    for (id, binding) in all {
        if binding.enabled || binding.selector.phase != HookPhase::Fact {
            continue;
        }
        for source in FactSource::ALL {
            if let Some(row) = store::cursor(vault, *id, source)?
                && !row.paused
            {
                pause.push((*id, source, row));
            }
        }
    }
    if pause.is_empty() {
        return Ok(());
    }
    let at = vault.store.clock.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        for (id, source, row) in &pause {
            store::put_cursor_in_txn(vault, txn, *id, *source, &row.paused(at))?;
        }
        Ok(())
    })
}

/// One pass's working state.
struct Pass<'v, 'jobs> {
    vault: &'v Vault,
    runtime: &'v dyn HookBodyRuntime,
    verdict: Option<&'v dyn HookVerdict>,
    /// Every live binding, for the authority recheck before an intent lands.
    all: &'v [(EntityId, PackHookBinding)],
    bodies: HashMap<EntityId, std::result::Result<String, String>>,
    classes: HashMap<EntityId, HookActorClass>,
    report: HookPassReport,
    retained: Option<RetainedPass<'jobs>>,
    /// A pending run owns this binding's next cursor position in every source.
    blocked: HashSet<EntityId>,
}

/// One binding on one fact.
struct Run<'r> {
    binding_id: EntityId,
    binding: &'r PackHookBinding,
    entry: &'r FactEntry,
    key: RunKey,
    grant: &'r HookGrant,
    actor: HookActorClass,
}

impl Pass<'_, '_> {
    fn run_source(
        &mut self,
        source: FactSource,
        max_entries: usize,
        bindings: &[(EntityId, PackHookBinding)],
    ) -> Result<()> {
        if bindings.iter().all(|(id, _)| self.blocked.contains(id)) {
            return Ok(());
        }
        let mut cursors = Vec::with_capacity(bindings.len());
        for (id, _) in bindings {
            cursors.push(self.cursor_for(*id, source)?);
        }
        let lowest = cursors.iter().copied().min().flatten();
        let batch = source::read_after(self.vault, source, lowest, max_entries)?;
        self.report.entries_read += batch.entries.len();
        self.report.more |= batch.more;
        let until = !batch.entries.is_empty() && block::any_until_predicate(self.vault)?;
        for entry in &batch.entries {
            if until
                && entry.kind == FactKind::ClaimLanded
                && let Some(predicate) = &entry.predicate
            {
                block::expire_for_predicate(
                    self.vault,
                    predicate,
                    self.vault.store.clock.now_recorded_at(),
                )?;
            }
            for ((id, binding), cursor) in bindings.iter().zip(&cursors) {
                if self.blocked.contains(id)
                    || cursor.is_some_and(|cursor| entry.position <= cursor)
                {
                    continue;
                }
                if self.deliver(*id, binding, entry)? {
                    self.blocked.insert(*id);
                }
            }
        }
        // Every entry up to `through` was delivered or passed over; skipped
        // entries move the cursor as runs do.
        if let Some(through) = batch.through {
            let vault = self.vault;
            let at = vault.store.clock.now_recorded_at();
            vault.with_write_txn_grouped(|txn| {
                for (id, _) in bindings {
                    if self.blocked.contains(id) {
                        continue;
                    }
                    store::advance_cursor_in_txn(vault, txn, *id, through, at)?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// A binding's cursor in `source`, or where it starts when it holds none
    /// or was re-enabled ([`store::enable_cursor_in_txn`]); one that holds no
    /// row at all is fresh to the source.
    fn cursor_for(&self, binding: EntityId, source: FactSource) -> Result<Option<FactPosition>> {
        let held = store::cursor(self.vault, binding, source)?;
        if let Some(row) = held
            && !row.paused
        {
            return Ok(row.position());
        }
        let row = {
            let rtxn = self.vault.store.env.read_txn()?;
            store::enable_cursor_in_txn(self.vault, &rtxn, &binding, source, held.is_none())?
        };
        let start = row.position();
        self.vault.with_write_txn_grouped(|txn| {
            store::put_cursor_in_txn(self.vault, txn, binding, source, &row)
        })?;
        Ok(start)
    }

    /// Visibility under the hook's grant first, then the filters, then the
    /// body. A fact the hook does not take only moves its cursor.
    fn deliver(
        &mut self,
        binding_id: EntityId,
        binding: &PackHookBinding,
        entry: &FactEntry,
    ) -> Result<bool> {
        if !filter::admits_entry(self.vault, binding_id, &binding.selector.verbs, entry)? {
            self.report.skipped += 1;
            return Ok(false);
        }
        let key = store::run_key(binding_id, binding, entry)?;
        if store::memo(self.vault, &key)?.is_some() {
            self.report.memo_hits += 1;
            return Ok(false);
        }
        let grant = grant::effective_grant(self.vault, binding_id, binding)?;
        let memory = self
            .vault
            .memory(grant.reader, filter::edge_class(grant.reader_class));
        let lane = match memory.read_lane(ClaimReadStatus::Recorded) {
            Ok(lane) => lane,
            Err(error) => {
                tracing::warn!(code = %error.code, "a hook's reader has no read lane");
                self.report.skipped += 1;
                return Ok(false);
            }
        };
        let seen = if read::fact_point(entry).is_some() {
            let _bodies = lane.prepare_point_read::<crate::Error>()?;
            let txn = self.vault.store.env.read_txn()?;
            read::fact_row_in_txn(&lane, &txn, &grant, entry)?
        } else {
            None
        };
        let Some(seen) = seen else {
            self.report.skipped += 1;
            return Ok(false);
        };
        let actor = self.actor_class(entry.actor)?;
        if !filter::fact_matches(
            self.vault,
            &binding.selector,
            entry,
            seen.claim.as_ref(),
            actor,
        )? {
            self.report.skipped += 1;
            return Ok(false);
        }
        let body = self.body(binding_id, binding);
        let run = Run {
            binding_id,
            binding,
            entry,
            key,
            grant: &grant,
            actor,
        };
        self.run(&run, &lane, &seen, body)
    }

    fn run(
        &mut self,
        run: &Run<'_>,
        lane: &ScopedRead<'_>,
        seen: &SeenFact,
        body: std::result::Result<String, String>,
    ) -> Result<bool> {
        let now = self
            .vault
            .store
            .clock
            .now_recorded_at()
            .saturating_mul(1_000);
        let input = input_json(
            run.binding_id,
            run.binding,
            run.entry,
            run.actor,
            &seen.claim_json,
            now,
        )?;
        if let Some(retained) = &mut self.retained {
            retained.enqueue(run, self.all, lane.actor_key().clone(), body, input, now)?;
            return Ok(true);
        }
        let prepared = evaluation::evaluate(
            self.runtime,
            self.verdict,
            run,
            lane,
            body,
            input,
            now,
            false,
        );
        let memo = prepared.memo(self.vault, run)?;
        let queued = self.commit(run, memo, &prepared.verdict)?;
        self.report.count(&prepared.verdict);
        if queued {
            apply::drain_one(self.vault, self.all, &run.key, &mut self.report)?;
        }
        Ok(false)
    }

    fn body(
        &mut self,
        binding_id: EntityId,
        binding: &PackHookBinding,
    ) -> std::result::Result<String, String> {
        let vault = self.vault;
        self.bodies
            .entry(binding_id)
            .or_insert_with(|| {
                vault
                    .pack_hook_body(binding)
                    .map_err(|error| error.to_string())
                    .and_then(|bytes| {
                        String::from_utf8(bytes).map_err(|_| "hook body is not UTF-8".to_owned())
                    })
            })
            .clone()
    }

    fn actor_class(&mut self, actor: EntityId) -> Result<HookActorClass> {
        if let Some(class) = self.classes.get(&actor) {
            return Ok(*class);
        }
        let class = filter::actor_class(self.vault, actor)?;
        self.classes.insert(actor, class);
        Ok(class)
    }
}

/// The input a body sees as `input`. `now` is Unix milliseconds from the
/// vault clock; `recorded_at` is the fact's own, in seconds. A tick adds
/// `tick` (its TASK and due time, seconds), an inbound surface event adds
/// `surface` (its ids and tokens).
pub(super) fn input_json(
    binding_id: EntityId,
    binding: &PackHookBinding,
    entry: &FactEntry,
    actor: HookActorClass,
    claim: &Value,
    now: u64,
) -> Result<String> {
    let mut input = json!({
        "hook": {
            "binding": binding_id.to_hex(),
            "code": binding.code.to_hex(),
            "pack": binding.pack,
            "name": binding.hook,
            "version": binding.hook_version,
            "body_hash": binding.body_hash,
        },
        "fact": {
            "kind": entry.kind.as_str(),
            "source": entry.position.source().as_str(),
            "position": entry.position.hex(),
            "entity": entry.entity.to_hex(),
            "op": entry.op.as_str(),
            "actor": {
                "principal": entry.actor.to_hex(),
                "class": filter::class_token(actor),
            },
            "recorded_at": entry.recorded_at,
        },
        "claim": claim,
        "now": now,
    });
    if let Some(settlement) = entry.settlement {
        input["fact"]["settlement"] = json!({
            "kind": settlement.kind,
            "outcome": settlement.outcome,
        });
    }
    if let Some(tick) = entry.tick {
        input["tick"] = json!({
            "task": entry.entity.to_hex(),
            "due_at": tick.due_at,
        });
    }
    if let Some(surface) = &entry.surface {
        input["surface"] = json!({
            "connector": surface.connector,
            "channel": surface.channel,
            "action": surface.action,
            "receiving_identity": surface.receiving_identity.to_hex(),
            "actor": surface.actor.to_hex(),
            "attempt": hex_lower(&surface.attempt),
            "received_at": surface.received_at,
        });
    }
    serde_json::to_string(&input).map_err(|_| Error::InvariantViolation("hook input encode"))
}

pub(super) fn block_id(key: &RunKey) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(b"oneiron.hook-block.v1", &[key.as_slice()])
}

/// `text`, cut to [`MAX_FIELD`] bytes on a character boundary.
pub(super) fn bounded(text: &str) -> String {
    let mut end = text.len().min(MAX_FIELD);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
