//! The fact-hook runner (ARCH-0080 §4 Delivery). It reads each source after
//! its bindings' cursors, filters in Rust, runs each matching body once per
//! run key, and commits the run's memo, its run index row, local outcomes,
//! receipt, intents and cursor in one write. Delivery is at least once, in
//! commit order, per hook and per source.

mod body;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::receipt::hex_lower;
use crate::skill_hub::pack_catalog::{HookActorClass, HookPhase, PackHookBinding};
use crate::{EntityId, Error, Result, Vault};

use super::apply;
use super::block::{self, HookBlock};
use super::body::{HookBodyRuntime, HookRunContext, HookVerdict};
use super::filter;
use super::grant::{self, HookGrant};
use super::lineage::{self, HookCheck, LineageLink};
use super::outcome::HookOutcome;
use super::read::{self, SeenFact};
use super::source::{self, FactEntry, FactKind, FactPosition, FactSource};
use super::store::{
    self, CursorRow, HookIntent, HookIntentState, HookRunRecord, HookRunRef, HookRunState, RunKey,
};

pub(super) use body::{Verdict, ask_verdict, judge};
use body::{VerdictPins, receipt, record};

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
pub(super) const MAX_OUTCOME_BYTES: usize = 64 * 1024;
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
    /// `hooks.enabled` is off; the pass read nothing.
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
    /// A source held more entries than this pass read.
    pub more: bool,
}

impl HookPassReport {
    fn count(&mut self, verdict: &Verdict) {
        self.runs += 1;
        match verdict.state {
            HookRunState::Completed => {}
            HookRunState::Refused => self.refused += 1,
            HookRunState::Failed => self.failed += 1,
        }
    }
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
    /// priority order (higher first, ties by body hash). With no binding it
    /// reads nothing.
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
        let mut report = HookPassReport::default();
        if !vault.hooks_enabled()? {
            report.disabled = true;
            return Ok(report);
        }
        // Calls a settled verb hook ask made ready run here, the first pass
        // at start included: outside any write, at hook depth 0. A failed
        // drain leaves its calls for the next pass.
        if let Err(error) = vault.drain_verb_asks() {
            tracing::warn!(%error, "settled verb hook asks wait for the next pass");
        }
        if !self.drained.swap(true, Ordering::AcqRel) {
            apply::drain_pending(vault, &mut report)?;
        }
        let all = vault.pack_hook_bindings()?;
        pause_disabled(vault, &all)?;
        let mut bindings: Vec<(EntityId, PackHookBinding)> = all
            .iter()
            .filter(|(_, binding)| binding.enabled && binding.selector.phase == HookPhase::Fact)
            .cloned()
            .collect();
        if bindings.is_empty() {
            return Ok(report);
        }
        bindings.sort_by(|(_, a), (_, b)| {
            b.selector
                .priority
                .cmp(&a.selector.priority)
                .then_with(|| a.body_hash.cmp(&b.body_hash))
        });
        let mut pass = Pass {
            vault,
            runtime,
            verdict: self.verdict.as_deref(),
            bindings: &bindings,
            all: &all,
            bodies: HashMap::new(),
            classes: HashMap::new(),
            report,
        };
        for source in FactSource::ALL {
            pass.run_source(source, max_entries)?;
        }
        Ok(pass.report)
    }

    /// Runs passes until `shutdown` turns true. It subscribes to the vault's
    /// change notice before the first pass, catches up from every cursor at
    /// start, then wakes on a notice or every [`HOOK_RUNNER_TICK`]. Each pass
    /// runs on a blocking thread, under one `admit`; a refused pass waits
    /// for the next notice or tick. `verdict` answers generative hooks'
    /// `ai.verdict`.
    #[cfg(feature = "sync")]
    pub fn spawn(
        vault: std::sync::Arc<Vault>,
        runtime: std::sync::Arc<dyn HookBodyRuntime>,
        verdict: Option<std::sync::Arc<dyn HookVerdict>>,
        admit: HookPassAdmission,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        use std::sync::Arc;
        // Subscribed before the first pass, so a commit between that pass and
        // the first wait still wakes the loop.
        let mut changes = vault.subscribe_proactivity_changes();
        let runner = Arc::new(match verdict {
            Some(verdict) => Self::new().with_verdict(verdict),
            None => Self::new(),
        });
        tokio::spawn(async move {
            loop {
                if *shutdown.borrow() {
                    break;
                }
                let more = match admit() {
                    Some(admission) => {
                        let (pass_runner, pass_vault, pass_runtime) = (
                            Arc::clone(&runner),
                            Arc::clone(&vault),
                            Arc::clone(&runtime),
                        );
                        let pass = tokio::task::spawn_blocking(move || {
                            let _admission = admission;
                            pass_runner.run_pass(
                                &pass_vault,
                                pass_runtime.as_ref(),
                                HOOK_PASS_ENTRIES,
                            )
                        })
                        .await;
                        match pass {
                            Ok(Ok(report)) => report.more,
                            Ok(Err(error)) => {
                                tracing::warn!(%error, "fact hook pass failed");
                                false
                            }
                            Err(error) => {
                                tracing::warn!(%error, "fact hook pass did not finish");
                                false
                            }
                        }
                    }
                    None => false,
                };
                if more {
                    continue;
                }
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                    _ = changes.changed() => {}
                    () = tokio::time::sleep(HOOK_RUNNER_TICK) => {}
                }
            }
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
struct Pass<'v> {
    vault: &'v Vault,
    runtime: &'v dyn HookBodyRuntime,
    verdict: Option<&'v dyn HookVerdict>,
    /// Enabled fact bindings, in run order.
    bindings: &'v [(EntityId, PackHookBinding)],
    /// Every live binding, for the authority recheck before an intent lands.
    all: &'v [(EntityId, PackHookBinding)],
    bodies: HashMap<EntityId, std::result::Result<String, String>>,
    classes: HashMap<EntityId, HookActorClass>,
    report: HookPassReport,
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

impl Pass<'_> {
    fn run_source(&mut self, source: FactSource, max_entries: usize) -> Result<()> {
        let bindings = self.bindings;
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
                if cursor.is_some_and(|cursor| entry.position <= cursor) {
                    continue;
                }
                self.deliver(*id, binding, entry)?;
            }
        }
        // Every entry up to `through` was delivered or passed over; skipped
        // entries move the cursor as runs do.
        if let Some(through) = batch.through {
            let vault = self.vault;
            let at = vault.store.clock.now_recorded_at();
            vault.with_write_txn_grouped(|txn| {
                for (id, _) in bindings {
                    store::advance_cursor_in_txn(vault, txn, *id, through, at)?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// A binding's cursor in `source`. A new binding starts where its binding
    /// claim was last written, a re-enabled one where it was re-enabled. The
    /// settlement feed holds no such mark, so there both start at its head.
    fn cursor_for(&self, binding: EntityId, source: FactSource) -> Result<Option<FactPosition>> {
        if let Some(row) = store::cursor(self.vault, binding, source)?
            && !row.paused
        {
            return Ok(row.position());
        }
        let start = match source {
            FactSource::ClaimChangelog => match source::binding_written_at(self.vault, &binding)? {
                Some(position) => Some(position),
                None => source::head(self.vault, source)?,
            },
            FactSource::Settlement => source::head(self.vault, source)?,
        };
        let row = CursorRow::new(start, self.vault.store.clock.now_recorded_at());
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
    ) -> Result<()> {
        if !filter::verbs_admit_kind(&binding.selector.verbs, entry.kind) {
            self.report.skipped += 1;
            return Ok(());
        }
        let key = store::run_key(binding_id, binding, entry)?;
        if store::memo(self.vault, &key)?.is_some() {
            self.report.memo_hits += 1;
            return Ok(());
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
                return Ok(());
            }
        };
        let Some(seen) = read::fact_row(&lane, &grant, entry.entity)? else {
            self.report.skipped += 1;
            return Ok(());
        };
        let actor = self.actor_class(entry.actor)?;
        if !filter::fact_matches(
            self.vault,
            &binding.selector,
            entry.kind,
            entry.entity,
            seen.claim.as_ref(),
            actor,
        )? {
            self.report.skipped += 1;
            return Ok(());
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
    ) -> Result<()> {
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
        let started = Instant::now();
        let mut context = HookRunContext::new(run.binding.selector.budget_ms);
        let deadline = context.deadline();
        let mut pins = Vec::new();
        let mut verdicts = VerdictPins::new();
        let result = match body {
            Ok(body) => {
                let mut answer = |request: &str| read::answer(lane, run.grant, request, &mut pins);
                // Each verdict is pinned as it is heard: replay answers from
                // the pins rather than asking a model again.
                let host = self.verdict;
                let mut verdict = |request: &str| {
                    let (reply, evidence) =
                        ask_verdict(run.binding, run.grant, host, request, deadline);
                    verdicts.push(request, &reply, evidence);
                    reply
                };
                self.runtime
                    .run_fact_hook(&body, &input, &mut context, &mut answer, &mut verdict)
            }
            Err(reason) => Err(Error::InvalidConfig(reason)),
        };
        // The body's worker has joined, a failed run's too: its accounting
        // ends here, and an overrun goes beside its outcome (FIX 8842).
        let overrun = context.finish();
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let verdict = judge(run.binding, result, overrun);
        let memo = record(run, &input, pins, verdicts, &verdict, duration_ms, now);
        let queued = self.commit(run, memo, &verdict)?;
        self.report.count(&verdict);
        if queued {
            apply::drain_one(self.vault, self.all, &run.key, &mut self.report)?;
        }
        Ok(())
    }

    /// The run's one write: lineage and any owner check, local outcomes,
    /// saved intents, memo and its run index row, receipt and the cursor.
    /// Returns whether an intent waits.
    fn commit(&mut self, run: &Run<'_>, memo: HookRunRecord, verdict: &Verdict) -> Result<bool> {
        let vault = self.vault;
        let at = vault.store.clock.now_recorded_at();
        let key = run.key;
        let queued = verdict.outcome.as_ref().is_some_and(HookOutcome::is_queued);
        let proposal = match &verdict.outcome {
            Some(HookOutcome::Propose { .. }) => Some(apply::proposal_id(&key)?),
            _ => None,
        };
        let added = match &verdict.outcome {
            Some(HookOutcome::AddBlock { block }) => Some((
                block_id(&key)?,
                HookBlock::from_request(
                    run.binding_id,
                    format!("{}/{}", run.binding.pack, run.binding.hook),
                    hex_lower(&key),
                    block,
                    at,
                )?,
            )),
            _ => None,
        };
        let rows_read = memo.reads.iter().map(|pin| pin.rows.len()).sum::<usize>();
        let (duration_ms, now) = (memo.duration_ms, memo.now);
        let link = LineageLink {
            binding: run.binding_id,
            run_key: hex_lower(&key),
            entity: run.entry.entity,
            position: run.entry.position.hex(),
        };
        let memo = HookRunRecord {
            committed_at: at.saturating_mul(1_000),
            ..memo
        };
        let check = vault.with_write_txn_grouped(|txn| {
            let parent = lineage::chain_of(vault, txn, &run.entry.entity)?;
            let (chain, check) = lineage::extend(&parent, link);
            if let Some(reason) = check {
                let raised = HookCheck {
                    binding: run.binding_id,
                    run_key: hex_lower(&key),
                    reason,
                    chain: chain.clone(),
                    raised_at: at,
                };
                lineage::raise_check_in_txn(vault, txn, &key, &raised)?;
            }
            if let Some((id, added)) = &added {
                block::put_block_in_txn(vault, txn, *id, added)?;
                lineage::put_in_txn(vault, txn, id.as_bytes(), &chain)?;
            }
            if let Some(id) = proposal {
                lineage::put_in_txn(vault, txn, id.as_bytes(), &chain)?;
            }
            if queued {
                let intent = HookIntent {
                    binding: run.binding_id,
                    author: run.binding.author_id(),
                    outcome_json: verdict.outcome_json.clone().unwrap_or_default(),
                    lineage: chain,
                    state: HookIntentState::Pending,
                    landed: None,
                    reason: None,
                    created_at: at,
                    settled_at: None,
                };
                store::INTENTS.put(vault, txn, &key, &intent)?;
            }
            let previous = store::MEMOS
                .get(&vault.store, txn, &key)?
                .map(|old| old.committed_at);
            store::MEMOS.put(vault, txn, &key, &memo)?;
            store::index_run_in_txn(
                vault,
                txn,
                run.binding_id,
                previous,
                memo.committed_at,
                HookRunRef::Fact(key),
            )?;
            let hook_receipt = receipt(run, verdict, check, rows_read, duration_ms, now);
            store::RECEIPTS.put(vault, txn, &key, &hook_receipt)?;
            store::advance_cursor_in_txn(vault, txn, run.binding_id, run.entry.position, at)?;
            Ok(check)
        })?;
        if check.is_some() {
            self.report.checks += 1;
        }
        Ok(queued)
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
/// vault clock; `recorded_at` is the fact's own, in seconds.
pub(super) fn input_json(
    binding_id: EntityId,
    binding: &PackHookBinding,
    entry: &FactEntry,
    actor: HookActorClass,
    claim: &Value,
    now: u64,
) -> Result<String> {
    let input = json!({
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
