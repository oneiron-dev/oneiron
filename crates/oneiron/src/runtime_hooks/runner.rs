//! The fact-hook runner (ARCH-0080 §4 Delivery). It reads each source after
//! its bindings' cursors, filters in Rust, runs each matching body once per
//! run key, and commits the run's memo, local outcomes, receipt, intents and
//! cursor in one write. Delivery is at least once, in commit order, per hook
//! and per source.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::receipt::{ReceiptKind, ReceiptRecord, hex_lower};
use crate::skill_hub::pack_catalog::{HookActorClass, HookPhase, HookRenderClass, PackHookBinding};
use crate::{EntityId, Error, Result, Vault};

use super::apply;
use super::block::{self, HookBlock};
use super::body::{HookBodyRun, HookBodyRuntime, HookVerdict};
use super::filter;
use super::grant::{self, HookGrant};
use super::lineage::{self, HookCheck, HookCheckReason, LineageLink};
use super::outcome::{HookOutcome, kind_token};
use super::read::{self, SeenFact};
use super::source::{self, FactEntry, FactKind, FactPosition, FactSource};
use super::store::{
    self, CursorRow, HookIntent, HookIntentState, HookReadPin, HookRunRecord, HookRunState, RunKey,
};

/// Entries one pass reads from each source: the in-memory cap. A source with
/// more is read again from its cursors on the next pass.
pub const HOOK_PASS_ENTRIES: usize = 256;
/// How often the runner re-reads its cursors without a change notice: not
/// every claim write notifies.
pub const HOOK_RUNNER_TICK: Duration = Duration::from_secs(2);
/// The largest input a memo row pins.
const MAX_PINNED_INPUT: usize = 256 * 1024;
const MAX_OUTCOME_BYTES: usize = 64 * 1024;
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
    /// runs on a blocking thread. `verdict` answers generative hooks'
    /// `ai.verdict`.
    #[cfg(feature = "sync")]
    pub fn spawn(
        vault: std::sync::Arc<Vault>,
        runtime: std::sync::Arc<dyn HookBodyRuntime>,
        verdict: Option<std::sync::Arc<dyn HookVerdict>>,
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
                let (pass_runner, pass_vault, pass_runtime) = (
                    Arc::clone(&runner),
                    Arc::clone(&vault),
                    Arc::clone(&runtime),
                );
                let pass = tokio::task::spawn_blocking(move || {
                    pass_runner.run_pass(&pass_vault, pass_runtime.as_ref(), HOOK_PASS_ENTRIES)
                })
                .await;
                let more = match pass {
                    Ok(Ok(report)) => report.more,
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "fact hook pass failed");
                        false
                    }
                    Err(error) => {
                        tracing::warn!(%error, "fact hook pass did not finish");
                        false
                    }
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
        let budget_ms = run.binding.selector.budget_ms;
        let deadline = started + Duration::from_millis(u64::from(budget_ms));
        let mut pins = Vec::new();
        let result = match body {
            Ok(body) => {
                let mut answer = |request: &str| read::answer(lane, run.grant, request, &mut pins);
                // The verdict is asked for the grant's reader, the identity
                // whose reach the hook reads with.
                let host = self.verdict;
                let mut verdict = |request: &str| match (run.binding.selector.render_class, host) {
                    (HookRenderClass::Generative, Some(host)) => host.verdict(
                        run.grant.reader,
                        filter::edge_class(run.grant.reader_class),
                        request,
                        deadline,
                    ),
                    (HookRenderClass::Generative, None) => {
                        Err("no verdict host serves this runner".to_owned())
                    }
                    (HookRenderClass::DeterministicEager, _) => Err(
                        "a deterministic hook calls no model: declare render_class: generative"
                            .to_owned(),
                    ),
                };
                self.runtime
                    .run_fact_hook(&body, &input, budget_ms, &mut answer, &mut verdict)
            }
            Err(reason) => Err(Error::InvalidConfig(reason)),
        };
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let verdict = judge(run.binding, result);
        let queued = self.commit(run, &input, pins, &verdict, duration_ms, now)?;
        self.report.count(&verdict);
        if queued {
            apply::drain_one(self.vault, self.all, &run.key, &mut self.report)?;
        }
        Ok(())
    }

    /// The run's one write: lineage and any owner check, local outcomes,
    /// saved intents, memo, receipt and the cursor. Returns whether an
    /// intent waits.
    fn commit(
        &mut self,
        run: &Run<'_>,
        input: &str,
        reads: Vec<HookReadPin>,
        verdict: &Verdict,
        duration_ms: u64,
        now: u64,
    ) -> Result<bool> {
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
        let rows_read = reads.iter().map(|pin| pin.rows.len()).sum::<usize>();
        let link = LineageLink {
            binding: run.binding_id,
            run_key: hex_lower(&key),
            entity: run.entry.entity,
            position: run.entry.position.hex(),
        };
        let memo = record(run, input, reads, verdict, duration_ms, now);
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
                store::INTENTS.put(&vault.store, txn, &key, &intent)?;
            }
            store::MEMOS.put(&vault.store, txn, &key, &memo)?;
            let hook_receipt = receipt(run, verdict, check, rows_read, duration_ms, now);
            store::RECEIPTS.put(&vault.store, txn, &key, &hook_receipt)?;
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

/// How a body run ended, judged against its binding.
pub(super) struct Verdict {
    pub(super) state: HookRunState,
    pub(super) outcome: Option<HookOutcome>,
    pub(super) outcome_json: Option<String>,
    /// The outcome kind, or `refused` / `failed`.
    pub(super) token: String,
    pub(super) reason: Option<String>,
    pub(super) fuel_used: u64,
    pub(super) host_calls: u32,
}

/// A body that failed, trapped or ran past its budget is `failed`. An
/// outcome that does not parse, is not a kind of the binding's phase, is not
/// one the binding allows, or has the wrong shape is `refused`.
pub(super) fn judge(binding: &PackHookBinding, result: Result<HookBodyRun>) -> Verdict {
    let run = match result {
        Ok(run) => run,
        Err(error) => {
            return Verdict {
                state: HookRunState::Failed,
                outcome: None,
                outcome_json: None,
                token: "failed".to_owned(),
                reason: Some(bounded(&error.to_string())),
                fuel_used: 0,
                host_calls: 0,
            };
        }
    };
    match accept(binding, &run.outcome_json) {
        Ok(outcome) => Verdict {
            state: HookRunState::Completed,
            token: kind_token(outcome.kind()).to_owned(),
            outcome: Some(outcome),
            outcome_json: Some(run.outcome_json),
            reason: None,
            fuel_used: run.fuel_used,
            host_calls: run.host_calls,
        },
        Err(reason) => Verdict {
            state: HookRunState::Refused,
            token: "refused".to_owned(),
            outcome: None,
            outcome_json: (run.outcome_json.len() <= MAX_OUTCOME_BYTES).then_some(run.outcome_json),
            reason: Some(reason),
            fuel_used: run.fuel_used,
            host_calls: run.host_calls,
        },
    }
}

fn accept(binding: &PackHookBinding, json: &str) -> std::result::Result<HookOutcome, String> {
    if json.len() > MAX_OUTCOME_BYTES {
        return Err("the outcome is too large".to_owned());
    }
    let outcome: HookOutcome =
        serde_json::from_str(json).map_err(|_| "the outcome does not parse".to_owned())?;
    let kind = outcome.kind();
    let phase = binding.selector.phase;
    if !kind.applies_in(phase) {
        return Err(format!(
            "{} is not a {} outcome",
            kind_token(kind),
            match phase {
                HookPhase::Pre => "pre-hook",
                HookPhase::Post => "post-hook",
                HookPhase::Fact => "fact-hook",
            }
        ));
    }
    if !binding.selector.outcomes.contains(&kind) {
        return Err(format!("the binding does not allow {}", kind_token(kind)));
    }
    outcome.validate()?;
    Ok(outcome)
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

fn record(
    run: &Run<'_>,
    input: &str,
    reads: Vec<HookReadPin>,
    verdict: &Verdict,
    duration_ms: u64,
    now: u64,
) -> HookRunRecord {
    HookRunRecord {
        binding: run.binding_id,
        code: run.binding.code,
        body_hash: run.binding.body_hash.clone(),
        source: run.entry.position.source(),
        position: run.entry.position.hex(),
        fact: run.entry.kind,
        entity: run.entry.entity,
        input_json: (input.len() <= MAX_PINNED_INPUT).then(|| input.to_owned()),
        input_hash: blake3::hash(input.as_bytes()).to_hex().to_string(),
        reads,
        outcome_json: verdict.outcome_json.clone(),
        outcome: verdict.token.clone(),
        reason: verdict.reason.clone(),
        state: verdict.state,
        receipt_id: store::receipt_id(&run.key),
        duration_ms,
        now,
    }
}

/// The run's Hook receipt: the hook, its CODE id and body hash, the duration,
/// the outcome, `now`, the rows read and the run key.
fn receipt(
    run: &Run<'_>,
    verdict: &Verdict,
    check: Option<HookCheckReason>,
    rows_read: usize,
    duration_ms: u64,
    now: u64,
) -> ReceiptRecord {
    let binding = run.binding;
    let mut fields: BTreeMap<String, String> = [
        ("binding", run.binding_id.to_hex()),
        ("code", binding.code.to_hex()),
        ("body_hash", binding.body_hash.clone()),
        ("hook", format!("{}/{}", binding.pack, binding.hook)),
        ("hook_version", binding.hook_version.clone()),
        ("fact", run.entry.kind.as_str().to_owned()),
        ("source", run.entry.position.source().as_str().to_owned()),
        ("position", run.entry.position.hex()),
        ("duration_ms", duration_ms.to_string()),
        ("now", now.to_string()),
        ("rows_read", rows_read.to_string()),
        ("run_key", hex_lower(&run.key)),
        ("fuel_used", verdict.fuel_used.to_string()),
        ("host_calls", verdict.host_calls.to_string()),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect();
    if let Some(check) = check {
        fields.insert("check".to_owned(), check.as_str().to_owned());
    }
    if let Some(reason) = &verdict.reason {
        fields.insert("reason".to_owned(), bounded(reason));
    }
    ReceiptRecord {
        receipt_id: store::receipt_id(&run.key),
        receipt_kind: ReceiptKind::Hook,
        occurred_at: now / 1_000,
        actor: Some(binding.author_id().to_hex()),
        on_behalf_of: None,
        outcome: verdict.token.clone(),
        job_ref: None,
        trigger_ref: Some(run.entry.entity.to_hex()),
        policy_trace: Vec::new(),
        fields,
    }
}

/// `text`, cut to [`MAX_FIELD`] bytes on a character boundary.
pub(super) fn bounded(text: &str) -> String {
    let mut end = text.len().min(MAX_FIELD);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
