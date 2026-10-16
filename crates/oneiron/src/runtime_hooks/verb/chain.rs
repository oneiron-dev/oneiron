//! The verb-hook chain (ARCH-0080 §3): matching, run order, each run's input
//! and verdict, the failure policy by domain, and the one write that commits
//! a chain's receipts, blocks and intents once it resolves, even when a Skip
//! or an Ask stops the verb.

use std::collections::BTreeMap;
use std::time::Instant;

use serde::Serialize;
use serde_json::{Value, json};

use crate::claim::ClaimReadStatus;
use crate::receipt::{ReceiptKind, ReceiptRecord, hex_lower};
use crate::runtime_hooks::block::{self, HookBlock};
use crate::runtime_hooks::lineage::{self, LineageLink};
use crate::runtime_hooks::outcome::{BlockRequest, HookOutcome};
use crate::runtime_hooks::runner::{Verdict, block_id, bounded, judge};
use crate::runtime_hooks::store::{self, HookIntent, HookIntentState, HookRunState, RunKey};
use crate::runtime_hooks::{HookBodyRuntime, HookPassReport, apply, filter, grant, read};
use crate::skill_hub::pack_catalog::{HookPhase, HookSelector, PackHookBinding};
use crate::{EntityId, Error, Result, Vault};

use super::state::{Carry, Entered, HookDepth, depth};
use super::{
    InvocationId, VerbArgsCheck, VerbCall, VerbDomain, VerbHookPre, VerbHookStop, ask, redact,
    served,
};

/// Receipts the input's tail carries.
const RECEIPT_TAIL: usize = 8;
/// The host verb a pre-hook may never skip: a skipped compaction overflows
/// the next turn (ARCH-0080 §5).
const COMPACT: &str = "host.compact";

/// One hook a call matched: its binding id and row.
type Hook<'b> = (EntityId, &'b PackHookBinding);

type Stopped<T> = std::result::Result<T, VerbHookStop>;

/// The pre chain of `call`. It passes through with hooks off or suppressed,
/// at hook depth 1, inside the same actor's call of this invocation, without
/// the sandbox, and when no binding matches; the cached binding list keeps
/// that last case free of reads.
pub(super) fn pre(
    vault: &Vault,
    call: VerbCall,
    args: Value,
    check: VerbArgsCheck<'_>,
) -> Result<Stopped<VerbHookPre>> {
    let state = &vault.verb_hook_state;
    if state.suppressed() || depth() > 0 {
        return through(call, args);
    }
    let bindings = state.bindings(vault)?;
    let hooks = matching(&bindings.verb, HookPhase::Pre, &call);
    if hooks.is_empty() && matching(&bindings.verb, HookPhase::Post, &call).is_empty() {
        return through(call, args);
    }
    let Some(runtime) = state.runtime() else {
        return through(call, args);
    };
    let mark = match state.enter(call.invocation, call.actor) {
        Entered::Nested => return through(call, args),
        Entered::Fresh(mark) => mark,
    };
    let carry = Carry {
        mark,
        now: vault.store.clock.now_recorded_at().saturating_mul(1_000),
    };
    if hooks.is_empty() {
        return Ok(Ok(VerbHookPre {
            call,
            args,
            carry: Some(carry),
        }));
    }
    let _depth = HookDepth::enter();
    let (start, args) = match ask::retry(vault, &call)? {
        ask::Retry::Fresh => (0, args),
        ask::Retry::Stop(stop) => return Ok(Err(stop)),
        ask::Retry::Resume {
            binding,
            position,
            args,
        } => (
            hooks
                .iter()
                .position(|(id, _)| *id == binding)
                .unwrap_or(position)
                .saturating_add(1),
            args,
        ),
    };
    let ended = Chain::new(vault, &call, HookPhase::Pre, runtime, carry.now)
        .pre(&hooks, start, args, check)?;
    Ok(ended.map(|args| VerbHookPre {
        call,
        args,
        carry: Some(carry),
    }))
}

/// The post chain over the verb's `result`, for a call whose pre chain found
/// hooks live.
pub(super) fn post(vault: &Vault, pre: VerbHookPre, result: Value) -> Result<Stopped<Value>> {
    let VerbHookPre { call, args, carry } = pre;
    let state = &vault.verb_hook_state;
    let Some(carry) = carry else {
        return Ok(Ok(result));
    };
    if state.suppressed() || depth() > 0 {
        return Ok(Ok(result));
    }
    let bindings = state.bindings(vault)?;
    let hooks = matching(&bindings.verb, HookPhase::Post, &call);
    if hooks.is_empty() {
        return Ok(Ok(result));
    }
    let Some(runtime) = state.runtime() else {
        return Ok(Ok(result));
    };
    let _depth = HookDepth::enter();
    let ended =
        Chain::new(vault, &call, HookPhase::Post, runtime, carry.now).post(&hooks, &args, result);
    // A nested boundary of this invocation passes through until here.
    drop(carry.mark);
    ended
}

fn through(call: VerbCall, args: Value) -> Result<Stopped<VerbHookPre>> {
    Ok(Ok(VerbHookPre {
        call,
        args,
        carry: None,
    }))
}

fn matching<'b>(
    bindings: &'b [(EntityId, PackHookBinding)],
    phase: HookPhase,
    call: &VerbCall,
) -> Vec<Hook<'b>> {
    bindings
        .iter()
        .filter(|(_, binding)| takes(&binding.selector, phase, call))
        .map(|(id, binding)| (*id, binding))
        .collect()
}

/// Whether `selector` takes `call` in `phase`: a verb glob, the class, and a
/// scope the call's scope is, or sits under (`<scope>/…`).
fn takes(selector: &HookSelector, phase: HookPhase, call: &VerbCall) -> bool {
    selector.phase == phase
        && selector
            .verbs
            .iter()
            .any(|glob| filter::glob_match(glob, &call.verb))
        && (selector.actors.is_empty() || selector.actors.contains(&call.class))
        && selector.scope.as_deref().is_none_or(|scope| {
            call.scope.as_deref().is_some_and(|own| {
                own.strip_prefix(scope)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
            })
        })
}

/// One chain: its call and phase, and what its runs leave to commit.
struct Chain<'c> {
    vault: &'c Vault,
    call: &'c VerbCall,
    phase: HookPhase,
    runtime: std::result::Result<&'c dyn HookBodyRuntime, &'c str>,
    now: u64,
    /// The last receipts the caller sees, as JSON.
    tail: Value,
    runs: Vec<RunRecord<'c>>,
    blocks: Vec<(EntityId, HookBlock, Vec<LineageLink>)>,
    /// Queued outcomes, each with the proposal it lands, if any.
    intents: Vec<(RunKey, HookIntent, Option<EntityId>)>,
}

/// One run, as its receipt tells it.
struct RunRecord<'c> {
    id: EntityId,
    binding: &'c PackHookBinding,
    key: RunKey,
    /// The outcome kind, or `refused`, `failed` or `timed_out`.
    token: String,
    reason: Option<String>,
    note: Option<String>,
    /// What a blocking hook's failure did: `ask`, `skipped`, `hidden` or
    /// `recorded`.
    fail_safe: Option<&'static str>,
    duration_ms: u64,
    rows_read: usize,
    fuel_used: u64,
    host_calls: u32,
}

/// A verb hook's `input`.
#[derive(Serialize)]
struct Input<'i> {
    hook: Value,
    verb: &'i str,
    phase: &'static str,
    invocation: String,
    actor: String,
    class: &'static str,
    scope: Option<&'i str>,
    args: &'i Value,
    board_epoch: Option<u64>,
    receipt_tail: &'i Value,
    /// Unix milliseconds from the vault clock at dispatch.
    now: u64,
    /// The caller's view of the verb's result so far; post only.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'i Value>,
    /// The rows that view serves, when it is a pack, as the hook's served
    /// filter takes them; post only.
    #[serde(skip_serializing_if = "Option::is_none")]
    served: Option<Vec<served::ServedRow<'i>>>,
}

impl<'c> Chain<'c> {
    fn new(
        vault: &'c Vault,
        call: &'c VerbCall,
        phase: HookPhase,
        runtime: std::result::Result<&'c dyn HookBodyRuntime, &'c str>,
        now: u64,
    ) -> Self {
        let tail = vault
            .memory(call.actor, filter::edge_class(call.class))
            .receipts(RECEIPT_TAIL)
            .ok()
            .and_then(|receipts| serde_json::to_value(receipts).ok())
            .unwrap_or_else(|| Value::Array(Vec::new()));
        Self {
            vault,
            call,
            phase,
            runtime,
            now,
            tail,
            runs: Vec::new(),
            blocks: Vec::new(),
            intents: Vec::new(),
        }
    }

    /// Runs the pre-hooks from `start`. Rewrites chain; the first Skip or
    /// Ask ends the chain. A failed blocking hook sends a write to an ask and
    /// hides a read.
    fn pre(
        mut self,
        hooks: &[Hook<'c>],
        start: usize,
        mut args: Value,
        check: VerbArgsCheck<'_>,
    ) -> Result<Stopped<Value>> {
        for (index, &(id, binding)) in hooks.iter().enumerate().skip(start) {
            let stop = match self.run(id, binding, &args, None, Some(check))? {
                Some(HookOutcome::Rewrite { args: next }) => {
                    args = next;
                    None
                }
                Some(HookOutcome::Skip { reason }) => Some(VerbHookStop::Skipped {
                    hook: hook_name(binding),
                    reason: bounded(&reason),
                }),
                Some(HookOutcome::Ask { question }) => {
                    let label = if question.trim().is_empty() {
                        format!("Hook {} asks before {}.", hook_name(binding), self.call.verb)
                    } else {
                        format!(
                            "Hook {} asks before {}: {question}",
                            hook_name(binding),
                            self.call.verb
                        )
                    };
                    match self.ask(index, (id, binding), &args, &label)? {
                        Ok(pending) => return Ok(Err(pending)),
                        Err(refusal) => self.ask_refused(binding, &refusal),
                    }
                }
                Some(_) => None,
                None if binding.selector.blocking => match self.call.domain {
                    VerbDomain::Read => Some(self.hide(binding)),
                    VerbDomain::Write => {
                        let why = self
                            .runs
                            .last()
                            .and_then(|run| run.reason.clone())
                            .unwrap_or_default();
                        self.fail_safe("ask");
                        let label = format!(
                            "Hook {} failed before {} ({why}). Run it anyway?",
                            hook_name(binding),
                            self.call.verb
                        );
                        match self.ask(index, (id, binding), &args, &label)? {
                            Ok(pending) => return Ok(Err(pending)),
                            Err(refusal) => {
                                self.fail_safe("skipped");
                                Some(VerbHookStop::Skipped {
                                    hook: hook_name(binding),
                                    reason: bounded(&format!(
                                        "the hook failed and its ask did not open: {refusal}"
                                    )),
                                })
                            }
                        }
                    }
                },
                None => None,
            };
            if let Some(stop) = stop {
                self.commit()?;
                return Ok(Err(stop));
            }
        }
        self.commit()?;
        Ok(Ok(args))
    }

    /// Runs the post-hooks over the caller's view of `result`. Redacts
    /// narrow the view; a failed blocking hook hides a read's result and is
    /// recorded on a write, whose commit stands.
    fn post(mut self, hooks: &[Hook<'c>], args: &Value, result: Value) -> Result<Stopped<Value>> {
        let mut view = result;
        let mut hidden = None;
        for &(id, binding) in hooks {
            if !served::admits(&binding.selector.served, &view) {
                continue;
            }
            match self.run(id, binding, args, Some(&view), None)? {
                Some(HookOutcome::Redact { paths }) => {
                    for path in &paths {
                        redact::hide(&mut view, path);
                    }
                }
                Some(_) => {}
                None if binding.selector.blocking => {
                    if self.call.domain == VerbDomain::Read {
                        hidden = Some(self.hide(binding));
                        break;
                    }
                    self.fail_safe("recorded");
                }
                None => {}
            }
        }
        self.commit()?;
        self.apply();
        Ok(hidden.map_or(Ok(view), Err))
    }

    /// One body run, judged. Blocks, notes and queued outcomes join the
    /// chain here; the flow outcomes go back to the chain.
    fn run(
        &mut self,
        id: EntityId,
        binding: &'c PackHookBinding,
        args: &Value,
        result: Option<&Value>,
        check: Option<VerbArgsCheck<'_>>,
    ) -> Result<Option<HookOutcome>> {
        let key = run_key(self.call.invocation, id, self.phase);
        let input = self.input(id, binding, args, result)?;
        // The caller's lane, narrowed to the hook's grant: its reader's lane
        // when that is someone else, and its predicates and worlds.
        let grant = grant::effective_grant(self.vault, id, binding)?;
        let caller = self
            .vault
            .memory(self.call.actor, filter::edge_class(self.call.class));
        let lane = caller.read_lane(ClaimReadStatus::Recorded).ok();
        let reader = (grant.reader != self.call.actor).then(|| {
            self.vault
                .memory(grant.reader, filter::edge_class(grant.reader_class))
        });
        let cap = reader
            .as_ref()
            .map(|reader| reader.read_lane(ClaimReadStatus::Recorded).ok());
        let mut pins = Vec::new();
        let started = Instant::now();
        let ran = match self.runtime {
            Err(reason) => Err(Error::InvalidConfig(reason.to_owned())),
            Ok(runtime) => match self.vault.verb_hook_state.body(self.vault, binding) {
                Err(reason) => Err(Error::InvalidConfig(reason)),
                Ok(body) => {
                    let mut answer = |request: &str| match (&lane, &cap) {
                        (Some(lane), None) => {
                            read::answer_within(lane, None, &grant, request, &mut pins)
                        }
                        (Some(lane), Some(Some(cap))) => {
                            read::answer_within(lane, Some(cap), &grant, request, &mut pins)
                        }
                        _ => Err("this call has no read lane".to_owned()),
                    };
                    runtime.run_hook(&body, &input, binding.selector.budget_ms, &mut answer)
                }
            },
        };
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut verdict = judge(binding, ran);
        if let Some(reason) = verdict
            .outcome
            .as_ref()
            .and_then(|outcome| self.admit(outcome, check).err())
        {
            verdict = Verdict {
                state: HookRunState::Refused,
                outcome: None,
                token: "refused".to_owned(),
                reason: Some(reason),
                ..verdict
            };
        }
        let timed_out = verdict.state == HookRunState::Failed
            && verdict
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("deadline exceeded"));
        let mut run = RunRecord {
            id,
            binding,
            key,
            token: if timed_out {
                "timed_out".to_owned()
            } else {
                verdict.token.clone()
            },
            reason: verdict.reason.clone(),
            note: None,
            fail_safe: None,
            duration_ms,
            rows_read: pins.iter().map(|pin| pin.rows.len()).sum(),
            fuel_used: verdict.fuel_used,
            host_calls: verdict.host_calls,
        };
        match &verdict.outcome {
            Some(HookOutcome::AddBlock { block }) => self.block(id, binding, &key, block)?,
            Some(HookOutcome::Annotate { note }) => run.note = Some(bounded(note)),
            Some(outcome) if outcome.is_queued() => {
                let proposal = match outcome {
                    HookOutcome::Propose { .. } => Some(apply::proposal_id(&key)?),
                    _ => None,
                };
                let intent = HookIntent {
                    binding: id,
                    author: binding.owner,
                    outcome_json: verdict.outcome_json.clone().unwrap_or_default(),
                    lineage: self.lineage(id, &key),
                    state: HookIntentState::Pending,
                    landed: None,
                    reason: None,
                    created_at: self.vault.store.clock.now_recorded_at(),
                    settled_at: None,
                };
                self.intents.push((key, intent, proposal));
            }
            _ => {}
        }
        self.runs.push(run);
        Ok(verdict.outcome)
    }

    /// The verb engine's own checks on an outcome its binding accepted; the
    /// reason refuses it.
    fn admit(
        &self,
        outcome: &HookOutcome,
        check: Option<VerbArgsCheck<'_>>,
    ) -> std::result::Result<(), String> {
        match outcome {
            HookOutcome::Rewrite { args } => match check {
                Some(check) => check(args)
                    .map_err(|reason| format!("the rewritten args are refused: {reason}")),
                None => Err("a rewrite has nothing to check its args".to_owned()),
            },
            HookOutcome::Skip { .. } if self.call.verb == COMPACT => {
                Err("a host.compact pre-hook may not skip".to_owned())
            }
            HookOutcome::Redact { paths }
                if paths.is_empty()
                    || paths.len() > redact::MAX_PATHS
                    || paths.iter().any(|path| path.len() > redact::MAX_PATH_BYTES) =>
            {
                Err("a redact names 1 to 64 paths of at most 256 bytes".to_owned())
            }
            HookOutcome::Annotate { note } if note.trim().is_empty() => {
                Err("an annotation is empty".to_owned())
            }
            _ => Ok(()),
        }
    }

    fn input(
        &self,
        id: EntityId,
        binding: &PackHookBinding,
        args: &Value,
        result: Option<&Value>,
    ) -> Result<String> {
        let input = Input {
            hook: json!({
                "binding": id.to_hex(),
                "code": binding.code.to_hex(),
                "pack": binding.pack,
                "name": binding.hook,
                "version": binding.hook_version,
                "body_hash": binding.body_hash,
                "blocking": binding.selector.blocking,
            }),
            verb: &self.call.verb,
            phase: phase_token(self.phase),
            invocation: self.call.invocation.to_hex(),
            actor: self.call.actor.to_hex(),
            class: filter::class_token(self.call.class),
            scope: self.call.scope.as_deref(),
            args,
            board_epoch: self.call.board_epoch,
            receipt_tail: &self.tail,
            now: self.now,
            result,
            served: result.and_then(|view| served::rows(view, &binding.selector.served)),
        };
        serde_json::to_string(&input).map_err(|_| Error::InvariantViolation("hook input encode"))
    }

    fn block(
        &mut self,
        id: EntityId,
        binding: &PackHookBinding,
        key: &RunKey,
        request: &BlockRequest,
    ) -> Result<()> {
        let row = HookBlock::from_request(
            id,
            hook_name(binding),
            hex_lower(key),
            request,
            self.vault.store.clock.now_recorded_at(),
        )?;
        let lineage = self.lineage(id, key);
        self.blocks.push((block_id(key)?, row, lineage));
        Ok(())
    }

    /// The chain behind what a run lands: the run itself.
    fn lineage(&self, id: EntityId, key: &RunKey) -> Vec<LineageLink> {
        vec![LineageLink {
            binding: id,
            run_key: hex_lower(key),
            entity: self.call.actor,
            position: format!(
                "verb:{}:{}",
                self.call.invocation.to_hex(),
                phase_token(self.phase)
            ),
        }]
    }

    /// Opens the asking hook's ask; on success the chain's rows commit with
    /// the saved call.
    fn ask(
        &self,
        index: usize,
        hook: Hook<'c>,
        args: &Value,
        label: &str,
    ) -> Result<std::result::Result<VerbHookStop, String>> {
        ask::open(
            self.vault,
            self.call,
            hook,
            index,
            args,
            label,
            &|txn: &mut heed::RwTxn<'_>| self.write_in_txn(txn),
        )
    }

    /// An Ask outcome whose ask did not open is a failed run: a blocking hook
    /// fails safe, any other fails open.
    fn ask_refused(&mut self, binding: &PackHookBinding, refusal: &str) -> Option<VerbHookStop> {
        if let Some(run) = self.runs.last_mut() {
            run.token = "failed".to_owned();
            run.reason = Some(bounded(&format!("the ask did not open: {refusal}")));
        }
        if !binding.selector.blocking {
            return None;
        }
        Some(match self.call.domain {
            VerbDomain::Read => self.hide(binding),
            VerbDomain::Write => {
                self.fail_safe("skipped");
                VerbHookStop::Skipped {
                    hook: hook_name(binding),
                    reason: bounded(&format!("the hook's ask did not open: {refusal}")),
                }
            }
        })
    }

    fn hide(&mut self, binding: &PackHookBinding) -> VerbHookStop {
        self.fail_safe("hidden");
        VerbHookStop::Hidden {
            hook: hook_name(binding),
        }
    }

    fn fail_safe(&mut self, what: &'static str) {
        if let Some(run) = self.runs.last_mut() {
            run.fail_safe = Some(what);
        }
    }

    fn commit(&self) -> Result<()> {
        if self.runs.is_empty() {
            return Ok(());
        }
        self.vault
            .with_write_txn_grouped(|txn| self.write_in_txn(txn))
    }

    /// The chain's receipts, blocks and intents. A retried call writes each
    /// block and intent once.
    fn write_in_txn(&self, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        let vault = self.vault;
        for run in &self.runs {
            store::RECEIPTS.put(&vault.store, txn, &run.key, &self.receipt(run))?;
        }
        for (id, row, chain) in &self.blocks {
            if block::put_new_block_in_txn(vault, txn, *id, row)? {
                lineage::put_in_txn(vault, txn, id.as_bytes(), chain)?;
            }
        }
        for (key, intent, proposal) in &self.intents {
            if store::INTENTS.get(&vault.store, txn, key)?.is_some() {
                continue;
            }
            if let Some(id) = proposal {
                lineage::put_in_txn(vault, txn, id.as_bytes(), &intent.lineage)?;
            }
            store::INTENTS.put(&vault.store, txn, key, intent)?;
        }
        Ok(())
    }

    /// Lands the post chain's queued outcomes, each once, as its hook's
    /// author with source Generated. One that does not land now stays
    /// pending for the runner's start-up drain: the verb's result stands.
    fn apply(&self) {
        if self.intents.is_empty() {
            return;
        }
        let bindings = match self.vault.pack_hook_bindings() {
            Ok(bindings) => bindings,
            Err(error) => {
                tracing::warn!(%error, "verb hook outcomes wait for the hook runner");
                return;
            }
        };
        let mut report = HookPassReport::default();
        for (key, _, _) in &self.intents {
            if let Err(error) = apply::drain_one(self.vault, &bindings, key, &mut report) {
                tracing::warn!(%error, "a verb hook outcome waits for the hook runner");
            }
        }
    }

    /// The run's Hook receipt: the hook, its content hash, the call, the
    /// duration, the outcome, `now` and the rows read.
    fn receipt(&self, run: &RunRecord<'_>) -> ReceiptRecord {
        let binding = run.binding;
        let mut fields: BTreeMap<String, String> = [
            ("binding", run.id.to_hex()),
            ("code", binding.code.to_hex()),
            ("body_hash", binding.body_hash.clone()),
            ("hook", hook_name(binding)),
            ("hook_version", binding.hook_version.clone()),
            ("invocation", self.call.invocation.to_hex()),
            ("verb", bounded(&self.call.verb)),
            ("phase", phase_token(self.phase).to_owned()),
            ("class", filter::class_token(self.call.class).to_owned()),
            ("duration_ms", run.duration_ms.to_string()),
            ("now", self.now.to_string()),
            ("rows_read", run.rows_read.to_string()),
            ("run_key", hex_lower(&run.key)),
            ("fuel_used", run.fuel_used.to_string()),
            ("host_calls", run.host_calls.to_string()),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        for (name, value) in [
            ("reason", run.reason.as_deref()),
            ("note", run.note.as_deref()),
            ("fail_safe", run.fail_safe),
            ("scope", self.call.scope.as_deref()),
        ] {
            if let Some(value) = value {
                fields.insert(name.to_owned(), bounded(value));
            }
        }
        ReceiptRecord {
            receipt_id: store::receipt_id(&run.key),
            receipt_kind: ReceiptKind::Hook,
            occurred_at: self.now / 1_000,
            actor: Some(binding.owner.to_hex()),
            on_behalf_of: Some(self.call.actor.to_hex()),
            outcome: run.token.clone(),
            job_ref: None,
            trigger_ref: Some(self.call.invocation.to_hex()),
            policy_trace: Vec::new(),
            fields,
        }
    }
}

/// A verb run's key: the invocation, the binding and the phase. A retry of
/// one invocation keys the same runs, so their blocks and outcomes land once.
fn run_key(invocation: InvocationId, binding: EntityId, phase: HookPhase) -> RunKey {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron.hook-verb-run-key.v1");
    hasher.update(&invocation.0);
    hasher.update(binding.as_bytes());
    hasher.update(phase_token(phase).as_bytes());
    *hasher.finalize().as_bytes()
}

const fn phase_token(phase: HookPhase) -> &'static str {
    match phase {
        HookPhase::Pre => "pre",
        HookPhase::Post => "post",
        HookPhase::Fact => "fact",
    }
}

fn hook_name(binding: &PackHookBinding) -> String {
    format!("{}/{}", binding.pack, binding.hook)
}
