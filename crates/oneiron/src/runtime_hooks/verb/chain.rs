//! The verb-hook chain (ARCH-0080 §3): matching, run order, each run's input
//! and verdict, the failure policy by domain, and the one write that commits
//! a chain's receipts, saved runs, blocks and intents once it resolves, even
//! when a Skip or an Ask stops the verb. In an off-record room its hooks read
//! the room's view and its records stage in the room's own store
//! ([`session`], [`storage`]; WILL L11-01 S01-2c).

mod run;
mod session;
mod storage;

use std::cell::Cell;
use std::sync::Arc;

use serde::Serialize;
use serde_json::{Value, json};

use crate::receipt::hex_lower;
use crate::runtime_hooks::block::HookBlock;
use crate::runtime_hooks::lineage::LineageLink;
use crate::runtime_hooks::outcome::{BlockRequest, HookOutcome};
use crate::runtime_hooks::runner::{block_id, bounded};
use crate::runtime_hooks::store::{HookIntent, RunKey};
use crate::runtime_hooks::{HookBodyRuntime, filter, scope};
use crate::skill_hub::pack_catalog::{HookPhase, HookSelector, PackHookBinding};
use crate::task_verb::revoke_lands::Landing;
use crate::work_line::TaskWorkTurn;
use crate::{EntityId, Error, Result, Vault};

use super::state::{Carry, Entered, HookDepth, depth};
use super::storage::VerbHookStorage;
use super::{
    InvocationId, VerbArgsCheck, VerbCall, VerbDomain, VerbHookPre, VerbHookStop, VerbResume, ask,
    redact, served,
};

use run::RunRecord;

/// Receipts the input's tail carries.
const RECEIPT_TAIL: usize = 8;
/// The host verb a pre-hook may never skip: a skipped compaction overflows
/// the next turn (ARCH-0080 §5).
const COMPACT: &str = "host.compact";
/// Why a resumed chain in a build without the sandbox runs no hook.
const NO_SANDBOX: &str = "this build runs no hook sandbox";

/// One hook a call matched: its binding id and row.
type Hook<'b> = (EntityId, &'b PackHookBinding);

type Stopped<T> = std::result::Result<T, VerbHookStop>;

/// Whether a verb hook may run on `verb`: no when hooks are off or
/// suppressed, at hook depth 1, or when no binding's verb glob takes it. The
/// cached binding list answers; one that does not read answers yes, so the
/// chain reports the error. Scope is not read here: a scoped binding may run.
/// A call an earlier try of its invocation left saved reaches the chain
/// whatever this says ([`super::ask::saved`]).
pub(super) fn may_run(vault: &Vault, verb: &str) -> bool {
    let state = &vault.verb_hook_state;
    if state.suppressed() || depth() > 0 {
        return false;
    }
    match state.bindings(vault) {
        Ok(bindings) => bindings.verb.iter().any(|(_, binding)| {
            binding
                .selector
                .verbs
                .iter()
                .any(|glob| filter::glob_match(glob, verb))
        }),
        Err(_) => true,
    }
}

/// The pre chain of `call`. At hook depth 1, and inside the same actor's
/// call of this invocation, it passes through. Otherwise what an earlier try
/// of the invocation left comes first: a retry while the drain runs the call
/// again gets the ask's Pending, one after it what the call returned, and a
/// call still parked on its ask its Pending. A settled proceed resumes after
/// the asking hook under current authority, even when no hook matches now:
/// its commit still uses the answer up. With hooks off or suppressed a
/// parked call stays parked, and resumes once they are back on. Only a call
/// with nothing saved passes through with hooks off, without the sandbox,
/// or when no binding matches; the cached binding list keeps that last case
/// free of reads. `resume` is how settlement could run the call again
/// without its caller: an ask saves it. `turn` is the task-work turn the
/// calling operation already holds: a hook's ask and a retry's read of it run
/// on it as the hook's author ([`ask::retry`], [`ask::open`]).
pub(super) fn pre(
    vault: &Vault,
    storage: VerbHookStorage<'_>,
    call: VerbCall,
    args: Value,
    check: VerbArgsCheck<'_>,
    resume: Option<&VerbResume>,
    turn: Option<Arc<TaskWorkTurn>>,
) -> Result<Stopped<VerbHookPre>> {
    if depth() > 0 {
        return through(call, args);
    }
    let state = &vault.verb_hook_state;
    let mark = match state.enter(call.invocation, call.actor) {
        Entered::Nested => return through(call, args),
        Entered::Draining(group) => return Ok(Err(ask::pending(call.invocation, group))),
        Entered::Fresh(mark) => mark,
    };
    // The owner's revoke always lands (FIX 5076): a restrictive call, judged
    // on its caller's own args (and, for a polymorphic row, what the vault
    // holds of them, FIX 5137-5139), keeps them to fall back to.
    let mut landing = Landing::of(vault, &call.verb, &args);
    // A session-only call resumes from the in-memory keep (L13 PR-D), a
    // room's call under its stretch (FIX 5524).
    let saved = match storage {
        VerbHookStorage::Session(hooks) => {
            let _depth = HookDepth::enter();
            ask::session::retry(vault, hooks, hooks.pause_key(), &call, turn.as_ref())?
        }
        VerbHookStorage::Canonical => {
            let _depth = HookDepth::enter();
            ask::retry(vault, &call, resume, turn.as_ref())?
        }
    };
    // A recorded call run as new after the ask its retry named was forgot
    // says so in its receipts (FIX 5693).
    let expired =
        matches!(storage, VerbHookStorage::Canonical) && state.take_expired(call.invocation);
    let resumed = match saved {
        ask::Retry::Fresh => None,
        ask::Retry::Stop(stop) => return Ok(Err(stop)),
        ask::Retry::Resume {
            binding,
            position,
            args,
            token,
        } => Some((binding, position, args, token)),
    };
    let bindings = if state.suppressed() {
        None
    } else {
        Some(session::hook_read(
            storage,
            "bindings",
            state.bindings(vault),
        )?)
    };
    let Some(bindings) = bindings.filter(|bindings| bindings.enabled) else {
        return match resumed {
            Some((.., token)) => Ok(Err(token.parked(call.invocation))),
            None => through(call, args),
        };
    };
    let hooks = session::hook_read(
        storage,
        "scopes",
        matching(vault, &bindings.verb, HookPhase::Pre, &call),
    )?;
    let runtime = state.runtime();
    let (start, args, token) = match resumed {
        None => {
            if runtime.is_none()
                || (hooks.is_empty()
                    && session::hook_read(
                        storage,
                        "scopes",
                        matching(vault, &bindings.verb, HookPhase::Post, &call),
                    )?
                    .is_empty())
            {
                return through(call, args);
            }
            (0, args, None)
        }
        Some((binding, position, args, token)) => (
            hooks
                .iter()
                .position(|(id, _)| *id == binding)
                .unwrap_or(position)
                .saturating_add(1),
            args,
            Some(token),
        ),
    };
    let carry = Carry {
        mark,
        now: vault.store.clock.now_recorded_at().saturating_mul(1_000),
    };
    if token.is_none() && hooks.is_empty() {
        return Ok(Ok(VerbHookPre {
            call,
            args,
            carry: Some(carry),
            landing: None,
            session: None,
        }));
    }
    // A resumed call with no sandbox runs no hook after the asking one, as a
    // new call would run none.
    let (runtime, hooks) = match runtime {
        Some(runtime) => (runtime, hooks),
        None => (Err(NO_SANDBOX), Vec::new()),
    };
    let _depth = HookDepth::enter();
    let mut chain = Chain::new(
        vault,
        storage,
        &call,
        HookPhase::Pre,
        runtime,
        carry.now,
        turn,
    );
    chain.landing = landing.as_mut();
    chain.expired = expired;
    let ended = chain.pre(&hooks, start, args, check, token, resume)?;
    Ok(ended.map(|args| VerbHookPre {
        call,
        args,
        carry: Some(carry),
        landing,
        session: None,
    }))
}

/// The post chain over the verb's `result`, for a call whose pre chain found
/// hooks live.
pub(super) fn post(
    vault: &Vault,
    storage: VerbHookStorage<'_>,
    pre: VerbHookPre,
    result: Value,
) -> Result<Stopped<Value>> {
    let VerbHookPre {
        call, args, carry, ..
    } = pre;
    let state = &vault.verb_hook_state;
    let Some(carry) = carry else {
        return Ok(Ok(result));
    };
    if state.suppressed() || depth() > 0 {
        return Ok(Ok(result));
    }
    let bindings = session::hook_read(storage, "bindings", state.bindings(vault))?;
    let hooks = session::hook_read(
        storage,
        "scopes",
        matching(vault, &bindings.verb, HookPhase::Post, &call),
    )?;
    if hooks.is_empty() {
        return Ok(Ok(result));
    }
    let Some(runtime) = state.runtime() else {
        return Ok(Ok(result));
    };
    let _depth = HookDepth::enter();
    let ended = Chain::new(
        vault,
        storage,
        &call,
        HookPhase::Post,
        runtime,
        carry.now,
        None,
    )
    .post(&hooks, &args, result);
    // A nested boundary of this invocation passes through until here.
    drop(carry.mark);
    ended
}

fn through(call: VerbCall, args: Value) -> Result<Stopped<VerbHookPre>> {
    Ok(Ok(VerbHookPre {
        call,
        args,
        carry: None,
        landing: None,
        session: None,
    }))
}

/// The bindings that take `call` in `phase`. A storage error reading a
/// scope fails the chain, as other binding reads do.
fn matching<'b>(
    vault: &Vault,
    bindings: &'b [(EntityId, PackHookBinding)],
    phase: HookPhase,
    call: &VerbCall,
) -> Result<Vec<Hook<'b>>> {
    let mut hooks = Vec::new();
    for (id, binding) in bindings {
        if takes(vault, &binding.selector, phase, call)? {
            hooks.push((*id, binding));
        }
    }
    Ok(hooks)
}

/// Whether `selector` takes `call` in `phase`: a verb glob, the class, and a
/// scope that holds the call's ([`scope::call_within`]). The scope is read
/// last, so an unscoped binding reads nothing.
fn takes(
    vault: &Vault,
    selector: &HookSelector,
    phase: HookPhase,
    call: &VerbCall,
) -> Result<bool> {
    if selector.phase != phase
        || !selector
            .verbs
            .iter()
            .any(|glob| filter::glob_match(glob, &call.verb))
        || !(selector.actors.is_empty() || selector.actors.contains(&call.class))
    {
        return Ok(false);
    }
    match selector.scope.as_deref() {
        None => Ok(true),
        Some(wanted) => scope::call_within(vault, wanted, call),
    }
}

/// One chain: its call and phase, and what its runs leave to commit.
struct Chain<'c> {
    vault: &'c Vault,
    /// Where its hooks read content and its records go.
    storage: VerbHookStorage<'c>,
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
    /// The proceed answer a resumed pre chain uses up in its commit.
    token: Option<ask::AskToken>,
    /// Set when that answer was used meanwhile: nothing committed.
    used: Cell<bool>,
    /// The task-work turn the calling operation holds, which a hook's ask
    /// runs on; `None` in a post chain, which opens no ask.
    turn: Option<Arc<TaskWorkTurn>>,
    /// A restrictive pre chain's landing: each rewrite is pinned, and one
    /// still refused keeps the prior args, no hook failure (FIX 5076).
    landing: Option<&'c mut Landing>,
    /// Set on a recorded call's pre chain its retry runs as new, after the
    /// drain's pass forgot the ask it named: each receipt says so (FIX 5693).
    expired: bool,
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
        storage: VerbHookStorage<'c>,
        call: &'c VerbCall,
        phase: HookPhase,
        runtime: std::result::Result<&'c dyn HookBodyRuntime, &'c str>,
        now: u64,
        turn: Option<Arc<TaskWorkTurn>>,
    ) -> Self {
        let tail = vault
            .memory(call.actor, filter::edge_class(call.class))
            .receipts(RECEIPT_TAIL)
            .ok()
            .and_then(|receipts| serde_json::to_value(receipts).ok())
            .unwrap_or_else(|| Value::Array(Vec::new()));
        Self {
            vault,
            storage,
            call,
            phase,
            runtime,
            now,
            tail,
            runs: Vec::new(),
            blocks: Vec::new(),
            intents: Vec::new(),
            token: None,
            used: Cell::new(false),
            turn,
            landing: None,
            expired: false,
        }
    }

    /// Runs the pre-hooks from `start`. Rewrites chain; the first Skip or
    /// Ask ends the chain. A failed blocking hook sends a write to an ask and
    /// hides a read. A chain resumed on `token` checks the saved args again
    /// first, as the caller's own may be checked under other authority now,
    /// and uses the answer up in its commit; `resume` goes with a later ask.
    fn pre(
        mut self,
        hooks: &[Hook<'c>],
        start: usize,
        mut args: Value,
        check: VerbArgsCheck<'_>,
        token: Option<ask::AskToken>,
        resume: Option<&VerbResume>,
    ) -> Result<Stopped<Value>> {
        if let Some(token) = &token
            && let Err(reason) = check(&args)
        {
            let stop = VerbHookStop::Skipped {
                hook: token.hook.clone(),
                reason: bounded(&format!("the saved args are refused now: {reason}")),
            };
            self.token = Some(token.clone());
            return self.end_pre(Err(stop));
        }
        self.token = token;
        for (index, &(id, binding)) in hooks.iter().enumerate().skip(start) {
            let verb = self.call.verb.clone();
            let rewrite_check = |next: &Value| {
                crate::runtime_hooks::host_doors::check_rewrite(&verb, &args, next)?;
                check(next)
            };
            // A restrictive call's rewrite is pinned and checked here, not in
            // the run: one still refused keeps the prior args, is recorded as
            // refused and fails nothing (FIX 5076).
            let landed = |_: &Value| -> std::result::Result<(), String> { Ok(()) };
            let run_check: VerbArgsCheck<'_> = if self.landing.is_some() {
                &landed
            } else {
                &rewrite_check
            };
            let stop = match self.run(id, binding, &args, None, Some(run_check))? {
                Some(HookOutcome::Rewrite { args: next }) => {
                    let (chosen, refused) = match self.landing.as_deref_mut() {
                        Some(landing) => landing.select(&args, next, &rewrite_check),
                        None => (next, None),
                    };
                    if let (Some(reason), Some(run)) = (refused, self.runs.last_mut()) {
                        run.token = "refused".to_owned();
                        run.reason = Some(bounded(&reason));
                    }
                    args = chosen;
                    None
                }
                Some(HookOutcome::Skip { reason }) => Some(VerbHookStop::Skipped {
                    hook: hook_name(binding),
                    reason: bounded(&reason),
                }),
                Some(HookOutcome::Ask { question }) => {
                    let label = if question.trim().is_empty() {
                        format!(
                            "Hook {} asks before {}.",
                            hook_name(binding),
                            self.call.verb
                        )
                    } else {
                        format!(
                            "Hook {} asks before {}: {question}",
                            hook_name(binding),
                            self.call.verb
                        )
                    };
                    match self.ask(index, (id, binding), &args, &label, resume)? {
                        Ok(pending) => return Ok(Err(pending)),
                        Err(refusal) => self.ask_refused(binding, &refusal),
                    }
                }
                Some(_) => None,
                // A refused Skip (including a blocking hook's) cannot
                // turn compaction into an Ask and stop the pass.
                None if self.call.verb == COMPACT => None,
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
                        match self.ask(index, (id, binding), &args, &label, resume)? {
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
                return self.end_pre(Err(stop));
            }
        }
        self.end_pre(Ok(args))
    }

    /// Commits the pre chain's rows and ends it with `ended`. A resumed
    /// chain whose answer another try used meanwhile commits nothing and
    /// ends Skipped.
    fn end_pre(&self, ended: Stopped<Value>) -> Result<Stopped<Value>> {
        match self.commit() {
            Ok(()) => Ok(ended),
            Err(_) if self.used.get() => Ok(Err(self.used_stop())),
            Err(error) => Err(error),
        }
    }

    /// The Skipped a resumed chain ends with when its answer was used.
    fn used_stop(&self) -> VerbHookStop {
        VerbHookStop::Skipped {
            hook: self
                .token
                .as_ref()
                .map(|token| token.hook.clone())
                .unwrap_or_default(),
            reason: ask::USED.to_owned(),
        }
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

    /// Opens the asking hook's ask, on the calling operation's task-work
    /// turn; on success the chain's rows commit with the saved call and its
    /// `resume` target, and a resumed chain's old answer is used up first in
    /// the same write. When that answer was used meanwhile, nothing commits
    /// and the stop is the used Skip.
    fn ask(
        &self,
        index: usize,
        hook: Hook<'c>,
        args: &Value,
        label: &str,
        resume: Option<&VerbResume>,
    ) -> Result<std::result::Result<VerbHookStop, String>> {
        if let VerbHookStorage::Session(hooks) = self.storage {
            return self.ask_in_session(hooks, hooks.pause_key(), index, hook, args, label);
        }
        let opened = ask::open(
            self.vault,
            self.call,
            hook,
            index,
            args,
            label,
            resume,
            self.turn.as_ref(),
            &|txn: &mut heed::RwTxn<'_>| self.write_in_txn(txn),
        );
        if self.used.get() {
            return Ok(Ok(self.used_stop()));
        }
        opened
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
