//! `host.compact` (ARCH-0080 §5) around one compaction pass. The pre chain
//! runs once the window, its keep list and the token ceiling are in hand,
//! before the request seals: a Rewrite may only add lines to keep word for
//! word, and a Skip is refused, since a skipped compaction overflows the next
//! turn. The post chain runs once the pass landed its keyframe, and may
//! Annotate it.

use serde_json::{Value, json};

use super::{CompactionWindowMessage, SwapPlan};
use crate::error::VerbHookStop;
use crate::runtime_hooks::verb::RoomHookCall;
use crate::store::pack_hook_actor_class::HookActorClass;
use crate::store::verb_invocation::InvocationId;
use crate::{EntityId, Vault};
use crate::{runtime_hooks::VerbCall, runtime_hooks::VerbHookPre, store::verb_domain::VerbDomain};

/// The host verb a compaction pass runs under.
pub const HOST_COMPACT: &str = "host.compact";

/// A pass past its pre chain, as its post chain picks it up once the
/// keyframe lands, or the typed Pending its blocking hook saved (FIX 10085).
#[derive(Debug, Default)]
pub struct CompactHooks {
    pre: Option<VerbHookPre>,
    pending: Option<VerbHookStop>,
}

impl CompactHooks {
    /// The saved ask/Pending stop, never an ordinary unavailable pass.
    #[must_use]
    pub const fn pending(&self) -> Option<&VerbHookStop> {
        self.pending.as_ref()
    }
}

/// The invocation of one pass of a host-numbered log: the same across a
/// retry of the pass at the same watermark.
#[must_use]
pub fn compact_invocation(log: &[u8], watermark: u64) -> InvocationId {
    InvocationId::of_run_step(&[log, HOST_COMPACT.as_bytes()].concat(), watermark)
}

impl Vault {
    /// Runs `host.compact`'s pre chain over one pass: its `window`, its
    /// `keep` list and its `token_ceiling`. `keep` grows by the lines the
    /// hooks pin, each found word for word in the window, while `fits` says
    /// the summary still holds the whole list. A pass never waits on its
    /// hooks: a stop, or a storage error, leaves the host's own list.
    pub fn pre_compact_hooks(
        &self,
        invocation: InvocationId,
        actor: EntityId,
        reader: Option<crate::claim::ScopedReadActorKey>,
        window: &[CompactionWindowMessage],
        keep: &mut Vec<String>,
        token_ceiling: u64,
        fits: &dyn Fn(&[String]) -> bool,
    ) -> CompactHooks {
        let args = compact_args(window, keep, token_ceiling);
        let call = compact_call(invocation, actor, reader);
        let contains = |pin: &str| window.iter().any(|message| message.content.contains(pin));
        let check = |rewritten: &Value| added_pins(&args, rewritten, &contains, fits).map(|_| ());
        let ended = self.pre_verb_hooks(call, args.clone(), &check);
        compact_hooks_ended(ended, &args, window, keep, fits)
    }

    /// Runs `host.compact`'s post chain once the pass landed `plan`'s
    /// keyframe over turns `first..=last`. The keyframe stands whatever a
    /// post-hook says.
    pub fn post_compact_hooks(&self, hooks: CompactHooks, plan: &SwapPlan, first: u64, last: u64) {
        let Some(pre) = hooks.pre else {
            return;
        };
        if let Err(error) = self.post_verb_hooks(pre, compact_result(plan, first, last)) {
            tracing::warn!(
                ?error,
                "host.compact post-hooks failed on a landed keyframe"
            );
        }
    }
}

/// One pass's args: its `window`, its `keep` list and its `token_ceiling`.
fn compact_args(window: &[CompactionWindowMessage], keep: &[String], token_ceiling: u64) -> Value {
    json!({
        "window": window
            .iter()
            .map(|message| json!({
                "turn": message.turn,
                "content": message.content,
                "tokens": message.tokens,
            }))
            .collect::<Vec<_>>(),
        "keep_list": keep,
        "token_ceiling": token_ceiling,
    })
}

/// The `host.compact` call of one pass. `reader` is the run's verified
/// credential-bound key, independent of the host's System write attribution,
/// as a turn's does (REVIEW-4357 P1-1); `None` reads as the actor.
fn compact_call(
    invocation: InvocationId,
    actor: EntityId,
    reader: Option<crate::claim::ScopedReadActorKey>,
) -> VerbCall {
    VerbCall {
        verb: HOST_COMPACT.to_owned(),
        invocation,
        actor,
        // A write a host verb causes stamps the System class.
        class: HookActorClass::System,
        scope: None,
        board_epoch: None,
        turn: None,
        domain: VerbDomain::Write,
        reader,
    }
}

/// A landed pass's result, as its post chain reads it.
fn compact_result(plan: &SwapPlan, first: u64, last: u64) -> Value {
    json!({
        "epoch": plan.epoch,
        "summary": plan.summary_id.to_hex(),
        "first_turn": first,
        "last_turn": last,
    })
}

/// What a pass keeps of its pre chain's end, on the vault or in a room:
/// the pins it added join `keep`, a Pending stands typed, and a stop or a
/// storage error leaves the host's own list (a pass never waits on hooks).
fn compact_hooks_ended(
    ended: crate::Result<std::result::Result<VerbHookPre, VerbHookStop>>,
    args: &Value,
    window: &[CompactionWindowMessage],
    keep: &mut Vec<String>,
    fits: &dyn Fn(&[String]) -> bool,
) -> CompactHooks {
    let contains = |pin: &str| window.iter().any(|message| message.content.contains(pin));
    match ended {
        Ok(Ok(pre)) => {
            if let Ok(added) = added_pins(args, &pre.args, &contains, fits) {
                keep.extend(added);
            }
            CompactHooks {
                pre: Some(pre),
                pending: None,
            }
        }
        Ok(Err(stop)) => {
            if matches!(&stop, VerbHookStop::Pending { .. }) {
                return CompactHooks {
                    pre: None,
                    pending: Some(stop),
                };
            }
            tracing::warn!(%stop, "host.compact pre-hooks stopped; the pass keeps its own pins");
            CompactHooks::default()
        }
        Err(error) => {
            tracing::warn!(
                ?error,
                "host.compact pre-hooks failed; the pass keeps its own pins"
            );
            CompactHooks::default()
        }
    }
}

/// [`Vault::pre_compact_hooks`] for a run bound to a room (FIX 1594): the
/// pre chain runs in the room on the run's captured route, as a turn's
/// does since FIX 5563, so its receipts land in the room, never on
/// record. Hooks that cannot be read there leave the pass its own pins.
pub(crate) fn pre_compact_hooks_in_room(
    session: &crate::off_record::OffRecordSession<'_>,
    route: &crate::session_overlay::SessionWriteRoute,
    invocation: InvocationId,
    actor: EntityId,
    reader: Option<crate::claim::ScopedReadActorKey>,
    window: &[CompactionWindowMessage],
    keep: &mut Vec<String>,
    token_ceiling: u64,
    fits: &dyn Fn(&[String]) -> bool,
) -> CompactHooks {
    let args = compact_args(window, keep, token_ceiling);
    let call = compact_call(invocation, actor, reader);
    let contains = |pin: &str| window.iter().any(|message| message.content.contains(pin));
    let check = |rewritten: &Value| added_pins(&args, rewritten, &contains, fits).map(|_| ());
    let how = RoomHookCall {
        answers_unread: true,
        ..RoomHookCall::default()
    };
    let ended = session
        .pre_verb_hooks_in_room(route, call, args.clone(), &check, how)
        .map(|(ended, _)| ended);
    compact_hooks_ended(ended, &args, window, keep, fits)
}

/// [`Vault::post_compact_hooks`] for a pass whose pre chain ran in a room
/// (FIX 1594).
pub(crate) fn post_compact_hooks_in_room(
    session: &crate::off_record::OffRecordSession<'_>,
    route: &crate::session_overlay::SessionWriteRoute,
    hooks: CompactHooks,
    plan: &SwapPlan,
    first: u64,
    last: u64,
) {
    let Some(pre) = hooks.pre else {
        return;
    };
    if let Err(error) =
        session.post_verb_hooks_in_room(route, pre, compact_result(plan, first, last), true)
    {
        tracing::warn!(
            ?error,
            "host.compact post-hooks failed on a landed keyframe"
        );
    }
}

/// [`Vault::post_compact_hooks`] for a pass whose pre chain ran in a room but
/// which ends without landing (a backend refusal or a pre-swap-gate
/// rejection, REVIEW-4357 P1-2): its pre chain's records are kept in the
/// room, and no post chain runs.
pub(crate) fn keep_compact_hooks_in_room(
    session: &crate::off_record::OffRecordSession<'_>,
    route: &crate::session_overlay::SessionWriteRoute,
    hooks: CompactHooks,
) {
    let Some(pre) = hooks.pre else {
        return;
    };
    if let Err(error) = session.keep_verb_hooks_in_room(route, pre) {
        tracing::warn!(%error, "an unlanded room pass's verb hook records were not kept");
    }
}

/// The pins a `host.compact` rewrite adds to the host's keep list. The
/// window and the ceiling are the host's; the keep list only grows, each new
/// line nonblank, found word for word in the window and kept once, and the
/// whole list still fits the summary.
fn added_pins(
    args: &Value,
    rewritten: &Value,
    contains: &dyn Fn(&str) -> bool,
    fits: &dyn Fn(&[String]) -> bool,
) -> std::result::Result<Vec<String>, String> {
    let (Some(host), Some(hooked)) = (args.as_object(), rewritten.as_object()) else {
        return Err("a host.compact rewrite is an object".to_owned());
    };
    if hooked.len() != host.len()
        || host
            .iter()
            .any(|(key, value)| key != "keep_list" && hooked.get(key) != Some(value))
    {
        return Err("a host.compact rewrite changes only its keep list".to_owned());
    }
    let lines = |value: Option<&Value>| -> Option<Vec<String>> {
        value?
            .as_array()?
            .iter()
            .map(|line| line.as_str().map(str::to_owned))
            .collect()
    };
    let (Some(kept), Some(after)) = (lines(host.get("keep_list")), lines(hooked.get("keep_list")))
    else {
        return Err("a keep list holds lines".to_owned());
    };
    if after.len() < kept.len() || after[..kept.len()] != kept[..] {
        return Err("a host.compact rewrite only adds to its keep list".to_owned());
    }
    for (at, pin) in after.iter().enumerate().skip(kept.len()) {
        if pin.trim().is_empty() || !contains(pin) {
            return Err("a pinned line occurs word for word in the window".to_owned());
        }
        if after[..at].contains(pin) {
            return Err("a pinned line is kept once".to_owned());
        }
    }
    if after.len() > kept.len() && !fits(&after) {
        return Err("the summary cannot hold the added lines under its token ceiling".to_owned());
    }
    Ok(after[kept.len()..].to_vec())
}

/// The public trigger and the executor's attach point share the add-only,
/// word-for-word pin law. The window and ceiling remain the host's.
pub fn check_host_compact_rewrite(args: &Value, rewritten: &Value) -> Result<(), String> {
    let window = args
        .get("window")
        .and_then(Value::as_array)
        .ok_or("a compaction window holds messages")?;
    let contains = |pin: &str| {
        window.iter().any(|message| {
            message
                .get("content")
                .and_then(Value::as_str)
                .is_some_and(|content| content.contains(pin))
        })
    };
    check_host_compact_rewrite_with(args, rewritten, &contains)
}

/// Replay-side host.compact rewrite check over a saved window that holds
/// withheld placeholders instead of text: the window and ceiling presence,
/// the immutable fields and the append-only keep list still apply, but pin
/// membership in the window cannot run on placeholders and is skipped — the
/// live chain admits against the restored window, which replay cannot
/// rebuild.
pub fn check_host_compact_rewrite_unverified_window(
    args: &Value,
    rewritten: &Value,
) -> Result<(), String> {
    check_host_compact_rewrite_with(args, rewritten, &|_| true)
}

fn check_host_compact_rewrite_with(
    args: &Value,
    rewritten: &Value,
    contains: &dyn Fn(&str) -> bool,
) -> Result<(), String> {
    let ceiling = args
        .get("token_ceiling")
        .and_then(Value::as_u64)
        .ok_or("a compaction token ceiling is an integer")?;
    let fits = |pins: &[String]| {
        crate::tokenizer::count_context_pack_tokens(&pins.join("\n")) as u64 <= ceiling
    };
    added_pins(args, rewritten, contains, &fits).map(|_| ())
}

/// A host's explicit compaction uses the same sealed request, cheap backend,
/// six-check gate and epoch mint as automatic compaction. No model logic or
/// direct writes live in its transport handler.
pub(crate) fn host_compact_as_owner(
    memory: &crate::memory::Memory<'_>,
    owner: &crate::consent::AuthenticatedOwner,
    input: crate::compaction::host_request::HostCompactRequest,
    backend: &dyn super::CompactionBackend,
    policy: &super::CompactionGatePolicy,
) -> oneiron_contracts::memory::MemoryResult<crate::compaction::host_request::HostCompactResult> {
    use oneiron_contracts::memory::{MEMORY_CODE_INVALID_STATE, MemoryError};
    let vault = memory.vault();
    if input.token_ceiling == 0 {
        return Err(MemoryError::bad_request("token_ceiling must be positive"));
    }
    if backend.tier_class() != super::CompactionTierClass::Cheap {
        return Err(MemoryError::bad_request(
            "compaction requires a cheap backend",
        ));
    }
    let fits = |pins: &[String]| {
        crate::tokenizer::count_context_pack_tokens(&pins.join("\n")) as u64 <= input.token_ceiling
    };
    if !fits(&input.keep_list)
        || input.keep_list.iter().any(|pin| {
            pin.trim().is_empty()
                || !input
                    .window
                    .iter()
                    .any(|message| message.content.contains(pin))
        })
    {
        return Err(MemoryError::bad_request(
            "keep_list must fit and occur word for word in the window",
        ));
    }
    let turns: Vec<EntityId> = input.window.iter().map(|message| message.turn_id).collect();
    {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        owner.revalidate_in_txn(vault, &txn)?;
        super::validate_session(&vault.store, &txn, input.session_ref)?;
        super::validate_turn_membership(&vault.store, &txn, &turns, input.session_ref)?;
    }
    backend.prepare_flight(true).map_err(|why| {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!("compaction unavailable: {why:?}"),
            &[],
        )
    })?;
    let request = super::driver::CompactionRequest::for_host(
        vault,
        input.session_ref,
        input.window,
        input.keep_list,
        input.token_ceiling,
    )?;
    let mut retry = None;
    for _ in 0..policy.tries {
        let product = backend.compact(&request, retry).map_err(|why| {
            MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                format!("compaction refused: {why:?}"),
                &[],
            )
        })?;
        match super::gate_compaction(&request, &product, policy) {
            Ok(gated) => {
                let text = gated.summary_text().to_owned();
                let last_turn = request
                    .window
                    .last()
                    .expect("sealed window is nonempty")
                    .turn;
                let (epoch, summary) = super::epoch::mint_epoch_summary_guarded(
                    vault,
                    &input.session_ref,
                    memory.write_actor(),
                    gated.request(),
                    &super::CompactionProduct {
                        summary_text: text.clone(),
                        ..product
                    },
                    None,
                    |txn| {
                        owner.revalidate_in_txn(vault, txn)?;
                        memory
                            .verify_actor_write_in_txn(txn)
                            .map_err(|error| crate::Error::InvalidConfig(error.to_string()))?;
                        super::validate_session(&vault.store, txn, input.session_ref)?;
                        super::validate_turn_membership(
                            &vault.store,
                            txn,
                            &turns,
                            input.session_ref,
                        )
                    },
                    |_, _| Ok(()),
                )?;
                return Ok(crate::compaction::host_request::HostCompactResult {
                    epoch,
                    summary,
                    text,
                    keep_list: request.pins.clone(),
                    first_turn: request.turn_start,
                    last_turn,
                });
            }
            Err(failure) => retry = Some(failure.check),
        }
    }
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("compaction gate refused its replies: {retry:?}"),
        &[],
    ))
}
