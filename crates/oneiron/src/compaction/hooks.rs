//! `host.compact` (ARCH-0080 §5) around one compaction pass. The pre chain
//! runs once the window, its keep list and the token ceiling are in hand,
//! before the request seals: a Rewrite may only add lines to keep word for
//! word, and a Skip is refused, since a skipped compaction overflows the next
//! turn. The post chain runs once the pass landed its keyframe, and may
//! Annotate it.

use serde_json::{Value, json};

use super::{CompactionWindowMessage, SwapPlan};
use crate::runtime_hooks::{InvocationId, VerbCall, VerbDomain, VerbHookPre};
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::{EntityId, Vault};

/// The host verb a compaction pass runs under.
pub const HOST_COMPACT: &str = "host.compact";

/// A pass past its pre chain, as its post chain picks it up once the
/// keyframe lands. Empty when no hook is live for the pass.
#[derive(Debug, Default)]
pub struct CompactHooks(Option<VerbHookPre>);

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
        window: &[CompactionWindowMessage],
        keep: &mut Vec<String>,
        token_ceiling: u64,
        fits: &dyn Fn(&[String]) -> bool,
    ) -> CompactHooks {
        let args = json!({
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
        });
        let call = VerbCall {
            verb: HOST_COMPACT.to_owned(),
            invocation,
            actor,
            // A write a host verb causes stamps the System class.
            class: HookActorClass::System,
            scope: None,
            board_epoch: None,
            domain: VerbDomain::Write,
            // A host's own call reads as its actor.
            reader: None,
        };
        let contains = |pin: &str| window.iter().any(|message| message.content.contains(pin));
        let check = |rewritten: &Value| added_pins(&args, rewritten, &contains, fits).map(|_| ());
        match self.pre_verb_hooks(call, args.clone(), &check) {
            Ok(Ok(pre)) => {
                if let Ok(added) = added_pins(&args, &pre.args, &contains, fits) {
                    keep.extend(added);
                }
                CompactHooks(Some(pre))
            }
            Ok(Err(stop)) => {
                tracing::warn!(%stop, "host.compact pre-hooks stopped; the pass keeps its own pins");
                CompactHooks(None)
            }
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "host.compact pre-hooks failed; the pass keeps its own pins"
                );
                CompactHooks(None)
            }
        }
    }

    /// Runs `host.compact`'s post chain once the pass landed `plan`'s
    /// keyframe over turns `first..=last`. The keyframe stands whatever a
    /// post-hook says.
    pub fn post_compact_hooks(&self, hooks: CompactHooks, plan: &SwapPlan, first: u64, last: u64) {
        let Some(pre) = hooks.0 else {
            return;
        };
        let result = json!({
            "epoch": plan.epoch,
            "summary": plan.summary_id.to_hex(),
            "first_turn": first,
            "last_turn": last,
        });
        if let Err(error) = self.post_verb_hooks(pre, result) {
            tracing::warn!(
                ?error,
                "host.compact post-hooks failed on a landed keyframe"
            );
        }
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
    let ceiling = args
        .get("token_ceiling")
        .and_then(Value::as_u64)
        .ok_or("a compaction token ceiling is an integer")?;
    let contains = |pin: &str| {
        window.iter().any(|message| {
            message
                .get("content")
                .and_then(Value::as_str)
                .is_some_and(|content| content.contains(pin))
        })
    };
    let fits = |pins: &[String]| {
        crate::tokenizer::count_context_pack_tokens(&pins.join("\n")) as u64 <= ceiling
    };
    added_pins(args, rewritten, &contains, &fits).map(|_| ())
}

/// A host's explicit compaction uses the same sealed request, cheap backend,
/// six-check gate and epoch mint as automatic compaction. No model logic or
/// direct writes live in its transport handler.
pub(crate) fn host_compact_as_owner(
    memory: &crate::memory::Memory<'_>,
    owner: &crate::consent::AuthenticatedOwner,
    input: crate::runtime_hooks::host_doors::HostCompactRequest,
    backend: &dyn super::CompactionBackend,
    policy: &super::CompactionGatePolicy,
) -> crate::memory::MemoryResult<crate::runtime_hooks::host_doors::HostCompactResult> {
    use crate::memory::{MEMORY_CODE_INVALID_STATE, MemoryError};
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
                    crate::WriteActor::new(memory.actor(), memory.actor_class()),
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
                return Ok(crate::runtime_hooks::host_doors::HostCompactResult {
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
