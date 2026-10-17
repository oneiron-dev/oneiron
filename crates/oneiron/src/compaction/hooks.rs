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
            "keep": keep,
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
        };
        let check =
            |rewritten: &Value| added_pins(&args, rewritten, window, fits).map(|_| ());
        match self.pre_verb_hooks(call, args.clone(), &check) {
            Ok(Ok(pre)) => {
                if let Ok(added) = added_pins(&args, &pre.args, window, fits) {
                    keep.extend(added);
                }
                CompactHooks(Some(pre))
            }
            Ok(Err(stop)) => {
                tracing::warn!(%stop, "host.compact pre-hooks stopped; the pass keeps its own pins");
                CompactHooks(None)
            }
            Err(error) => {
                tracing::warn!(?error, "host.compact pre-hooks failed; the pass keeps its own pins");
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
            tracing::warn!(?error, "host.compact post-hooks failed on a landed keyframe");
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
    window: &[CompactionWindowMessage],
    fits: &dyn Fn(&[String]) -> bool,
) -> std::result::Result<Vec<String>, String> {
    let (Some(host), Some(hooked)) = (args.as_object(), rewritten.as_object()) else {
        return Err("a host.compact rewrite is an object".to_owned());
    };
    if hooked.len() != host.len()
        || host
            .iter()
            .any(|(key, value)| key != "keep" && hooked.get(key) != Some(value))
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
    let (Some(kept), Some(after)) = (lines(host.get("keep")), lines(hooked.get("keep"))) else {
        return Err("a keep list holds lines".to_owned());
    };
    if after.len() < kept.len() || after[..kept.len()] != kept[..] {
        return Err("a host.compact rewrite only adds to its keep list".to_owned());
    }
    for (at, pin) in after.iter().enumerate().skip(kept.len()) {
        if pin.trim().is_empty()
            || !window
                .iter()
                .any(|message| message.content.contains(pin.as_str()))
        {
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
