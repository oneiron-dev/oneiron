//! A public fold's completed pre chain, carried to its one native Mark action.

use crate::code_run::SelfCall;
use crate::code_run::fold_api::FoldMarkRequest;
use crate::compaction::{FoldKind, SelfFoldCall};
use crate::runtime_hooks::{VerbHookPre, hook_class};
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::{EntityId, WriteActor};

/// Evidence that the public `self.fold` pre chain already admitted these
/// Mark arguments. It carries no authority and is never part of an action's
/// request or replay record; the outer boundary still owns its post chain.
#[derive(Debug, Clone)]
pub struct PreHookedFold {
    actor: EntityId,
    class: HookActorClass,
    from: u64,
    through: u64,
    note: Option<String>,
    kind: Option<FoldKind>,
}

impl PreHookedFold {
    /// Carries only a real public `self.fold` pre chain. A native fold's
    /// differently shaped arguments, or another public verb, carries none.
    #[must_use]
    pub fn from_pre(pre: &VerbHookPre) -> Option<Self> {
        if pre.call().verb != "self.fold" {
            return None;
        }
        let input: FoldMarkRequest = serde_json::from_value(pre.args.clone()).ok()?;
        Some(Self {
            actor: pre.call().actor,
            class: pre.call().class,
            from: input.from,
            through: input.through,
            note: input.note,
            kind: input.kind,
        })
    }

    pub(in crate::code_run) fn covers(&self, actor: WriteActor, call: &SelfCall) -> bool {
        self.actor == actor.entity_ref()
            && self.class == hook_class(actor.actor_class())
            && matches!(call, SelfCall::Fold(SelfFoldCall::Mark { from, through, note, kind })
                if *from == self.from && *through == self.through && *note == self.note
                    && *kind == self.kind)
    }
}
