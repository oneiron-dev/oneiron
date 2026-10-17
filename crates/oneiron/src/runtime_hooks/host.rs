//! `host.budget.hit` (ARCH-0080 §5): a budget line spent under its
//! exhaustion policy. The hit is one event, not a call with a body, so its
//! pre and post chains run back to back once the host acted on it.

use serde_json::{Value, json};

use crate::skill_hub::pack_catalog::HookActorClass;
use crate::{BudgetExhaustionPolicy, EntityId, Vault};

use super::{InvocationId, VerbCall, VerbDomain};

/// The host verb a budget hit runs under.
pub const HOST_BUDGET_HIT: &str = "host.budget.hit";

/// One budget hit, as its hooks read it.
#[derive(Debug, Clone)]
pub struct BudgetHit<'a> {
    /// The seat whose line ran out: the line's id.
    pub seat: &'a str,
    /// What the line does once spent.
    pub policy: BudgetExhaustionPolicy,
    /// The line's accounting as it stood at the hit.
    pub accounting: Value,
    /// Whose work the line paid for.
    pub actor: EntityId,
    pub invocation: InvocationId,
}

impl Vault {
    /// Runs `host.budget.hit`'s chains once the host acted on `hit`. A
    /// pre-hook may add a block; a post-hook reads the line's accounting as
    /// it stood, and may Annotate it or Enqueue follow-up work, which pays
    /// through the queue's own budget doors. No hook lifts the hit: a stop is
    /// kept on its receipt, and the line stays spent.
    pub fn budget_hit_hooks(&self, hit: BudgetHit<'_>) {
        let args = json!({"seat": hit.seat, "policy": hit.policy});
        let call = VerbCall {
            verb: HOST_BUDGET_HIT.to_owned(),
            invocation: hit.invocation,
            actor: hit.actor,
            // A write a host verb causes stamps the System class.
            class: HookActorClass::System,
            scope: None,
            board_epoch: None,
            domain: VerbDomain::Write,
        };
        let check = |rewritten: &Value| {
            if *rewritten == args {
                Ok(())
            } else {
                Err("a host verb's args are the host's".to_owned())
            }
        };
        let pre = match self.pre_verb_hooks(call, args.clone(), &check) {
            Ok(Ok(pre)) => pre,
            Ok(Err(stop)) => {
                tracing::info!(%stop, "host.budget.hit pre-hooks stopped; the hit stands");
                return;
            }
            Err(error) => {
                tracing::warn!(?error, "host.budget.hit pre-hooks failed");
                return;
            }
        };
        let result = json!({"seat": hit.seat, "accounting": hit.accounting});
        if let Err(error) = self.post_verb_hooks(pre, result) {
            tracing::warn!(?error, "host.budget.hit post-hooks failed");
        }
    }
}
