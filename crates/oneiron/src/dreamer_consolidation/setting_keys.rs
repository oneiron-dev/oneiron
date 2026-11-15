//! The Dreamer's restriction Setting key: the owner's "Let the Dreamer lift a restriction on its
//! own" (RULING DREAMER-SETTLE-KEY-SCOPE = B, Engine 16 Nov 01:18). It sits at the vault, and the
//! owner sets it through `vault.settings.set`. A Dreamer act that would lift a restriction reads it
//! in its own writer, and each lift under it writes a [`dreamer_lift_receipt`]. The conflict settle
//! reads it now (`settle::apply_settlement_in_txn`); a follow-up wires the Dreamer's supersede,
//! revert, archive, stale-rung recheck and deferred correction grant to the same key.

use rmpv::Value;

use crate::setting::Kind;

/// Off: the Dreamer asks the owner (today's behaviour).
fn off() -> bool {
    false
}

/// Whether `a` is at least as tight as `b`: asking is tighter than lifting on its own.
fn asking_is_tighter(a: &bool, b: &bool) -> bool {
    !*a || *b
}

crate::setting::setting_keys! {
    /// Let the Dreamer lift a restriction on its own. When off, the Dreamer asks you: the open
    /// conflict waits for your answer. When on, the Dreamer lifts the restriction itself, and every
    /// lift is receipted. Agents and derive batches never lift one.
    pub(crate) DREAMER_LIFTS_RESTRICTIONS: bool = "dreamer.lifts_restrictions" {
        kind: Kind::new(off).strictest(off).tighter(asking_is_tighter),
    };
}

/// The Dreamer act that lifted a restriction under [`DREAMER_LIFTS_RESTRICTIONS`]. The follow-up
/// adds the supersede, revert, archive, stale-rung recheck and deferred correction acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DreamerLiftAct {
    /// A conflict settle superseded the restricting members it did not keep.
    Settle,
}

impl DreamerLiftAct {
    /// The act's name in the receipt.
    const fn label(self) -> &'static str {
        match self {
            Self::Settle => "settle",
        }
    }
}

/// The receipt of one Dreamer lift under [`DREAMER_LIFTS_RESTRICTIONS`]: the key, the act, and the
/// predicate of each restriction lifted (sorted, each once), so the owner's activity line can name
/// what the Dreamer lifted and while doing what.
pub(crate) fn dreamer_lift_receipt(act: DreamerLiftAct, mut lifted: Vec<String>) -> Value {
    lifted.sort_unstable();
    lifted.dedup();
    Value::Map(vec![
        (
            Value::from("key"),
            Value::from(DREAMER_LIFTS_RESTRICTIONS.spec.name),
        ),
        (Value::from("act"), Value::from(act.label())),
        (
            Value::from("lifted"),
            Value::Array(lifted.into_iter().map(Value::from).collect()),
        ),
    ])
}
