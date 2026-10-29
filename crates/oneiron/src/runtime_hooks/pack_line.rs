//! The pack lines generative fact hooks' `ai.verdict` asks spend on (FIX
//! 10075): one per pack and author, held for the vault's life in this
//! process. Every rung a verdict climbs admits and settles its own calls on
//! the line, once; a hook record only names those settlements.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use crate::llm::DEFAULT_BUDGET_RESERVE_UNITS;
use crate::{BudgetGuard, EntityId, Vault, WriteActor};

use super::body::HookVerdictContext;
use super::filter;

/// The vault's hook pack lines, by pack and author.
#[derive(Debug, Default)]
pub(crate) struct HookPackLines {
    lines: Mutex<HashMap<(String, EntityId), BudgetGuard>>,
}

impl HookPackLines {
    /// The line of `context`'s pack and author: the one guard every verdict
    /// of that pack shares, built on first use (clones share one line).
    fn line(&self, context: &HookVerdictContext) -> BudgetGuard {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry((context.pack.clone(), context.author))
            .or_insert_with(|| {
                BudgetGuard::uncapped(
                    format!("hook.pack:{}:{}", context.pack, context.author.to_hex()),
                    DEFAULT_BUDGET_RESERVE_UNITS,
                    WriteActor::new(context.author, filter::edge_class(context.author_class)),
                )
            })
            .clone()
    }
}

impl Vault {
    /// The line a hook's verdict spends on: its pack's, shared by every
    /// verdict of every hook in that pack under the same author (FIX
    /// 10075). It is uncapped (rule 5): it attributes spend and never
    /// refuses it, and a free or keyless rung stays free on it. Resolved
    /// here, by the host, from the binding the runner named, never from a
    /// request.
    #[must_use]
    pub fn hook_pack_line(&self, context: &HookVerdictContext) -> BudgetGuard {
        self.verb_hook_state.pack_lines.line(context)
    }
}
