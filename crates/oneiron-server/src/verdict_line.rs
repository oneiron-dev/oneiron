//! Each `ai.verdict` caller's own Read line (FIX 1123, Rule 5). A verdict's
//! model rungs (the house read, System One, Big and the Local-vision seat)
//! spend on the line of the actor that asked, never on a rung's or the host's
//! shared meter, and nothing on the line is refused for spend. A caller whose
//! verdicts spend past [`SPEND_CHECK_UNITS`] in one window raises one typed
//! health check ("is everything okay: a bot, or a valid burst?", in
//! `wire_health`); its calls go on while the check is asked.
//!
//! The lines live for the server's run.
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard, PoisonError};

use oneiron::{BudgetGuard, EdgeActorClass, EntityId, WriteActor};

/// What one caller's verdicts spend in a window before the host asks whether
/// everything is okay: far above what a working agent spends. A call
/// (CALLS, FIX 1123), and the ask never stops a call.
pub(crate) const SPEND_CHECK_UNITS: u64 = 20_000_000;
/// The window a caller's verdict spend is counted over, in seconds.
pub(crate) const SPEND_WINDOW_SECS: u64 = 86_400;
/// The line's name, as its check names it.
const LINE: &str = "ai.verdict";

/// Every caller's line, and the spend checks not yet kept as health checks.
#[derive(Default)]
pub(crate) struct VerdictLines {
    lines: Mutex<HashMap<EntityId, Line>>,
    crossed: Mutex<Crossed>,
}

struct Line {
    guard: BudgetGuard,
    /// The window the counts below are in.
    window: u64,
    /// What the line had spent when the window began.
    before: u64,
    /// What it had spent at its last read.
    seen: u64,
    /// Whether this window's check was raised.
    raised: bool,
}

#[derive(Default)]
struct Crossed {
    seq: u64,
    last_at: u64,
    /// By key: the time it was raised, then its order on this server.
    pending: BTreeMap<String, SpendCrossing>,
}

/// One caller's verdict spend past [`SPEND_CHECK_UNITS`] in a window.
#[derive(Clone, Debug)]
pub(crate) struct SpendCrossing {
    pub(crate) line: &'static str,
    /// The caller, as its engine-stamped actor.
    pub(crate) actor: String,
    pub(crate) threshold: u64,
    pub(crate) spent: u64,
    /// The window's start and end, in Unix seconds.
    pub(crate) window: [u64; 2],
    pub(crate) raised_at: u64,
}

/// Reads its caller's line when dropped: once the verdict ended, however it
/// ended.
pub(crate) struct Settles<'a> {
    lines: &'a VerdictLines,
    principal: EntityId,
}

impl Drop for Settles<'_> {
    fn drop(&mut self) {
        self.lines.settled(self.principal);
    }
}

impl VerdictLines {
    /// The line `principal` asks on, made on its first verdict.
    pub(crate) fn line(&self, principal: EntityId, class: EdgeActorClass) -> BudgetGuard {
        lock(&self.lines)
            .entry(principal)
            .or_insert_with(|| Line {
                guard: BudgetGuard::uncapped(
                    format!("{LINE}:{}", principal.to_hex()),
                    oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS,
                    WriteActor::new(principal, class),
                ),
                window: 0,
                before: 0,
                seen: 0,
                raised: false,
            })
            .guard
            .clone()
    }

    /// Reads `principal`'s line once the verdict it is held over ends.
    pub(crate) fn settles(&self, principal: EntityId) -> Settles<'_> {
        Settles {
            lines: self,
            principal,
        }
    }

    /// Reads `principal`'s line, and raises the window's spend check the
    /// first time the window's spend passes [`SPEND_CHECK_UNITS`].
    fn settled(&self, principal: EntityId) {
        let now = oneiron_vault_contract::now_ts();
        let window = now / SPEND_WINDOW_SECS * SPEND_WINDOW_SECS;
        let spent = {
            let mut lines = lock(&self.lines);
            let Some(line) = lines.get_mut(&principal) else {
                return;
            };
            let used = line.guard.read().used_units;
            if line.window != window {
                line.window = window;
                line.before = line.seen;
                line.raised = false;
            }
            line.seen = used;
            let spent = used.saturating_sub(line.before);
            if line.raised || spent < SPEND_CHECK_UNITS {
                return;
            }
            line.raised = true;
            spent
        };
        let actor = principal.to_hex();
        tracing::warn!(
            kind = "verdict_spend_crossed",
            %actor,
            spent,
            threshold = SPEND_CHECK_UNITS,
            "a caller's verdicts spent past their check; is everything okay?"
        );
        let mut crossed = lock(&self.crossed);
        crossed.seq = crossed.seq.saturating_add(1);
        crossed.last_at = crossed.last_at.max(now);
        let key = format!("{:020}:{:020}", crossed.last_at, crossed.seq);
        crossed.pending.insert(
            key,
            SpendCrossing {
                line: LINE,
                actor,
                threshold: SPEND_CHECK_UNITS,
                spent,
                window: [window, window.saturating_add(SPEND_WINDOW_SECS)],
                raised_at: now,
            },
        );
    }

    /// The spend checks raised after `after` (an earlier one's key), oldest
    /// first. Those at or before it are kept as health checks already, and
    /// are dropped.
    pub(crate) fn crossings_after(&self, after: Option<&str>) -> Vec<(String, SpendCrossing)> {
        let mut crossed = lock(&self.crossed);
        if let Some(after) = after {
            crossed.pending.retain(|key, _| key.as_str() > after);
        }
        crossed
            .pending
            .iter()
            .map(|(key, crossing)| (key.clone(), crossing.clone()))
            .collect()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
