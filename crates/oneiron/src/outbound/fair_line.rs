//! The order paced sends go out in once their window opens (FIX 12157).
//!
//! Every send a full count-bound window paced comes back at the instant the
//! window opens, so the order they are taken in then decides whom the window
//! serves: taken in arrival order, one writer's backlog takes it whole. The
//! fair line takes them as the vault's task-work line serves its waiters
//! ([`crate::work_line`]): round-robin across writers, writers in the order
//! their oldest waiting send arrived, and one writer's sends oldest first.
//! So each writer takes one turn in each round, and no writer needs a cap of
//! its own.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

/// `items`, given oldest first with each one's writer, in the fair line's
/// order: one item of each waiting writer per round, oldest first within a
/// writer.
pub(crate) fn fair_line_order<K, T>(items: impl IntoIterator<Item = (K, T)>) -> Vec<T>
where
    K: Hash + Eq + Clone,
{
    let mut waiting: HashMap<K, VecDeque<T>> = HashMap::new();
    let mut turns: VecDeque<K> = VecDeque::new();
    let mut count = 0_usize;
    for (writer, item) in items {
        let line = waiting.entry(writer.clone()).or_default();
        if line.is_empty() {
            turns.push_back(writer);
        }
        line.push_back(item);
        count = count.saturating_add(1);
    }
    let mut order = Vec::with_capacity(count);
    while let Some(writer) = turns.pop_front() {
        let Some(line) = waiting.get_mut(&writer) else {
            continue;
        };
        if let Some(item) = line.pop_front() {
            order.push(item);
        }
        if !line.is_empty() {
            turns.push_back(writer);
        }
    }
    order
}
