//! Threads of a branching export: the main path, and each edit or
//! regeneration the source kept beside it.

use std::collections::{BTreeMap, HashMap};

/// One node of a message tree, in the source's order.
pub(super) struct TreeNode<'a> {
    pub(super) id: &'a str,
    pub(super) parent: Option<&'a str>,
    /// Orders siblings: the source's rank for it (ChatGPT: its place in its
    /// parent's `children`; Claude.ai: its time), then the source's order.
    pub(super) order: (u64, usize),
}

/// Splits a tree into threads, each one chain. A node continues its parent's
/// thread when it is the parent's first child, and starts a thread of its own
/// otherwise: an edit or a regeneration starts one, and what was said after
/// it continues it. Thread 0 is the conversation as first written, from the
/// first root. Threads are a function of the tree alone, never of the branch
/// the source shows as current, so a later export that switched branches
/// keeps every node it shares with an earlier one in the same thread. Returns
/// node indexes per thread, root first; a node whose parent is missing is a
/// root.
pub(super) fn threads(nodes: &[TreeNode<'_>]) -> Vec<Vec<usize>> {
    let index: HashMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(position, node)| (node.id, position))
        .collect();
    let parent_of = |node: usize| {
        nodes[node]
            .parent
            .and_then(|parent| index.get(parent).copied())
    };
    let mut children: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut roots = Vec::new();
    for position in 0..nodes.len() {
        match parent_of(position) {
            Some(parent) if parent != position => {
                children.entry(parent).or_default().push(position);
            }
            _ => roots.push(position),
        }
    }
    for siblings in children.values_mut() {
        siblings.sort_by_key(|&child| nodes[child].order);
    }
    roots.sort_by_key(|&root| nodes[root].order);

    let mut thread_of = vec![usize::MAX; nodes.len()];
    let mut threads: Vec<Vec<usize>> = Vec::new();
    // Depth-first from each root in source order, first children first, so
    // thread numbering and membership are a function of the tree alone.
    let mut stack: Vec<usize> = roots.into_iter().rev().collect();
    while let Some(node) = stack.pop() {
        let first_child_of = parent_of(node)
            .filter(|parent| children.get(parent).and_then(|kids| kids.first()) == Some(&node));
        let thread = match first_child_of {
            Some(parent) => thread_of[parent],
            None => {
                threads.push(Vec::new());
                threads.len() - 1
            }
        };
        thread_of[node] = thread;
        threads[thread].push(node);
        if let Some(kids) = children.get(&node) {
            stack.extend(kids.iter().rev().copied());
        }
    }
    // Only a parent cycle leaves a node unreached; keep it rather than drop it.
    let unreached: Vec<usize> = (0..nodes.len())
        .filter(|&node| thread_of[node] == usize::MAX)
        .collect();
    if !unreached.is_empty() {
        threads.push(unreached);
    }
    threads
}
