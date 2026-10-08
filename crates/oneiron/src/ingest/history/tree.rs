//! Threads of a branching export: the main path, and each edit or
//! regeneration the source kept beside it.

use std::collections::{BTreeMap, HashMap};

/// One node of a message tree, in the source's order.
pub(super) struct TreeNode<'a> {
    pub(super) id: &'a str,
    pub(super) parent: Option<&'a str>,
    /// Orders siblings: the source time, then the source's own order.
    pub(super) order: (u64, usize),
}

/// Splits a tree into threads. Thread 0 is the main path, root to `leaf` (the
/// node the source shows as current; the latest leaf when it names none). Each
/// node off that path joins its parent's thread when it is the parent's first
/// child off the main path, and starts a new thread otherwise, so every thread
/// is one chain and every node is in exactly one. Returns node indexes per
/// thread, root first; a node whose parent is missing is a root.
pub(super) fn threads(nodes: &[TreeNode<'_>], leaf: Option<&str>) -> Vec<Vec<usize>> {
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

    let leaf = leaf.and_then(|leaf| index.get(leaf).copied()).or_else(|| {
        (0..nodes.len())
            .filter(|node| !children.contains_key(node))
            .max_by_key(|&node| nodes[node].order)
    });
    let mut thread_of = vec![usize::MAX; nodes.len()];
    let mut main = Vec::new();
    let mut cursor = leaf;
    // Bounded by the node count, so a parent cycle cannot loop.
    while let Some(node) = cursor {
        if thread_of[node] != usize::MAX {
            break;
        }
        thread_of[node] = 0;
        main.push(node);
        cursor = parent_of(node);
    }
    main.reverse();
    let mut threads = vec![main];

    // Depth-first from each root in source order, so thread numbering and
    // membership are a function of the tree alone.
    let mut stack: Vec<usize> = roots.into_iter().rev().collect();
    while let Some(node) = stack.pop() {
        if thread_of[node] == usize::MAX {
            let parent = parent_of(node).filter(|&parent| thread_of[parent] != 0);
            let continues = parent.and_then(|parent| {
                let first_off_main = children
                    .get(&parent)?
                    .iter()
                    .copied()
                    .find(|&child| thread_of[child] != 0)?;
                (first_off_main == node).then_some(thread_of[parent])
            });
            match continues {
                Some(thread) if thread != usize::MAX => {
                    thread_of[node] = thread;
                    threads[thread].push(node);
                }
                _ => {
                    thread_of[node] = threads.len();
                    threads.push(vec![node]);
                }
            }
        }
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
