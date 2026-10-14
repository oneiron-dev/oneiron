//! The order an import stages a signed history in (H72).
//!
//! An import is one write, and a store door judges each row against the rows
//! already stored: it holds a row no key that may vouch for it signed, which
//! aborts the import, and a row first observed below a sequence its signer
//! already showed in the same scope folds as a rollback. So each row is
//! staged after every row among them it names as a parent, after the rows
//! that let a key vouch for it, and after its signer's rows of lower
//! sequence in the same scope. The sequence order gives way only where the
//! parents contradict it, in a malformed history. Among the rows ready, the
//! rows the consent structure rests on, and every row they wait for, go
//! first, so each other row is judged under as much of the history's
//! structure as it can be; then the order given.

use std::collections::{BTreeMap, BTreeSet};

use super::log_budget::{Grant, StructureBuilder, admits_device, is_consent_device};
use super::*;

type Row = (AuthorityEntryHash, Vec<u8>, AuthorityLogEntry);

/// A row the consent structure rests on: a genesis, an owner or admin
/// admission, or a machine revision.
fn is_structural(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::Genesis { .. } | AuthorityOp::MachineProfile(_)
    ) || admits_device(op).is_some_and(is_consent_device)
}

/// The grants any one of which lets a key vouch for `entry`. A genesis the
/// stored log does not take as its root waits for nothing: no row admits it.
fn wanted(entry: &AuthorityLogEntry) -> Vec<Grant> {
    match &entry.op {
        AuthorityOp::Genesis { .. } => Vec::new(),
        AuthorityOp::WorldPrivacy(edit) => {
            vec![Grant::InstallKey(edit.machine, entry.signer_key().clone())]
        }
        _ => std::iter::once(&entry.signer)
            .chain(&entry.cosigns)
            .map(|signature| Grant::Admitter(signature.public_key.clone()))
            .collect(),
    }
}

/// `rows` in the order an import stages them over `stored`, the rows the
/// store holds, whose hashes are `resident`. A row no key comes to vouch for
/// goes last, in the order given; its door holds it.
pub(super) fn import_order<'a>(
    stored: impl Iterator<Item = &'a AuthorityLogEntry>,
    resident: &BTreeSet<AuthorityEntryHash>,
    rows: Vec<Row>,
) -> Vec<Row> {
    let order = {
        let mut stager = Stager::new(&rows, resident);
        for entry in stored {
            stager.builder.push(entry);
        }
        stager.builder.settle();
        stager.builder.grown.clear();
        for index in 0..rows.len() {
            if stager.waiting[index] == 0 {
                stager.offer(index);
            }
        }
        while let Some((_, index)) = stager
            .ready
            .pop_first()
            .or_else(|| stager.out_of_turn.pop_first())
        {
            stager.place(index);
        }
        let mut order = stager.order;
        order.extend((0..rows.len()).filter(|index| !stager.placed[*index]));
        order
    };
    let mut rows: Vec<_> = rows.into_iter().map(Some).collect();
    order
        .into_iter()
        .filter_map(|index| rows[index].take())
        .collect()
}

/// A ready row's place in the queue: the structure's rows and what they
/// wait for first, then the order given.
type Turn = (bool, usize);

struct Stager<'r> {
    rows: &'r [Row],
    resident: &'r BTreeSet<AuthorityEntryHash>,
    /// The consent structure of the stored rows and the rows staged so far.
    builder: StructureBuilder<'r>,
    /// Per row: its parents among `rows` not yet staged, and its children.
    waiting: Vec<usize>,
    children: Vec<Vec<usize>>,
    /// Each signer's rows in one sequence scope, one level per sequence,
    /// lowest first. A level opens once every row of the levels below it
    /// is staged.
    level_of: Vec<usize>,
    levels: Vec<Vec<usize>>,
    next_level: Vec<Option<usize>>,
    open: Vec<bool>,
    unstaged: Vec<usize>,
    structure_first: Vec<bool>,
    placed: Vec<bool>,
    /// Rows whose parents are staged and that a key vouches for: in turn,
    /// or with a lower-sequence row of their signer still unstaged.
    ready: BTreeSet<Turn>,
    out_of_turn: BTreeSet<Turn>,
    /// Rows whose parents are staged and that no key vouches for yet.
    deferred: BTreeMap<Grant, Vec<usize>>,
    is_deferred: Vec<bool>,
    order: Vec<usize>,
}

impl<'r> Stager<'r> {
    fn new(rows: &'r [Row], resident: &'r BTreeSet<AuthorityEntryHash>) -> Self {
        let count = rows.len();
        let at: BTreeMap<_, _> = rows
            .iter()
            .enumerate()
            .map(|(index, (hash, ..))| (*hash, index))
            .collect();
        let parents = |index: usize| {
            rows[index]
                .2
                .parent_hashes
                .iter()
                .filter_map(|parent| at.get(parent).copied())
        };
        let mut waiting = vec![0; count];
        let mut children = vec![Vec::new(); count];
        for (index, waiting) in waiting.iter_mut().enumerate() {
            for parent in parents(index) {
                *waiting += 1;
                children[parent].push(index);
            }
        }
        let mut scopes: BTreeMap<_, BTreeMap<u64, Vec<usize>>> = BTreeMap::new();
        for (index, (_, _, entry)) in rows.iter().enumerate() {
            let scope = (
                entry.signer_key(),
                super::world_privacy::side_world(&entry.op),
            );
            scopes
                .entry(scope)
                .or_default()
                .entry(entry.seq)
                .or_default()
                .push(index);
        }
        let (mut level_of, mut levels) = (vec![0; count], Vec::new());
        let (mut next_level, mut previous_level, mut open) = (Vec::new(), Vec::new(), Vec::new());
        for by_seq in scopes.into_values() {
            let mut below = None;
            for members in by_seq.into_values() {
                let level = levels.len();
                for index in &members {
                    level_of[*index] = level;
                }
                if let Some(below) = below {
                    next_level[below] = Some(level);
                }
                previous_level.push(below);
                next_level.push(None);
                open.push(below.is_none());
                levels.push(members);
                below = Some(level);
            }
        }
        // The rows the structure rests on, and every row they wait for, by
        // parent or by sequence.
        let mut structure_first = vec![false; count];
        let mut expanded = vec![false; levels.len()];
        let mut stack: Vec<_> = (0..count)
            .filter(|index| is_structural(&rows[*index].2.op))
            .collect();
        while let Some(index) = stack.pop() {
            if std::mem::replace(&mut structure_first[index], true) {
                continue;
            }
            stack.extend(parents(index));
            if let Some(below) = previous_level[level_of[index]]
                && !std::mem::replace(&mut expanded[below], true)
            {
                stack.extend(levels[below].iter().copied());
            }
        }
        Self {
            rows,
            resident,
            builder: StructureBuilder::default(),
            waiting,
            children,
            level_of,
            unstaged: levels.iter().map(Vec::len).collect(),
            levels,
            next_level,
            open,
            structure_first,
            placed: vec![false; count],
            ready: BTreeSet::new(),
            out_of_turn: BTreeSet::new(),
            deferred: BTreeMap::new(),
            is_deferred: vec![false; count],
            order: Vec::with_capacity(count),
        }
    }

    fn turn(&self, index: usize) -> Turn {
        (!self.structure_first[index], index)
    }

    /// Queues `index`, whose parents are all staged.
    fn offer(&mut self, index: usize) {
        let (hash, _, entry) = &self.rows[index];
        if !self.resident.contains(hash) && !self.builder.structure.vouches_for(entry) {
            self.is_deferred[index] = true;
            for grant in wanted(entry) {
                self.deferred.entry(grant).or_default().push(index);
            }
            return;
        }
        let turn = self.turn(index);
        if self.open[self.level_of[index]] {
            self.ready.insert(turn);
        } else {
            self.out_of_turn.insert(turn);
        }
    }

    fn place(&mut self, index: usize) {
        self.placed[index] = true;
        self.order.push(index);
        let rows = self.rows;
        let (hash, _, entry) = &rows[index];
        if is_structural(&entry.op) && !self.resident.contains(hash) {
            self.builder.push(entry);
            self.builder.settle();
            for grant in std::mem::take(&mut self.builder.grown) {
                for waiter in self.deferred.remove(&grant).unwrap_or_default() {
                    if std::mem::replace(&mut self.is_deferred[waiter], false) {
                        self.offer(waiter);
                    }
                }
            }
        }
        for child in std::mem::take(&mut self.children[index]) {
            self.waiting[child] -= 1;
            if self.waiting[child] == 0 {
                self.offer(child);
            }
        }
        let mut level = self.level_of[index];
        self.unstaged[level] -= 1;
        while self.open[level]
            && self.unstaged[level] == 0
            && let Some(next) = self.next_level[level]
            && !self.open[next]
        {
            self.open[next] = true;
            for row in std::mem::take(&mut self.levels[next]) {
                let turn = self.turn(row);
                if self.out_of_turn.remove(&turn) {
                    self.ready.insert(turn);
                }
            }
            level = next;
        }
    }
}
