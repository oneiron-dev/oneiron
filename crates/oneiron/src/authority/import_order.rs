//! The order a store door is handed several AUTHORITY_LOG rows in (H72).
//!
//! A store door judges each row against the rows already stored: it holds a
//! row no key that may vouch for it signed, and a row first observed below a
//! sequence its signer already showed in the same scope folds as a rollback.
//! It never needs a row's parents stored. So each signer's rows in one scope
//! stage by sequence, and each row after the rows among them it names as
//! parents, unless only a parent edge stands in the way: then the parent
//! edge gives way first, and a sequence edge only after it, lowest sequence
//! first. Among the rows ready, the consent structure's rows (genesis, owner
//! and admin admissions) and every row they wait for go first, with the rows
//! of the same signer and sequence as any of them; owned but not "yours"
//! machine revisions, which may land past their signer's bound as
//! restrictions, go after the rest, and a handoff, which retires the keys
//! before it, after every row beside it; then the order given.
//!
//! An import, like a local write of several rows, is one write that aborts
//! on the first held row, so it also stages each row after the rows that let
//! a key vouch for it, and a handoff after the row that makes its signer a
//! slip issuer. A sync pass holds such a row as pending and retries it, so
//! it orders without consent.

use std::collections::{BTreeMap, BTreeSet};

use super::log_structure::{Grant, LocalRoots, StructureBuilder, admits_device, is_consent_device};
use super::*;
use crate::store::Store;

type Row = (AuthorityEntryHash, Vec<u8>, AuthorityLogEntry);

/// A row the consent structure rests on: a genesis, or an owner or admin
/// admission.
fn is_consent_row(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::Genesis { .. }) || admits_device(op).is_some_and(is_consent_device)
}

/// A row the door's structure reads: a consent row, a machine revision, or
/// a root record, which names an owner anchor.
fn is_structural(op: &AuthorityOp) -> bool {
    is_consent_row(op)
        || matches!(
            op,
            AuthorityOp::MachineProfile(_) | AuthorityOp::OwnerRoot(_)
        )
}

/// A handoff: a replica refuses a row a key it retires signs that arrives
/// after it, unless the row is in its line.
fn is_handoff(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::ReRoot { .. })
}

/// An owned but not "yours" machine revision.
fn may_restrict(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::MachineProfile(profile)
        if matches!(profile.role, MachineRole::Owned(_))
            && profile.role != MachineRole::Owned(MachineOwnership::Yours))
}

/// The grants any one of which lets a key vouch for `entry`, and for a
/// handoff the grant that makes its signer a slip issuer. A genesis the
/// stored log does not take as its root, or a root record, waits for
/// nothing: no row admits it. A machine revision also waits for its signer
/// to be an owner anchor.
fn wanted(entry: &AuthorityLogEntry) -> Vec<Grant> {
    match &entry.op {
        AuthorityOp::Genesis { .. } | AuthorityOp::OwnerRoot(_) => Vec::new(),
        AuthorityOp::WorldPrivacy(edit) => {
            vec![Grant::InstallKey(edit.machine, entry.signer_key().clone())]
        }
        AuthorityOp::WorldKeyWraps(record) => {
            vec![Grant::InstallKey(
                record.machine,
                entry.signer_key().clone(),
            )]
        }
        AuthorityOp::ResidenceResult(result) => {
            vec![Grant::InstallKey(
                result.machine,
                entry.signer_key().clone(),
            )]
        }
        op => std::iter::once(&entry.signer)
            .chain(&entry.cosigns)
            .map(|signature| Grant::Admitter(signature.public_key.clone()))
            .chain(
                matches!(op, AuthorityOp::ReRoot { .. })
                    .then(|| Grant::Issuer(entry.signer_key().clone())),
            )
            .chain(
                matches!(op, AuthorityOp::MachineProfile(_))
                    .then(|| Grant::Anchor(entry.signer_key().clone())),
            )
            .collect(),
    }
}

/// `rows` in the order an import stages them over `stored`, the rows the
/// store holds, whose hashes are `resident`, with `local`'s anchors this
/// install's own. A row no key comes to vouch for goes last, in the order
/// given; its door holds it.
pub(super) fn import_order<'a>(
    stored: impl Iterator<Item = &'a AuthorityLogEntry>,
    resident: &BTreeSet<AuthorityEntryHash>,
    local: LocalRoots,
    rows: Vec<Row>,
) -> Vec<Row> {
    let stored: Vec<&'a AuthorityLogEntry> = stored.collect();
    let order = {
        let entries: Vec<_> = rows.iter().map(|(hash, _, entry)| (*hash, entry)).collect();
        consent_order(&stored, resident, local, &entries)
    };
    let mut rows: Vec<_> = rows.into_iter().map(Some).collect();
    order
        .into_iter()
        .filter_map(|index| rows[index].take())
        .collect()
}

/// Indices of `entries` (hash, row) in the order one local write stages
/// them over the rows `store` holds: as an import stages them. On a vault
/// that adopted a checkpoint image, the structure also reads the image's
/// carried rows, as the door does, while only the stored rows are resident.
pub(super) fn write_stage_order(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entries: &[(AuthorityEntryHash, &AuthorityLogEntry)],
) -> crate::error::Result<Vec<usize>> {
    let (mut stored, mut resident) = (Vec::new(), BTreeSet::new());
    for (_, body) in authority_log_rows_in_txn(store, txn)? {
        let entry = decode_authority_log_entry_body(&body)?;
        resident.insert(authority_entry_hash(&entry)?);
        stored.push(entry);
    }
    let evidence = super::adopted_evidence::adopted_evidence_in_txn(store, txn)?;
    let carried = evidence
        .iter()
        .flat_map(|evidence| evidence.bodies())
        .filter(|(hash, _)| !resident.contains(*hash))
        .map(|(_, entry)| entry);
    let stored: Vec<_> = stored.iter().chain(carried).collect();
    let local = LocalRoots::read_in_txn(store, txn)?;
    Ok(consent_order(&stored, &resident, local, entries))
}

/// Indices of `entries` in the order [`import_order`] stages them.
fn consent_order(
    stored: &[&AuthorityLogEntry],
    resident: &BTreeSet<AuthorityEntryHash>,
    local: LocalRoots,
    entries: &[(AuthorityEntryHash, &AuthorityLogEntry)],
) -> Vec<usize> {
    let mut builder = StructureBuilder::under(local);
    for entry in stored {
        builder.push(entry);
    }
    builder.settle();
    builder.grown.clear();
    stage_order(entries, Some((builder, resident)))
}

/// Indices of `entries` (hash, row) in the order a sync pass hands them to
/// the store door: parents first, each signer's rows by sequence, the
/// structure's rows first, then the order given.
#[cfg(any(test, feature = "sync"))]
pub(crate) fn authority_stage_order(
    entries: &[(AuthorityEntryHash, &AuthorityLogEntry)],
) -> Vec<usize> {
    stage_order(entries, None)
}

/// The consent structure of the stored rows and the rows staged so far, and
/// the hashes of the stored rows.
type Consent<'r> = (StructureBuilder<'r>, &'r BTreeSet<AuthorityEntryHash>);

fn stage_order<'r>(
    entries: &'r [(AuthorityEntryHash, &'r AuthorityLogEntry)],
    consent: Option<Consent<'r>>,
) -> Vec<usize> {
    let mut stager = Stager::new(entries, consent);
    for index in 0..entries.len() {
        stager.offer(index);
    }
    while let Some(index) = stager.next() {
        stager.place(index);
    }
    let mut order = stager.order;
    order.extend((0..entries.len()).filter(|index| !stager.placed[*index]));
    order
}

/// A queued row's place: its tier (the consent structure's rows and what
/// they wait for, then the rest; an owned but not "yours" machine revision
/// last in each; handoffs last of all), then the order given.
type Turn = (u8, usize);

/// A handoff's tier, after every other row.
const HANDOFF_TIER: u8 = 4;

/// Which of its edges still hold a row a key vouches for back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Ready,
    ByParent,
    BySequence,
    ByBoth,
}

struct Stager<'r> {
    entries: &'r [(AuthorityEntryHash, &'r AuthorityLogEntry)],
    consent: Option<Consent<'r>>,
    /// Hashes already pushed into the consent structure.
    pushed: BTreeSet<AuthorityEntryHash>,
    /// Per row: its parents among `entries` not yet staged, and its children.
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
    tier: Vec<u8>,
    placed: Vec<bool>,
    held: Vec<Option<Held>>,
    ready: BTreeSet<Turn>,
    by_parent: BTreeSet<Turn>,
    by_sequence: BTreeSet<(u64, Turn)>,
    by_both: BTreeSet<(u64, Turn)>,
    /// Rows no key vouches for yet, under the grants that would wake them.
    deferred: BTreeMap<Grant, Vec<usize>>,
    is_deferred: Vec<bool>,
    order: Vec<usize>,
}

impl<'r> Stager<'r> {
    fn new(
        entries: &'r [(AuthorityEntryHash, &'r AuthorityLogEntry)],
        consent: Option<Consent<'r>>,
    ) -> Self {
        let count = entries.len();
        let at: BTreeMap<_, _> = entries
            .iter()
            .enumerate()
            .map(|(index, (hash, _))| (*hash, index))
            .collect();
        let parents = |index: usize| {
            entries[index]
                .1
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
        for (index, (_, entry)) in entries.iter().enumerate() {
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
        // The consent structure's rows, and every row they wait for, by
        // parent or by sequence, go first, with their signer's other rows of
        // the same sequence, so a demotion never passes its counted sibling
        // there (review round 5, Astra F3). In each tier, an owned but not
        // "yours" revision goes last, the order the issuer's past-bound
        // exception needed before rule 5 retired it. A handoff goes after
        // every row beside it, so a row its predecessors signed beside it
        // lands before it retires them (review round 5, Astra F2).
        let mut tier: Vec<u8> = entries
            .iter()
            .map(|(_, entry)| match &entry.op {
                op if is_handoff(op) => HANDOFF_TIER,
                op => 2 + u8::from(may_restrict(op)),
            })
            .collect();
        let mut expanded = vec![false; levels.len()];
        let mut stack: Vec<_> = (0..count)
            .filter(|index| is_consent_row(&entries[*index].1.op))
            .collect();
        while let Some(index) = stack.pop() {
            if !(2..HANDOFF_TIER).contains(&tier[index]) {
                continue;
            }
            tier[index] -= 2;
            stack.extend(parents(index));
            let level = level_of[index];
            for level in std::iter::once(level).chain(previous_level[level]) {
                if !std::mem::replace(&mut expanded[level], true) {
                    stack.extend(levels[level].iter().copied());
                }
            }
        }
        Self {
            entries,
            consent,
            pushed: BTreeSet::new(),
            waiting,
            children,
            level_of,
            unstaged: levels.iter().map(Vec::len).collect(),
            levels,
            next_level,
            open,
            tier,
            placed: vec![false; count],
            held: vec![None; count],
            ready: BTreeSet::new(),
            by_parent: BTreeSet::new(),
            by_sequence: BTreeSet::new(),
            by_both: BTreeSet::new(),
            deferred: BTreeMap::new(),
            is_deferred: vec![false; count],
            order: Vec::with_capacity(count),
        }
    }

    /// The next row to stage: a ready one, else one only a parent edge
    /// holds back, else the lowest sequence a sequence edge holds back,
    /// whether a parent edge holds it too or not (review round 5, Astra F4).
    fn next(&mut self) -> Option<usize> {
        let (_, index) = match self
            .ready
            .pop_first()
            .or_else(|| self.by_parent.pop_first())
        {
            Some(turn) => turn,
            None => {
                let both_lower = match (self.by_sequence.first(), self.by_both.first()) {
                    (Some(alone), Some(both)) => both < alone,
                    (alone, _) => alone.is_none(),
                };
                let queue = if both_lower {
                    &mut self.by_both
                } else {
                    &mut self.by_sequence
                };
                queue.pop_first()?.1
            }
        };
        self.held[index] = None;
        Some(index)
    }

    /// Defers `index` until a key may vouch for it, or queues it.
    fn offer(&mut self, index: usize) {
        let (hash, entry) = self.entries[index];
        let vouched = self.consent.as_ref().is_none_or(|(builder, resident)| {
            resident.contains(&hash)
                || (builder.structure.vouches_for(entry)
                    && (!matches!(entry.op, AuthorityOp::ReRoot { .. })
                        || builder.structure.issuers.contains(entry.signer_key())))
        });
        if !vouched {
            self.is_deferred[index] = true;
            for grant in wanted(entry) {
                self.deferred.entry(grant).or_default().push(index);
            }
            return;
        }
        self.requeue(index);
    }

    /// Moves `index` to the queue its edges put it in.
    fn requeue(&mut self, index: usize) {
        if self.placed[index] || self.is_deferred[index] {
            return;
        }
        let (turn, seq) = ((self.tier[index], index), self.entries[index].1.seq);
        match self.held[index] {
            Some(Held::Ready) => self.ready.remove(&turn),
            Some(Held::ByParent) => self.by_parent.remove(&turn),
            Some(Held::BySequence) => self.by_sequence.remove(&(seq, turn)),
            Some(Held::ByBoth) => self.by_both.remove(&(seq, turn)),
            None => false,
        };
        let held = match (self.waiting[index] == 0, self.open[self.level_of[index]]) {
            (true, true) => Held::Ready,
            (false, true) => Held::ByParent,
            (true, false) => Held::BySequence,
            (false, false) => Held::ByBoth,
        };
        match held {
            Held::Ready => self.ready.insert(turn),
            Held::ByParent => self.by_parent.insert(turn),
            Held::BySequence => self.by_sequence.insert((seq, turn)),
            Held::ByBoth => self.by_both.insert((seq, turn)),
        };
        self.held[index] = Some(held);
    }

    fn place(&mut self, index: usize) {
        self.placed[index] = true;
        self.order.push(index);
        let (hash, entry) = self.entries[index];
        let mut grants = Vec::new();
        if let Some((builder, resident)) = &mut self.consent
            && is_structural(&entry.op)
            && !resident.contains(&hash)
            && self.pushed.insert(hash)
        {
            builder.push(entry);
            builder.settle();
            grants = std::mem::take(&mut builder.grown);
        }
        for grant in grants {
            for waiter in self.deferred.remove(&grant).unwrap_or_default() {
                if std::mem::replace(&mut self.is_deferred[waiter], false) {
                    self.offer(waiter);
                }
            }
        }
        for child in std::mem::take(&mut self.children[index]) {
            self.waiting[child] -= 1;
            self.requeue(child);
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
                self.requeue(row);
            }
            level = next;
        }
    }
}
