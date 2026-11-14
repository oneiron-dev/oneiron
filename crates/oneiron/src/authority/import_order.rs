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

type Row = (AuthorityEntryHash, Vec<u8>, FoldRow);

/// A row the consent structure rests on: a genesis, or an owner or admin
/// admission. A sealed row that does not open admits nothing (`admits_device`
/// reads its op, `None` for it), so it is never one here; it still waits for
/// its own grants through [`wanted`].
fn is_consent_row(row: &FoldRow) -> bool {
    row.op().is_some_and(|op| {
        matches!(op, AuthorityOp::Genesis { .. })
            || admits_device(row).is_some_and(is_consent_device)
    })
}

/// A row the door's structure reads: a consent row, a machine revision, or
/// a root record, which names an owner anchor. Open rows only: a sealed row
/// that does not open provides nothing, and pushing it admits nothing.
fn is_structural(row: &FoldRow) -> bool {
    row.op().is_some_and(|op| {
        is_consent_row(row)
            || matches!(
                op,
                AuthorityOp::MachineProfile(_) | AuthorityOp::OwnerRoot(_)
            )
    })
}

/// A handoff: a replica refuses a row a key it retires signs that arrives
/// after it, unless the row is in its line. Open `ReRoot` or a sealed row
/// whose standing is `ReRoot`, so the tier is the same before and after its
/// key arrives.
fn is_handoff(row: &FoldRow) -> bool {
    match row {
        FoldRow::Open(entry) => matches!(entry.op, AuthorityOp::ReRoot { .. }),
        FoldRow::PassThrough(public) => {
            matches!(public.standing(), PublicStanding::ReRoot { .. })
        }
    }
}

/// An owned but not "yours" machine revision. Open rows only: no
/// MachineProfile standing exists.
fn may_restrict(row: &FoldRow) -> bool {
    row.op().is_some_and(|op| {
        matches!(op, AuthorityOp::MachineProfile(profile)
        if matches!(profile.role, MachineRole::Owned(_))
            && profile.role != MachineRole::Owned(MachineOwnership::Yours))
    })
}

/// The grants any one of which lets a key vouch for `row`, and for a
/// handoff the grant that makes its signer a slip issuer. Open rows wait as
/// before; a sealed row that does not open waits for what its public standing
/// names, and provides nothing (it never satisfies another row's wait).
fn wanted(row: &FoldRow) -> Vec<Grant> {
    match row {
        FoldRow::Open(entry) => wanted_open(entry),
        FoldRow::PassThrough(public) => wanted_public(row, public),
    }
}

/// [`wanted`] for an opened entry. A genesis the stored log does not take as
/// its root, or a root record, waits for nothing: no row admits it. A machine
/// revision also waits for its signer to be an owner anchor.
fn wanted_open(entry: &AuthorityLogEntry) -> Vec<Grant> {
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
        AuthorityOp::GrantTravelSet(set) => {
            vec![Grant::InstallKey(set.machine, entry.signer_key().clone())]
        }
        AuthorityOp::CheckpointPolicySet(set) => {
            vec![Grant::InstallKey(set.machine, entry.signer_key().clone())]
        }
        AuthorityOp::HomeNodePick(pick) => {
            vec![Grant::InstallKey(pick.machine, entry.signer_key().clone())]
        }
        AuthorityOp::OriginCut(cut) => {
            vec![Grant::InstallKey(cut.machine, entry.signer_key().clone())]
        }
        AuthorityOp::DeviceSuccession(succession) => {
            vec![Grant::InstallKey(
                succession.machine,
                entry.signer_key().clone(),
            )]
        }
        AuthorityOp::ConversationTrainingSet(set) => {
            vec![Grant::InstallKey(set.machine, entry.signer_key().clone())]
        }
        AuthorityOp::ConversationTrainingVaultSet(set) => {
            vec![Grant::InstallKey(set.machine, entry.signer_key().clone())]
        }
        AuthorityOp::HomeCandidacy(declaration) => {
            vec![Grant::InstallKey(
                declaration.machine,
                entry.signer_key().clone(),
            )]
        }
        AuthorityOp::AgentGrantAct(record) => {
            vec![Grant::InstallKey(
                record.machine,
                entry.signer_key().clone(),
            )]
        }
        AuthorityOp::MembershipExecution(record) => {
            vec![Grant::InstallKey(
                record.machine,
                entry.signer_key().clone(),
            )]
        }
        AuthorityOp::PolicySettingSet(set) => {
            vec![Grant::InstallKey(set.machine, entry.signer_key().clone())]
        }
        AuthorityOp::ExportAct(record) => {
            vec![Grant::InstallKey(
                record.machine,
                entry.signer_key().clone(),
            )]
        }
        // A frontier join waits for its carrier's install key, as the act it
        // leads to does; the host issuer's waits as any admitter's row; an
        // owner anchor's for its signer to be an owner anchor, as the
        // anchor's own rows do (FIX 8498).
        AuthorityOp::FrontierJoin(FrontierJoin {
            family: FrontierJoinFamily::Install(carrier),
            ..
        }) => vec![Grant::InstallKey(*carrier, entry.signer_key().clone())],
        AuthorityOp::FrontierJoin(FrontierJoin {
            family: FrontierJoinFamily::Anchor,
            ..
        }) => vec![Grant::Anchor(entry.signer_key().clone())],
        // The owner's kit push (FIX 6053) waits for its signer to be an
        // owner anchor, as an anchored machine revision does.
        AuthorityOp::OwnerWorkRequest(request) if request.kit_root().is_some() => {
            vec![Grant::Anchor(entry.signer_key().clone())]
        }
        AuthorityOp::OwnerWorkRequest(request) => {
            vec![Grant::InstallKey(
                request.carrier,
                entry.signer_key().clone(),
            )]
        }
        AuthorityOp::OwnerWorkResult(result) => {
            vec![Grant::InstallKey(
                result.executor,
                entry.signer_key().clone(),
            )]
        }
        AuthorityOp::OwnerWorkCancel(cancel) => {
            vec![Grant::InstallKey(
                cancel.carrier,
                entry.signer_key().clone(),
            )]
        }
        AuthorityOp::ExportSupplementImported(mark) => {
            vec![Grant::InstallKey(mark.carrier, entry.signer_key().clone())]
        }
        // A custody request's permit piece waits as the request it leads to
        // (FIX 11866): for its carrier's install key, or with no carrier for
        // its signer to be an owner anchor.
        AuthorityOp::CustodyPermitPiece(piece) => match piece.carrier {
            Some(carrier) => vec![Grant::InstallKey(carrier, entry.signer_key().clone())],
            None => vec![Grant::Anchor(entry.signer_key().clone())],
        },
        // An owner answer waits for its carrier's install key (mesh PR1b).
        AuthorityOp::MachineProfile(MachineProfile {
            carrier: Some(carrier),
            ..
        }) => vec![Grant::InstallKey(*carrier, entry.signer_key().clone())],
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

/// [`wanted`] for a sealed row that does not open, from its public standing:
/// an agent grant waits for its machine's install key; a residence result for
/// its machine's (its directive entry waits as a parent edge in [`Stager`]);
/// an owner work result for its executor's (its request waits there too); a
/// genesis waits for nothing, as an opened one does; an enrollment, a
/// rotation, a re-root or a slip mint waits for its signer's standing, as its
/// opened kind does (admitters, plus the issuer for a re-root). It provides
/// nothing: no grant from it ever wakes another row.
fn wanted_public(row: &FoldRow, public: &AuthorityPublicRow) -> Vec<Grant> {
    let signer = row.signer_key().clone();
    match public.standing() {
        PublicStanding::AgentGrantAct { machine } => {
            vec![Grant::InstallKey(*machine, signer)]
        }
        PublicStanding::ResidenceResult { machine, .. } => {
            vec![Grant::InstallKey(*machine, signer)]
        }
        PublicStanding::OwnerWorkResult { executor, .. } => {
            vec![Grant::InstallKey(*executor, signer)]
        }
        PublicStanding::Genesis { .. } => Vec::new(),
        PublicStanding::EnrollDevice { .. }
        | PublicStanding::RotateKey { .. }
        | PublicStanding::SlipMint => std::iter::once(row.signer())
            .chain(row.cosigns())
            .map(|signature| Grant::Admitter(signature.public_key.clone()))
            .collect(),
        PublicStanding::ReRoot { .. } => std::iter::once(row.signer())
            .chain(row.cosigns())
            .map(|signature| Grant::Admitter(signature.public_key.clone()))
            .chain(std::iter::once(Grant::Issuer(signer)))
            .collect(),
    }
}

/// `rows` in the order an import stages them over `stored`, the rows the
/// store holds, whose hashes are `resident`, with `local`'s anchors this
/// install's own. A row no key comes to vouch for goes last, in the order
/// given; its door holds it. Sealed rows that do not open stage as structure:
/// they wait for their standing's grants and provide none.
pub(super) fn import_order<'a>(
    stored: impl Iterator<Item = &'a FoldRow>,
    resident: &BTreeSet<AuthorityEntryHash>,
    local: LocalRoots,
    rows: Vec<Row>,
) -> Vec<Row> {
    let stored: Vec<&'a FoldRow> = stored.collect();
    let order = {
        let entries: Vec<_> = rows.iter().map(|(hash, _, row)| (*hash, row)).collect();
        consent_order(&stored, resident, local, &entries)
    };
    let mut rows: Vec<_> = rows.into_iter().map(Some).collect();
    order
        .into_iter()
        .filter_map(|index| rows[index].take())
        .collect()
}

/// Indices of `entries` (hash, row) in the order one local write stages
/// them over the rows `store` holds: as an import stages them. Stored rows
/// read as fold rows without forcing them open, so a sealed row that does not
/// open still orders as structure. On a vault that adopted a checkpoint image,
/// the structure also reads the image's carried rows, as the door does, while
/// only the stored rows are resident; those carried bodies are whole entries,
/// wrapped here (the image is out of scope).
pub(super) fn write_stage_order(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entries: &[(AuthorityEntryHash, &FoldRow)],
) -> crate::error::Result<Vec<usize>> {
    let (mut stored, mut resident) = (Vec::new(), BTreeSet::new());
    for (_, body) in authority_log_rows_in_txn(store, txn)? {
        let row = decode_stored_authority_fold_row(store, txn, &body)?;
        resident.insert(row.hash()?);
        stored.push(row);
    }
    let evidence = super::adopted_evidence::adopted_evidence_in_txn(store, txn)?;
    let carried: Vec<FoldRow> = evidence
        .iter()
        .flat_map(|evidence| evidence.bodies())
        .filter(|(hash, _)| !resident.contains(*hash))
        .map(|(_, entry)| FoldRow::Open(entry.clone()))
        .collect();
    let stored: Vec<_> = stored.iter().chain(carried.iter()).collect();
    let local = LocalRoots::read_in_txn(store, txn)?;
    Ok(consent_order(&stored, &resident, local, entries))
}

/// Indices of `entries` in the order [`import_order`] stages them.
fn consent_order(
    stored: &[&FoldRow],
    resident: &BTreeSet<AuthorityEntryHash>,
    local: LocalRoots,
    entries: &[(AuthorityEntryHash, &FoldRow)],
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
/// structure's rows first, then the order given. The sync pass and its tests
/// hold whole entries (commit 8, out of scope), wrapped here as open rows.
#[cfg(any(test, feature = "sync"))]
pub(crate) fn authority_stage_order(
    entries: &[(AuthorityEntryHash, &AuthorityLogEntry)],
) -> Vec<usize> {
    let rows: Vec<FoldRow> = entries
        .iter()
        .map(|(_, entry)| FoldRow::Open((*entry).clone()))
        .collect();
    let staged: Vec<_> = entries
        .iter()
        .zip(rows.iter())
        .map(|((hash, _), row)| (*hash, row))
        .collect();
    stage_order(&staged, None)
}

/// The consent structure of the stored rows and the rows staged so far, and
/// the hashes of the stored rows.
type Consent<'r> = (StructureBuilder<'r>, &'r BTreeSet<AuthorityEntryHash>);

fn stage_order<'r>(
    entries: &'r [(AuthorityEntryHash, &'r FoldRow)],
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
    entries: &'r [(AuthorityEntryHash, &'r FoldRow)],
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
    fn new(entries: &'r [(AuthorityEntryHash, &'r FoldRow)], consent: Option<Consent<'r>>) -> Self {
        let count = entries.len();
        let at: BTreeMap<_, _> = entries
            .iter()
            .enumerate()
            .map(|(index, (hash, _))| (*hash, index))
            .collect();
        // A sealed row that does not open waits for its parents as any row
        // does, plus the entry its standing names: a residence result's
        // directive entry, an owner work result's request. Those land first
        // where they are among the rows.
        let parents = |index: usize| {
            let row = entries[index].1;
            row.parent_hashes()
                .iter()
                .copied()
                .chain(row.public().and_then(|public| match public.standing() {
                    PublicStanding::ResidenceResult {
                        directive_entry, ..
                    } => Some(*directive_entry),
                    PublicStanding::OwnerWorkResult { request, .. } => Some(*request),
                    _ => None,
                }))
                .filter_map(|parent| at.get(&parent).copied())
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
        for (index, (_, row)) in entries.iter().enumerate() {
            let scope = (
                row.signer_key(),
                row.op().and_then(super::world_privacy::side_world),
            );
            scopes
                .entry(scope)
                .or_default()
                .entry(row.seq())
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
            .map(|(_, row)| {
                if is_handoff(row) {
                    HANDOFF_TIER
                } else {
                    2 + u8::from(may_restrict(row))
                }
            })
            .collect();
        let mut expanded = vec![false; levels.len()];
        let mut stack: Vec<_> = (0..count)
            .filter(|index| is_consent_row(entries[*index].1))
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

    /// Defers `index` until a key may vouch for it, or queues it. A sealed
    /// row that does not open is vouched as the structure vouches it (R5) and
    /// waits for its standing's grants; it never provides one.
    fn offer(&mut self, index: usize) {
        let (hash, row) = self.entries[index];
        let vouched = self.consent.as_ref().is_none_or(|(builder, resident)| {
            resident.contains(&hash)
                || (builder.structure.vouches_for(row)
                    && (!is_handoff(row) || builder.structure.issuers.contains(row.signer_key())))
        });
        if !vouched {
            self.is_deferred[index] = true;
            for grant in wanted(row) {
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
        let (turn, seq) = ((self.tier[index], index), self.entries[index].1.seq());
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
        let (hash, row) = self.entries[index];
        let mut grants = Vec::new();
        if let Some((builder, resident)) = &mut self.consent
            && is_structural(row)
            && !resident.contains(&hash)
            && self.pushed.insert(hash)
        {
            builder.push(row);
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
