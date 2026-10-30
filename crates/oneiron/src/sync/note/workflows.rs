//! NOTE review workflows as window carriers hold them (FIX 8877, 8878, 8879).
//!
//! A NOTE's core rides the window of the month it was learned in; a review
//! bundle belongs to no month. It rides beside each NOTE it holds a member
//! of, whole, with the rows of its other member NOTEs as attachments: each
//! row bound to its own NOTE and to the bundle or the fork it serves, never
//! an off-month entity row. Where an export may not carry every member NOTE,
//! the bundle rides as a projection onto the NOTEs it does carry: their
//! members alone, the shared explainer redacted, never marked complete.
//!
//! A carrier holds proposal values only: the value of each undecided fork,
//! never a merge basis or the value of a current or retired head. A fork
//! names its real parent document, the NOTE itself or a fork a switch made
//! its head, and the carrier holds every decided fork that family passes
//! through. Received carriers stay advisory: nothing here mints a fork, an
//! authorship, a receipt or a landing.

use super::*;
use crate::FederationGrantScope;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::note::NoteVerdict;
use crate::side_table::{self, HexId, Named, Raw, SideKey, SideTable};
use crate::sync::SyncSelector;
use serde::{Deserialize, Serialize};

/// Recorded NOTE forks awaiting review/decision (owned by `note::proposals`;
/// this binds the same `note_fork:v1:` declaration for this module's
/// read-only export scan — "two typed tables may bind one declaration").
const NOTE_FORK: SideTable<EntityId, NoteFork, Named> = SideTable::new(&side_table::NOTE_FORK);
/// Durable head-move receipts (owned by `note::proposals`; see [`NOTE_FORK`]).
const NOTE_RECEIPT: SideTable<EntityId, NoteLandingReceipt, Named> =
    SideTable::new(&side_table::NOTE_RECEIPT);
/// Review bundles (owned by `note::proposals`; see [`NOTE_FORK`]).
const NOTE_PROPOSAL_BUNDLE: SideTable<EntityId, NoteReviewBundle, Named> =
    SideTable::new(&side_table::NOTE_PROPOSAL_BUNDLE);
/// Loro snapshot bytes of a proposal (non-live) NOTE document head, keyed by
/// [`NoteForkKey`] (owned by `note::documents`; see [`NOTE_FORK`]).
const NOTE_PROPOSAL_DOC: SideTable<NoteForkKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_PROPOSAL_DOC);

/// `hex32(note) ":" hex32(fork)` — the [`NOTE_PROPOSAL_DOC`] key shape
/// (mirrors `note::side_keys::HexPair`, not visible from this module tree).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NoteForkKey(HexId, HexId);

impl SideKey for NoteForkKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
        out.push(b':');
        self.1.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (a, rest) = bytes.split_at_checked(32)?;
        let b = rest.strip_prefix(b":")?;
        Some(Self(HexId::decode_key(a)?, HexId::decode_key(b)?))
    }
}

/// A review bundle as a window carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct BundleCarrier {
    pub(super) bundle: NoteReviewBundle,
    /// Every member rides, with the explainer they share. A projection
    /// holds the members of the NOTEs its window carries and no explainer.
    pub(super) complete: bool,
}

impl BundleCarrier {
    /// This bundle once a member left it: its explainer could quote what
    /// left, and it is no longer whole.
    pub(super) fn redact(&mut self) {
        REDACTED.clone_into(&mut self.bundle.explainer);
        self.complete = false;
    }

    /// This bundle as a projection onto the members of the NOTEs in `keep`.
    fn project_onto(&mut self, keep: &BTreeSet<EntityId>) {
        self.bundle.waiting.retain(|fork| keep.contains(&fork.note));
        self.bundle
            .landed
            .retain(|receipt| keep.contains(&receipt.note));
        self.redact();
    }
}

/// `fork` in the proposal-only shape every ordinary carrier holds (FIX
/// 8879): no historical merge basis, so no parent text. Explicit history
/// widening is a separate export.
fn proposal_only(fork: NoteFork) -> NoteFork {
    NoteFork {
        recovery_merge: None,
        ..fork
    }
}

/// What one export judges a NOTE by, in its own read `txn`: the window's
/// `tombstones`, the device-only worlds `flagged` for its destination, and,
/// for a selector export, that grant's scope and the exact selector.
pub(super) struct Judge<'a, 't> {
    pub(super) vault: &'a Vault,
    pub(super) txn: &'a heed::RoTxn<'t>,
    pub(super) tombstones: &'a TombstoneIndex,
    pub(super) flagged: &'a BTreeSet<EntityId>,
    pub(super) selector: Option<(FederationGrantScope, &'a SyncSelector)>,
}

impl Judge<'_, '_> {
    /// Whether the export drops `note`, a NOTE whose core its window holds:
    /// blocked, or kept on this device by a device-only world.
    pub(super) fn drops(&self, note: &EntityId) -> Result<bool> {
        Ok(blocked(self.vault, self.txn, self.tombstones, note)?
            || held(self.vault, self.txn, self.flagged, note)?)
    }

    /// Whether the rows of `note`, a NOTE whose core rides another window,
    /// may ride here as attachments: not dropped, not deleted here, and for
    /// a selector export selected by that exact selector wherever it is
    /// placed. A refused selection is no attachment, never a failed export.
    pub(super) fn attaches(&self, note: &EntityId) -> Result<bool> {
        if self.drops(note)?
            || crate::ports::TombstoneStore::port_tombstone_is_deleted(self.vault, self.txn, note)?
        {
            return Ok(false);
        }
        Ok(self.selector.is_none_or(|(scope, selector)| {
            crate::sync::selector::admit_note_in_txn(
                self.vault, self.txn, *note, scope, selector, None,
            )
            .is_ok()
        }))
    }
}

/// Which NOTEs held only as attachments still ride an export.
enum Attached {
    /// The source's attachments already passed the selection that made it.
    AsCarried,
    /// Exactly these passed this export's own judgement.
    Judged(BTreeSet<EntityId>),
}

/// What an export carries of the NOTE workflows its source window holds
/// (FIX 8878): the NOTEs whose cores it drops, and which NOTEs held there
/// only as attachments still ride.
pub(crate) struct NoteSelection {
    dropped: BTreeSet<EntityId>,
    attached: Attached,
}

impl NoteSelection {
    /// The selection of a copy whose source already passed the selection
    /// that made it: it drops nothing, and its attachments ride as they are.
    pub(crate) fn carried() -> Self {
        Self {
            dropped: BTreeSet::new(),
            attached: Attached::AsCarried,
        }
    }

    /// The selection an export of `source` makes, judged in its own read
    /// `txn` against the flags `flagged` it read there: the NOTEs among
    /// `ids` it drops, and each NOTE held only as an attachment that passes
    /// [`Judge::attaches`], with `selector` when the export names one.
    pub(crate) fn judged_in(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        flagged: &BTreeSet<EntityId>,
        source: &LoroDoc,
        ids: &BTreeSet<EntityId>,
        selector: Option<(FederationGrantScope, &SyncSelector)>,
    ) -> Result<Self> {
        let mut dropped = BTreeSet::new();
        let mut attached = BTreeSet::new();
        if is_native(source) {
            let state = codec::read(source)?;
            let tombstones = TombstoneIndex::build(&source.get_map("tombstones"));
            let judge = Judge {
                vault,
                txn,
                tombstones: &tombstones,
                flagged,
                selector,
            };
            for note in ids {
                if state.cores.contains_key(note) && judge.drops(note)? {
                    dropped.insert(*note);
                }
            }
            for note in state.notes() {
                if !state.cores.contains_key(&note) && judge.attaches(&note)? {
                    attached.insert(note);
                }
            }
        }
        Ok(Self {
            dropped,
            attached: Attached::Judged(attached),
        })
    }

    /// Whether the export drops `note`'s core.
    pub(crate) fn drops(&self, note: &EntityId) -> bool {
        self.dropped.contains(note)
    }

    fn attaches(&self, note: &EntityId) -> bool {
        match &self.attached {
            Attached::AsCarried => true,
            Attached::Judged(notes) => notes.contains(note),
        }
    }
}

/// The trusted review rows, read whole in an export's read, each under the
/// key it is filed at.
struct Stored {
    forks: BTreeMap<EntityId, NoteFork>,
    receipts: BTreeMap<EntityId, NoteLandingReceipt>,
    /// Each decided fork's landing receipt, by fork.
    landings: BTreeMap<EntityId, EntityId>,
    bundles: Vec<(EntityId, NoteReviewBundle)>,
}

impl Stored {
    fn read(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Self> {
        let forks = NOTE_FORK.scan(&vault.store, txn)?.into_iter().collect();
        let receipts: BTreeMap<_, _> = NOTE_RECEIPT.scan(&vault.store, txn)?.into_iter().collect();
        let landings = receipts
            .iter()
            .filter(|(key, receipt)| **key == receipt.id)
            .map(|(key, receipt)| (receipt.fork, *key))
            .collect();
        Ok(Self {
            forks,
            receipts,
            landings,
            bundles: NOTE_PROPOSAL_BUNDLE.scan(&vault.store, txn)?,
        })
    }

    /// The decided fork `parent` of `note` a switch made its head, with its
    /// landing receipt, filed where it belongs.
    fn switched(
        &self,
        note: EntityId,
        parent: EntityId,
    ) -> Option<(&NoteFork, &NoteLandingReceipt)> {
        let fork = self
            .forks
            .get(&parent)
            .filter(|fork| fork.fork == parent && fork.note == note && fork.decided)?;
        let receipt = self
            .receipts
            .get(self.landings.get(&parent)?)
            .filter(|receipt| receipt.verdict == NoteVerdict::Switch && receipt.note == note)?;
        Some((fork, receipt))
    }

    /// Adds to `rows` what a whole `bundle` attaches of `note`, a member
    /// NOTE whose core rides another window: its members' forks and
    /// receipts, each undecided member's value, and each decided fork its
    /// members' document family passes through, with its landing. False,
    /// leaving `rows` to be discarded, when `note` may not ride here or a
    /// row it needs is missing.
    fn attach(
        &self,
        judge: &Judge<'_, '_>,
        bundle: &NoteReviewBundle,
        note: EntityId,
        rows: &mut State,
    ) -> Result<bool> {
        if !is_note(judge, note)? || !judge.attaches(&note)? {
            return Ok(false);
        }
        let mut members = Vec::new();
        for waiting in bundle.waiting.iter().filter(|fork| fork.note == note) {
            match self.forks.get(&waiting.fork) {
                Some(row) if row == waiting && !row.decided => members.push(row),
                _ => return Ok(false),
            }
            let key = NoteForkKey(HexId(note), HexId(waiting.fork));
            let Some(raw) = NOTE_PROPOSAL_DOC.get(&judge.vault.store, judge.txn, &key)? else {
                return Ok(false);
            };
            let Ok(text) = crate::note::documents::proposal_text(note, &raw) else {
                return Ok(false);
            };
            rows.docs.insert((note, waiting.fork), text);
        }
        for landed in bundle.landed.iter().filter(|receipt| receipt.note == note) {
            match (self.receipts.get(&landed.id), self.forks.get(&landed.fork)) {
                (Some(receipt), Some(fork))
                    if receipt == landed && fork.fork == landed.fork && fork.decided =>
                {
                    rows.receipts.insert(receipt.id, receipt.clone());
                    members.push(fork);
                }
                _ => return Ok(false),
            }
        }
        for member in members {
            let mut seen = BTreeSet::from([member.fork]);
            let mut parent = member.parent;
            while parent != note {
                let Some((fork, receipt)) = self.switched(note, parent) else {
                    return Ok(false);
                };
                if !seen.insert(parent) {
                    return Ok(false);
                }
                rows.forks.insert(parent, proposal_only(fork.clone()));
                rows.receipts.insert(receipt.id, receipt.clone());
                parent = fork.parent;
            }
            rows.forks
                .insert(member.fork, proposal_only(member.clone()));
        }
        Ok(true)
    }
}

/// Whether `note` is a NOTE this vault holds with its body.
fn is_note(judge: &Judge<'_, '_>, note: EntityId) -> Result<bool> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&judge.vault.store, judge.txn, &note)?;
    Ok(raw.is_some_and(|raw| {
        raw.len() > ENTITY_METADATA_HEADER_LEN
            && EntityMetadataHeader::parse(&raw)
                .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_NOTE)
    }))
}

impl State {
    /// Every NOTE this state holds a row of: its cores and its attachments.
    pub(super) fn notes(&self) -> BTreeSet<EntityId> {
        self.cores
            .keys()
            .copied()
            .chain(self.docs.keys().map(|(note, _)| *note))
            .chain(self.forks.values().map(|fork| fork.note))
            .chain(self.receipts.values().map(|receipt| receipt.note))
            .chain(
                self.bundles
                    .values()
                    .flat_map(|row| bundle_notes(&row.bundle)),
            )
            .collect()
    }

    /// Packs, from the trusted store in `judge`'s read, the review rows of
    /// the NOTEs whose cores this state holds (FIX 8877, 8878): every fork
    /// and receipt of each, each undecided fork's value for each NOTE in
    /// `local`, and each bundle holding a member of one. A bundle rides
    /// whole, its other member NOTEs' rows as attachments, when each of
    /// them may ride here; else it is a projection onto these NOTEs. A
    /// NOTE in `removed` never rides.
    ///
    /// # Errors
    ///
    /// Storage errors, or a row of one of these NOTEs that is not filed at
    /// its own id or whose value does not read.
    pub(super) fn assemble(
        &mut self,
        judge: &Judge<'_, '_>,
        local: &BTreeSet<EntityId>,
        removed: &BTreeSet<EntityId>,
    ) -> Result<()> {
        let anchors: BTreeSet<EntityId> = self.cores.keys().copied().collect();
        if anchors.is_empty() {
            return Ok(());
        }
        let stored = Stored::read(judge.vault, judge.txn)?;
        for (key, fork) in &stored.forks {
            if anchors.contains(&fork.note) {
                if *key != fork.fork {
                    return Err(invalid("NOTE stored fork key"));
                }
                self.forks.insert(fork.fork, proposal_only(fork.clone()));
            }
        }
        for (key, receipt) in &stored.receipts {
            if anchors.contains(&receipt.note) {
                if *key != receipt.id {
                    return Err(invalid("NOTE stored receipt key"));
                }
                self.receipts.insert(receipt.id, receipt.clone());
            }
        }
        for note in local.intersection(&anchors) {
            self.pack_values(judge, &stored, *note)?;
            self.heads.insert(*note, *note);
        }
        for (key, bundle) in &stored.bundles {
            let notes = bundle_notes(bundle);
            if notes.is_disjoint(&anchors) {
                continue;
            }
            if *key != bundle.id {
                return Err(invalid("NOTE stored proposal key"));
            }
            let mut rows = State::default();
            let mut complete = true;
            for note in notes.difference(&anchors) {
                if removed.contains(note) || !stored.attach(judge, bundle, *note, &mut rows)? {
                    complete = false;
                    break;
                }
            }
            let mut carrier = BundleCarrier {
                bundle: NoteReviewBundle {
                    waiting: bundle.waiting.iter().cloned().map(proposal_only).collect(),
                    ..bundle.clone()
                },
                complete: true,
            };
            if complete {
                self.docs.append(&mut rows.docs);
                self.forks.append(&mut rows.forks);
                self.receipts.append(&mut rows.receipts);
            } else {
                carrier.project_onto(&anchors);
            }
            self.bundles.insert(bundle.id, carrier);
        }
        Ok(())
    }

    /// The value of each undecided fork of `note`. The head's document rides
    /// the text plane, never a window, and no decided fork's value rides: a
    /// current or retired head, or a merged or rejected proposal (FIX 8877).
    fn pack_values(
        &mut self,
        judge: &Judge<'_, '_>,
        stored: &Stored,
        note: EntityId,
    ) -> Result<()> {
        let mut key_prefix = Vec::with_capacity(33);
        HexId(note).encode_into(&mut key_prefix);
        key_prefix.push(b':');
        for (NoteForkKey(_, HexId(fork)), raw) in
            NOTE_PROPOSAL_DOC.scan_from(&judge.vault.store, judge.txn, &key_prefix)?
        {
            if stored
                .forks
                .get(&fork)
                .is_some_and(|row| row.fork == fork && row.note == note && !row.decided)
            {
                self.docs.insert(
                    (note, fork),
                    crate::note::documents::proposal_text(note, &raw)?,
                );
            }
        }
        Ok(())
    }

    /// This state as an export of only the NOTEs in `keep` carries it (FIX
    /// 8878): their cores, heads and rows; each bundle with a member among
    /// them, whole while every other member NOTE rides as an attachment
    /// `selection` lets through, else a projection onto `keep`; and only
    /// the attachments a whole bundle still needs.
    pub(super) fn select(&mut self, keep: &BTreeSet<EntityId>, selection: &NoteSelection) {
        let cores: BTreeSet<EntityId> = self.cores.keys().copied().collect();
        let rides = |note: &EntityId| {
            keep.contains(note) || (!cores.contains(note) && selection.attaches(note))
        };
        self.bundles.retain(|_, carrier| {
            let notes = bundle_notes(&carrier.bundle);
            if notes.is_disjoint(keep) {
                return false;
            }
            if !carrier.complete || !notes.iter().all(&rides) {
                carrier.project_onto(keep);
            }
            true
        });
        let left = |note: &EntityId| cores.contains(note) && !keep.contains(note);
        self.cores.retain(|note, _| keep.contains(note));
        self.heads.retain(|note, _| keep.contains(note));
        self.docs.retain(|(note, _), _| !left(note));
        self.forks.retain(|_, row| !left(&row.note));
        self.receipts.retain(|_, row| !left(&row.note));
        self.prune_attachments();
    }

    /// Drops each attached row no carried bundle still needs. A NOTE whose
    /// core this state does not hold keeps only its bundle members' forks,
    /// the decided forks their document family passes through, the
    /// receipts of those forks and its undecided members' values.
    pub(super) fn prune_attachments(&mut self) {
        let bound = self.attached_family();
        let cores = &self.cores;
        self.forks
            .retain(|id, fork| cores.contains_key(&fork.note) || bound.contains(id));
        let forks = &self.forks;
        self.receipts.retain(|_, receipt| {
            cores.contains_key(&receipt.note) || forks.contains_key(&receipt.fork)
        });
        self.docs
            .retain(|(note, fork), _| cores.contains_key(note) || forks.contains_key(fork));
    }

    /// The forks of the NOTEs whose cores this state does not hold that a
    /// carried bundle binds: its members, and each fork their parents lead
    /// through to the NOTE.
    pub(super) fn attached_family(&self) -> BTreeSet<EntityId> {
        let mut bound = BTreeSet::new();
        for carrier in self.bundles.values() {
            let members = carrier.bundle.waiting.iter().map(|fork| fork.fork);
            let landed = carrier.bundle.landed.iter().map(|receipt| receipt.fork);
            for member in members.chain(landed) {
                let Some(fork) = self.forks.get(&member) else {
                    continue;
                };
                if self.cores.contains_key(&fork.note) || !bound.insert(member) {
                    continue;
                }
                let mut parent = fork.parent;
                while parent != fork.note
                    && let Some(up) = self.forks.get(&parent).filter(|up| up.note == fork.note)
                    && bound.insert(parent)
                {
                    parent = up.parent;
                }
            }
        }
        bound
    }

    /// Whether `fork`'s parent is a document of its NOTE's family: the NOTE
    /// itself, or a decided fork of it in `switched`, which a switch made its
    /// head, whose own parent is so in turn, no fork met twice (FIX 8877).
    pub(super) fn binds_family(&self, fork: &NoteFork, switched: &BTreeSet<EntityId>) -> bool {
        let mut seen = BTreeSet::from([fork.fork]);
        let mut parent = fork.parent;
        while parent != fork.note {
            match self.forks.get(&parent) {
                Some(up)
                    if up.note == fork.note
                        && up.decided
                        && switched.contains(&parent)
                        && seen.insert(parent) =>
                {
                    parent = up.parent;
                }
                _ => return false,
            }
        }
        true
    }
}
