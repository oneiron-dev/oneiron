//! The mixed sync carriers in a checkpoint (KS-7, FIX 5688 KS7-3a, Engine
//! design (d)): the type boundary between KS7-2's projection and the sync
//! families' own codecs. Copy-only: live documents, the sync wire and
//! every reader stay as they are; only what a checkpoint copies is placed.
//!
//! [`project_checkpoint_sync`] reads the capture's exact rows of the mixed
//! families ([`CapturedSyncRows`]) and places each with its family's codec:
//! whole under each of its rightful holders ([`Holder`]), as one atom per
//! holder ([`SyncAtom`]) that KS7-2 seals and answers with an opaque ordinal
//! ([`AtomRef`]); as structure; with another custody client; or not
//! compartmented, named ([`SyncUnclassified`]), under today's vault-wide
//! seal. Nothing refuses the capture. The [`SyncSkeleton`] it returns holds
//! locators, owners and ordinals, never payload bytes.
//! [`restore_checkpoint_sync`] puts a skeleton's sealed rows back from the
//! atoms that opened ([`OpenedSyncAtoms`]): a row whose holders were all
//! erased or did not open goes, and only it; no missing leaf refuses.
//!
//! KS7-3a places every non-Loro row ([`rows`]). A window's snapshot and
//! updates and a queued window update, placed one row at a time, stay
//! unclassified ([`SyncUnclassified::PendingLoroProjection`]): one row
//! cannot carry the outer skeleton its split needs.
//!
//! KS7-3b splits them a window at a time ([`project_checkpoint_windows`]),
//! over the vendored root-map checkpoint (`loro::checkpoint`). Each value
//! and the operation history around it go apart: the values become atoms,
//! one copy per rightful holder ([`AtomHome`], FIX 9128), each actor a value
//! names split out under the actor's own entity tree (FIX 9127); the history
//! stays in a payload-free outer skeleton ([`LoroCarrier`]).
//! [`restore_checkpoint_windows`] joins each carrier from the copies that
//! opened, erases the values none did and proves the join before any row is
//! put back. A window the vendored capture or the families' codecs cannot
//! split stays under the vault-wide seal, named. Nothing calls either before
//! KS7-5, and nothing reaches them while CHECKPOINT_PAYLOADS_ENABLED is false.
#![allow(
    dead_code,
    reason = "KS7-5 drives these; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

mod frame;
mod operations;
mod owners;
mod parts;
mod restore;
mod rows;

use loro::IdSpan;
use loro::checkpoint::Skeleton;

#[allow(unused_imports, reason = "KS7-5 drives them")]
pub(crate) use self::owners::root_entry;
#[allow(unused_imports, reason = "KS7-5 drives them")]
pub(crate) use self::parts::PartHolders;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::checkpoint_payload::rows::{
    ActorPart, OtherClient, OwnerRef, RoundTripPolicy, RowDb, RowLocator,
};
use crate::sync::carrier_parts::Parts;

/// The mixed sync families a capture hands the projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SyncCarrier {
    /// A window's document snapshot (`d:w:`).
    WindowSnapshot,
    /// A window's pending CRDT update (`u:w:`).
    WindowUpdate,
    /// A thin-residence item's cached blob or document (`ri:b:`, `ri:d:`).
    ResidenceItem,
    /// An unacknowledged local text edit (`qd:e:`).
    PendingEdit,
    /// A pending NOTE-operation request (`qn:e:`).
    PendingNoteOperation,
    /// The sync queue's rows: queued updates, their delete-bearing markers,
    /// quarantine records and counters.
    SyncQueue,
}

impl SyncCarrier {
    /// The database the family's rows sit in.
    pub(crate) const fn db(self) -> RowDb {
        match self {
            Self::SyncQueue => RowDb::SyncQueue,
            _ => RowDb::SyncState,
        }
    }
}

/// One captured row, as stored.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CapturedSyncRow<'a> {
    pub(crate) carrier: SyncCarrier,
    pub(crate) key: &'a [u8],
    pub(crate) value: &'a [u8],
}

/// The capture's exact rows of the mixed sync families, borrowed from its
/// one read view: nothing here reads a live document or opens a txn.
pub(crate) struct CapturedSyncRows<'a> {
    rows: Vec<CapturedSyncRow<'a>>,
}

impl<'a> CapturedSyncRows<'a> {
    pub(crate) fn new(rows: Vec<CapturedSyncRow<'a>>) -> Self {
        Self { rows }
    }
}

/// Why a sync row or value is not compartmented: it stays under the image's
/// vault-wide seal, named on the capture receipt. Never an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyncUnclassified {
    /// A window's Loro row placed alone: only its window's projection
    /// ([`project_checkpoint_windows`]) splits it.
    PendingLoroProjection,
    /// Its key or value does not read with its family's own codec.
    Undecodable,
    /// A window root map no adapter here reads.
    UnknownRoot,
    /// An entity kind the registry does not hold.
    UnknownKind,
    /// No owner the registry places it under.
    NoOwner,
    /// A part no manifest of the capture's history names.
    OrphanPart,
    /// It names an actor, or holds a history, no split here takes out; the
    /// carrier is named.
    ActorSplit(&'static str),
}

/// One rightful holder of a value: the owner its own copy is sealed under,
/// and the owners that copy holds only while they do.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Holder {
    pub(crate) owner: OwnerRef,
    pub(crate) dependencies: Vec<OwnerRef>,
}

impl Holder {
    pub(crate) fn new(owner: OwnerRef, dependencies: Vec<OwnerRef>) -> Self {
        Self {
            owner,
            dependencies,
        }
    }
}

/// Where one sync row or window value goes, as its family's codec places it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Whole, one copy under each holder: shared holders each hold their
    /// own atom, never one guessed owner for all.
    Owned(Vec<Holder>),
    /// A window value naming actors (FIX 9127): each holder's copy holds
    /// its family's no-one form, and each actor is split out beside it.
    Split {
        holders: Vec<Holder>,
        split: ValueSplit,
    },
    /// Ids, markers and metadata with no payload of its own, kept as it is
    /// and dropped with an owner it depends on.
    Structure { dependencies: Vec<OwnerRef> },
    /// Another custody client's, handed to it as it stands.
    Dispatched(OtherClient),
    /// A parted value's manifest (ids, lengths and digests): each holder
    /// holds every part it names ([`PartHolders`]). `joined` names why the
    /// joined value still goes through its own split before a part is
    /// sealed; `None` when its holders take it as it is.
    Manifest {
        holders: Vec<Holder>,
        parts: Parts,
        joined: Option<SyncUnclassified>,
    },
    /// One part of a parted value: its holders are the manifests' that name
    /// it, across the capture's whole history.
    Part,
    /// Not compartmented, named; with its owner when one was found.
    Unclassified {
        owner: Option<OwnerRef>,
        reason: SyncUnclassified,
    },
}

impl Placement {
    pub(crate) fn unclassified(owner: Option<OwnerRef>, reason: SyncUnclassified) -> Self {
        Self::Unclassified { owner, reason }
    }

    /// Whole under `owner` alone.
    pub(crate) fn owned(owner: OwnerRef, dependencies: Vec<OwnerRef>) -> Self {
        Self::Owned(vec![Holder::new(owner, dependencies)])
    }

    /// Under `holders`, as `split` leaves it; whole when it names no one.
    pub(crate) fn split(holders: Vec<Holder>, split: ValueSplit) -> Self {
        if split.actors.is_empty() {
            Self::Owned(holders)
        } else {
            Self::Split { holders, split }
        }
    }
}

/// A window value with the actors it names taken out (FIX 9127): its
/// family's no-one form, and each actor at the family's field for it. A
/// field names its place in the value, never the actor. The family's fill
/// ([`owners::root_fill`]) puts each opened actor back and decides what a
/// field whose actor did not open leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValueSplit {
    pub(crate) no_one: Vec<u8>,
    pub(crate) actors: Vec<(String, EntityId)>,
}

/// What a window map key spells. The vendored capture keeps every key it
/// admits plaintext in the outer skeleton, which outlives an erase, so only
/// opaque ids and schema names may stand there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyClass {
    /// Opaque ids and fixed schema names only.
    Opaque,
    /// A digest of the value it carries.
    Digest,
    /// Anything else: payload.
    Payload,
}

/// Where an entity's own bytes go, by its kind, as KS7-2's registry places
/// that kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KindPlacement {
    /// Its own entity tree's compartment.
    Owner,
    /// Another custody client's: KS-2's ASSET bytes, KS-5's pads, KS-6's
    /// credentials, KS-2B's responses.
    Other(OtherClient),
    /// Not compartmented here.
    Unclassified(SyncUnclassified),
}

/// The owner resolution a projection asks of KS7-2, for what a family's
/// codec cannot answer alone. It reads nothing outside the capture and
/// mints nothing.
pub(crate) trait SyncPayloadOwners {
    /// Where an entity row of the kind tagged `entity_type` goes.
    fn entity_kind(&self, entity_type: u8) -> KindPlacement;

    /// The entity a row kept under `id` belongs to: a masked repo copy's
    /// rows are its source's, so an erased source's copy goes with it (FIX
    /// 7608, KEY STORE = A, FIX 10799). `id` itself unless the capture read
    /// its copy aliases.
    fn owner_entity(&self, id: EntityId) -> EntityId {
        id
    }
}

/// One atom a holder holds: the whole native row, exact, or one copy of a
/// window value in its no-one form, and the owners it holds only while they
/// do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SyncAtom {
    pub(crate) at: RowLocator,
    pub(crate) value: Vec<u8>,
    pub(crate) dependencies: Vec<OwnerRef>,
    /// Each actor the value names, sealed under that actor's own entity
    /// tree and naming this copy (FIX 9127); empty for a whole row.
    pub(crate) actors: Vec<ActorPart>,
}

/// An emitted atom's capture-local ordinal: never an owner, a key or a
/// digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AtomRef(pub(crate) u32);

/// Where one copy of a window value goes (KS7-3b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AtomHome {
    /// Sealed under this owner.
    Owner(OwnerRef),
    /// Kept under the image's outer seal as structure, dropped with an
    /// owner it depends on.
    Structure,
    /// Another custody client's, handed to it as it stands.
    Client(OtherClient),
}

/// How the rows a Loro carrier puts back cut its joined history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LoroSlice {
    /// The whole joined document, as a snapshot: a window's `d:w:` row.
    Snapshot,
    /// An update's exact operation spans, in (peer, counter) order: a
    /// pending `u:w:` row, or a queued `q:` row rewrapped at its sequence.
    Updates(Vec<IdSpan>),
}

/// One captured row a Loro carrier puts back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoroRow {
    pub(crate) at: RowLocator,
    pub(crate) carrier: SyncCarrier,
    pub(crate) slice: LoroSlice,
}

/// One copy of a value: where it rests and the ordinal `emit` gave it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SlotCopy {
    pub(crate) at: RowLocator,
    pub(crate) atom: AtomRef,
}

/// One skeleton slot, by its vendored atom id: a copy per rightful holder,
/// never merged by owner (FIX 9128), and the fields of the actors its value
/// names (FIX 9127).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoroSlot {
    pub(crate) copies: Vec<SlotCopy>,
    pub(crate) holes: Vec<String>,
}

/// One window's split Loro rows (KS7-3b): the payload-free outer skeleton
/// KS7-5 keeps under the image's outer seal. `skeleton` is the vendored
/// one: root names, plaintext keys, versions and the operation history, its
/// values atom ids. `slots` follows its slots in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoroCarrier {
    pub(crate) window: String,
    pub(crate) skeleton: Skeleton,
    pub(crate) rows: Vec<LoroRow>,
    pub(crate) slots: Vec<LoroSlot>,
}

/// What a window projection left of the capture's Loro rows: the carriers
/// it split, and every Loro row it left whole, named. A row in neither is
/// not a Loro row, and the row projection ([`project_checkpoint_sync`])
/// places it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct WindowProjection {
    pub(crate) carriers: Vec<LoroCarrier>,
    pub(crate) unclassified: Vec<SkeletonRow>,
}

/// How a window's split must give its rows back (FIX 6072, Engine R1): the
/// joined bytes are a new encoding of the stored history, proved from the
/// vendored join's report, the rows' slices and the all-open actor fill.
pub(crate) const WINDOW_ROUND_TRIP: RoundTripPolicy = RoundTripPolicy::HistoryEquivalent;

/// What one carrier's join proved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoroVerdict {
    pub(crate) window: String,
    /// The vendored join's report: the joined bytes hold the skeleton's
    /// history with the values that opened.
    pub(crate) equivalent: bool,
    /// Every value and actor opened, so the history is the captured one;
    /// otherwise it is the captured one with what did not open erased.
    pub(crate) lossless: bool,
    pub(crate) policy: RoundTripPolicy,
}

/// How a projection placed one captured row. No variant holds payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SkeletonRow {
    /// Sealed: each atom is a whole copy of the row under one holder.
    Sealed {
        at: RowLocator,
        copies: Vec<AtomRef>,
    },
    /// Kept in the image as it stands.
    Structure {
        at: RowLocator,
        dependencies: Vec<OwnerRef>,
    },
    /// Another custody client's, kept as it stands.
    Dispatched { at: RowLocator, client: OtherClient },
    /// Kept in the image, not compartmented.
    Unclassified {
        at: RowLocator,
        owner: Option<OwnerRef>,
        reason: SyncUnclassified,
    },
}

/// What a projection left of the capture's sync rows: locators, owners and
/// ordinals, never payload bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SyncSkeleton {
    pub(crate) rows: Vec<SkeletonRow>,
}

/// One atom as a restore found it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenedAtom<'a> {
    /// Its bytes, opened.
    Opened(&'a [u8]),
    /// Its holder, or an owner it holds only while, was erased: it goes.
    Erased,
    /// Its holder's compartment did not open on this host: it goes.
    Unavailable,
}

/// The atoms a restore opened (KS7-5). It answers every ordinal, and a
/// missing owner leaf is an answer, never a refusal.
pub(crate) trait OpenedSyncAtoms {
    fn atom(&self, atom: AtomRef) -> OpenedAtom<'_>;

    /// The actor parts of `atom` whose actors opened (FIX 9127). None by
    /// default: a field no opened part fills keeps its family's no-one
    /// form, and no actor is taken from anywhere else.
    fn actor_parts(&self, _atom: AtomRef) -> Vec<&ActorPart> {
        Vec::new()
    }
}

/// What a restore of the sync rows puts back.
#[derive(Debug, Default)]
pub(crate) struct SyncRestoreRows {
    /// Native rows, each checked with its family's codec, for the
    /// restore-only sink.
    pub(crate) rows: Vec<(RowLocator, Vec<u8>)>,
    /// The rows that go: no holder's copy opened. For a window, each copy
    /// of a value that went.
    pub(crate) dropped: Vec<RowLocator>,
    /// The window markers (`fr:w:`, `hfs:w:`) the restored windows need.
    pub(crate) markers: Vec<(RowLocator, Vec<u8>)>,
    /// What each window carrier's join proved.
    pub(crate) verdicts: Vec<LoroVerdict>,
}

/// Places every row of `rows` (KS7-3a): each sealed row's atoms go to
/// `emit`, one per holder, and the skeleton names how each row went. Only
/// `emit`'s own error stops it.
pub(crate) fn project_checkpoint_sync(
    rows: &CapturedSyncRows<'_>,
    owners: &dyn SyncPayloadOwners,
    emit: &mut dyn FnMut(OwnerRef, SyncAtom) -> Result<AtomRef>,
) -> Result<SyncSkeleton> {
    let mut skeleton = SyncSkeleton::default();
    for row in &rows.rows {
        let at = RowLocator::row(row.carrier.db(), row.key.to_vec());
        let placed = match self::rows::place(row, owners) {
            Placement::Owned(holders) => {
                let mut copies = Vec::with_capacity(holders.len());
                for holder in holders {
                    let atom = SyncAtom {
                        at: at.clone(),
                        value: row.value.to_vec(),
                        dependencies: holder.dependencies,
                        actors: Vec::new(),
                    };
                    copies.push(emit(holder.owner, atom)?);
                }
                SkeletonRow::Sealed { at, copies }
            }
            Placement::Structure { dependencies } => SkeletonRow::Structure { at, dependencies },
            Placement::Dispatched(client) => SkeletonRow::Dispatched { at, client },
            Placement::Unclassified { owner, reason } => {
                SkeletonRow::Unclassified { at, owner, reason }
            }
            // A captured row is never a window value's manifest, part or
            // split.
            Placement::Manifest { .. } | Placement::Part | Placement::Split { .. } => {
                SkeletonRow::Unclassified {
                    at,
                    owner: None,
                    reason: SyncUnclassified::Undecodable,
                }
            }
        };
        skeleton.rows.push(placed);
    }
    Ok(skeleton)
}

/// Puts `skeleton`'s sealed rows back from the atoms `opened` holds: a row
/// lands from any holder's copy that opened, checked with its family's
/// codec, and goes when none did. An opened copy that does not read as its
/// row refuses: its compartment opened, so its bytes must be whole.
pub(crate) fn restore_checkpoint_sync(
    skeleton: &SyncSkeleton,
    opened: &dyn OpenedSyncAtoms,
) -> Result<SyncRestoreRows> {
    let mut restored = SyncRestoreRows::default();
    for row in &skeleton.rows {
        let SkeletonRow::Sealed { at, copies } = row else {
            continue;
        };
        let value = copies.iter().find_map(|copy| match opened.atom(*copy) {
            OpenedAtom::Opened(bytes) => Some(bytes),
            OpenedAtom::Erased | OpenedAtom::Unavailable => None,
        });
        match value {
            Some(value) => {
                self::rows::check(at, value)?;
                restored.rows.push((at.clone(), value.to_vec()));
            }
            None => restored.dropped.push(at.clone()),
        }
    }
    Ok(restored)
}

/// Splits the Loro rows of `rows` (KS7-3b) a window at a time: a window's
/// snapshot alone, and its pending and queued updates over that snapshot.
/// Each value's copies go to `emit`, one per rightful holder, only once the
/// window's capture, its codecs' splits and its all-open join all proved;
/// a window that does not stays whole, named, with nothing emitted for it.
/// Only `emit`'s own error stops it.
pub(crate) fn project_checkpoint_windows(
    rows: &CapturedSyncRows<'_>,
    owners: &dyn SyncPayloadOwners,
    emit: &mut dyn FnMut(AtomHome, SyncAtom) -> Result<AtomRef>,
) -> Result<WindowProjection> {
    self::operations::project(&rows.rows, owners, emit)
}

/// Puts each of `carriers`' rows back (KS7-3b), each carrier joined from
/// the copies `opened` holds: a value goes only when none of its copies
/// opened, an actor that did not open leaves its family's no-one form, and
/// the vendored join proves the history before any row is returned. A
/// missing leaf never refuses; an opened copy that does not read does.
pub(crate) fn restore_checkpoint_windows(
    carriers: &[LoroCarrier],
    opened: &dyn OpenedSyncAtoms,
) -> Result<SyncRestoreRows> {
    self::restore::restore(carriers, opened)
}
