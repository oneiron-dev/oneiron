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
//! KS7-3a places every non-Loro row ([`rows`]) and leaves a window's
//! snapshot and updates and a queued window update unclassified for
//! KS7-3b's Loro root and operation projection
//! ([`SyncUnclassified::PendingLoroProjection`]). The typed owner dispatch of
//! each window root map ([`root_entry`]) and the historical part-holder
//! index ([`PartHolders`]) are what that projection drives. Nothing calls
//! this before KS7-5, and nothing reaches it while CHECKPOINT_PAYLOADS_ENABLED
//! is false.
#![allow(
    dead_code,
    reason = "KS7-3b and KS7-5 drive these; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

mod owners;
mod parts;
mod rows;

#[allow(unused_imports, reason = "KS7-3b's Loro projection drives them")]
pub(crate) use self::owners::root_entry;
#[allow(unused_imports, reason = "KS7-3b's Loro projection drives them")]
pub(crate) use self::parts::PartHolders;
use crate::error::Result;
use crate::store::checkpoint_payload::rows::{OtherClient, OwnerRef, RowDb, RowLocator};
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
    /// A window's Loro history, which KS7-3b's root and operation
    /// projection splits.
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
}

/// One atom a holder holds: the whole native row, exact, and the owners it
/// holds only while they do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SyncAtom {
    pub(crate) at: RowLocator,
    pub(crate) value: Vec<u8>,
    pub(crate) dependencies: Vec<OwnerRef>,
}

/// An emitted atom's capture-local ordinal: never an owner, a key or a
/// digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AtomRef(pub(crate) u32);

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
}

/// What a restore of the sync rows puts back.
#[derive(Debug, Default)]
pub(crate) struct SyncRestoreRows {
    /// Native rows, each checked with its family's codec, for the
    /// restore-only sink.
    pub(crate) rows: Vec<(RowLocator, Vec<u8>)>,
    /// The rows that go: no holder's copy opened.
    pub(crate) dropped: Vec<RowLocator>,
    /// The window markers (`fr:w:`, `hfs:w:`) the restored rows need: none
    /// until KS7-3b puts a window back.
    pub(crate) markers: Vec<(RowLocator, Vec<u8>)>,
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
            // A captured row is never a window value's manifest or part.
            Placement::Manifest { .. } | Placement::Part => SkeletonRow::Unclassified {
                at,
                owner: None,
                reason: SyncUnclassified::Undecodable,
            },
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
