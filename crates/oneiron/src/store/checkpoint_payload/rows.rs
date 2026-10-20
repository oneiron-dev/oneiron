//! The rows a per-owner checkpoint getter hands a capture (KS7-2), and the
//! one sink a restore writes them back through.
//!
//! Each store that keeps an owner's payload exports a getter beside its own
//! private codecs. `capture` reads the capture's one read view and returns
//! each owner's rows ([`OwnerRows`]), the rows with no payload
//! ([`StructureRow`]), the rows another custody client seals
//! ([`DispatchRow`]) and the rows it cannot place ([`Unclassified`]).
//! `bytes_for_owner` frames an owner's rows for its compartment, and
//! `restore_in_txn` checks an opened compartment's rows with the same codecs
//! and writes their exact bytes through [`restore_row_in_txn`]. These types
//! sit below recovery, so no store imports it.
//!
//! An owner's content never names an actor: an actor field is split out as an
//! [`ActorPart`] sealed under the actor's own entity tree, and the content
//! keeps the row's no-one form, or a placeholder where the key itself names
//! the actor. Nothing calls a getter yet: projection (KS7-2b) and capture and
//! restore (KS7-5) do, once [`super::CHECKPOINT_PAYLOADS_ENABLED`] is on.

mod frame;
mod restore;
mod typed;

use std::collections::BTreeMap;

pub(crate) use self::frame::{frame_actor_parts, frame_owner, read_actor_parts};
pub(crate) use self::restore::{
    OpenedOwnerRows, Restored, no_join, restore_parts, restore_parts_keyed, restore_row_in_txn,
};
pub(crate) use self::typed::{
    ACTOR_KEYED_ROW, NOT_SPELLED_BACK, TypedRow, actor_keyed, check_row, join_actors, spells_back,
    split_actors, typed_rows,
};
use super::{OWNER_LEN, Subtype, corrupt};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::side_table::{SideDb, SideTableDecl};

/// A compartment part that does not read as the row it names, or a frame
/// that does not parse: the compartment opened, so it refuses.
pub(crate) fn bad_part() -> Error {
    corrupt()
}

/// The database a captured row sits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum RowDb {
    Entities,
    EdgesOut,
    EdgesIn,
    VaultMeta,
    SyncState,
}

impl RowDb {
    /// The database `decl`'s rows live in.
    pub(crate) fn of(decl: &SideTableDecl) -> Self {
        match decl.db {
            SideDb::VaultMeta => Self::VaultMeta,
            SideDb::SyncState => Self::SyncState,
        }
    }
}

/// Where a part sits: its database, its row's exact full key, and the member
/// path of a fragment (empty for a whole row). An actor-keyed row's
/// placeholder names its table and a slot, never the key that names the
/// actor.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RowLocator {
    pub(crate) db: RowDb,
    pub(crate) key: Vec<u8>,
    pub(crate) path: String,
}

impl RowLocator {
    /// A whole row.
    pub(crate) fn row(db: RowDb, key: Vec<u8>) -> Self {
        Self {
            db,
            key,
            path: String::new(),
        }
    }

    /// Whether this names a row of `decl`.
    pub(crate) fn in_table(&self, decl: &SideTableDecl) -> bool {
        self.db == RowDb::of(decl) && self.key.starts_with(decl.prefix)
    }

    /// This row's fragment at `path`.
    pub(crate) fn fragment(&self, path: String) -> Self {
        Self {
            db: self.db,
            key: self.key.clone(),
            path,
        }
    }
}

/// One compartment's owner: its subtype and canonical 32 owner bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct OwnerRef {
    pub(crate) subtype: Subtype,
    pub(crate) owner32: [u8; OWNER_LEN],
}

impl OwnerRef {
    /// An entity tree: the id, zero-padded.
    pub(crate) fn entity(id: &EntityId) -> Self {
        let mut owner32 = [0; OWNER_LEN];
        owner32[..16].copy_from_slice(id.as_bytes());
        Self {
            subtype: Subtype::EntityTree,
            owner32,
        }
    }

    /// One attachment occurrence: the holding record's id, then the
    /// occurrence's.
    pub(crate) fn occurrence(owner: &EntityId, occurrence: &EntityId) -> Self {
        let mut owner32 = [0; OWNER_LEN];
        owner32[..16].copy_from_slice(owner.as_bytes());
        owner32[16..].copy_from_slice(occurrence.as_bytes());
        Self {
            subtype: Subtype::AttachmentOccurrence,
            owner32,
        }
    }
}

/// One row of an owner's content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RowPart {
    /// The row's exact bytes.
    Exact { at: RowLocator, value: Vec<u8> },
    /// The row in its no-one form: each actor it names is in an actor part
    /// naming `at`, and the getter puts the ones that open back.
    NoActor { at: RowLocator, value: Vec<u8> },
    /// A row whose key or value names an actor: `at` is its placeholder, and
    /// the row's key and value are all in the actor part naming it.
    ActorKeyed { at: RowLocator },
}

impl RowPart {
    pub(crate) fn at(&self) -> &RowLocator {
        match self {
            Self::Exact { at, .. } | Self::NoActor { at, .. } | Self::ActorKeyed { at } => at,
        }
    }
}

/// One actor atom split out of an owner's row, sealed under the actor's own
/// entity tree: its actor, the content part it belongs to, the field it
/// fills and the bytes that fill it (the actor's 16 id bytes, or an
/// actor-keyed row's framed key and value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActorPart {
    pub(crate) actor_entity: EntityId,
    pub(crate) content_locator: RowLocator,
    pub(crate) field: String,
    pub(crate) bytes: Vec<u8>,
}

/// A part that holds only while another owner does: a citation's citer, a
/// pin's cited claim. When the checkpoint holds `on`'s compartment and it
/// does not open, the part is dropped; an owner the checkpoint holds no
/// compartment for drops nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Dependency {
    pub(crate) at: RowLocator,
    pub(crate) on: OwnerRef,
}

/// One owner's rows, as one getter read them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnerRows {
    pub(crate) subtype: Subtype,
    pub(crate) owner32: [u8; OWNER_LEN],
    /// The occurrence id of an attachment occurrence's rows.
    pub(crate) occurrence_hint: Option<[u8; 16]>,
    pub(crate) rows: Vec<RowPart>,
    pub(crate) actor_parts: Vec<ActorPart>,
    pub(crate) dependencies: Vec<Dependency>,
    /// The key each part whose locator does not name its row rests at in
    /// the image, by that locator: a NOTE title reservation's, which its
    /// join spells back from its author's part (FIX 6075). In memory only,
    /// for the projection's claim on the row; never framed.
    pub(crate) image_keys: BTreeMap<RowLocator, Vec<u8>>,
}

impl OwnerRows {
    fn new(owner: OwnerRef) -> Self {
        Self {
            subtype: owner.subtype,
            owner32: owner.owner32,
            occurrence_hint: None,
            rows: Vec::new(),
            actor_parts: Vec::new(),
            dependencies: Vec::new(),
            image_keys: BTreeMap::new(),
        }
    }

    pub(crate) fn owner(&self) -> OwnerRef {
        OwnerRef {
            subtype: self.subtype,
            owner32: self.owner32,
        }
    }

    fn absorb(&mut self, other: Self) {
        self.occurrence_hint = self.occurrence_hint.or(other.occurrence_hint);
        self.rows.extend(other.rows);
        self.actor_parts.extend(other.actor_parts);
        self.dependencies.extend(other.dependencies);
        self.image_keys.extend(other.image_keys);
    }
}

/// A row with no payload of its own, kept under the checkpoint's outer seal
/// and dropped with an owner it depends on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StructureRow {
    pub(crate) at: RowLocator,
    pub(crate) value: Vec<u8>,
    pub(crate) dependencies: Vec<OwnerRef>,
}

/// A custody client other than KS-7, whose own compartments seal a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OtherClient {
    /// KS-2: ASSET bytes, inline and file.
    Body,
    /// KS-2B: a response a row holds.
    Response,
    /// KS-5: a world's key pad.
    WorldPad,
    /// KS-6: a credential value.
    Credential,
}

/// A row another custody client seals, handed over as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DispatchRow {
    pub(crate) client: OtherClient,
    pub(crate) at: RowLocator,
    pub(crate) value: Vec<u8>,
}

/// Why a row is not compartmented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unresolved {
    /// Its key or value does not read with its table's own codec.
    Undecodable,
    /// No owner it names could be found.
    NoOwner,
    /// Its entity kind is not one the registry holds.
    UnknownKind,
    /// It holds fields several owners share, which no one owner can hold.
    SharedOwners,
    /// It names actors no split takes out losslessly; the carrier is named.
    ActorSplit(&'static str),
}

/// A row a getter cannot compartment: it stays under today's vault-wide
/// seal, and the capture receipt names it ("not compartmented: erase can't
/// reach it in this checkpoint").
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Unclassified {
    pub(crate) at: RowLocator,
    /// Its owner, when one was found.
    pub(crate) owner: Option<OwnerRef>,
    pub(crate) reason: Unresolved,
}

/// What one or more getters read: every owner's rows, and every row that is
/// not an owner's.
#[derive(Debug, Default)]
pub(crate) struct Captured {
    owners: BTreeMap<OwnerRef, OwnerRows>,
    pub(crate) structure: Vec<StructureRow>,
    pub(crate) dispatched: Vec<DispatchRow>,
    pub(crate) unclassified: Vec<Unclassified>,
}

impl Captured {
    /// `owner`'s rows, opened empty on first use.
    pub(crate) fn owner(&mut self, owner: OwnerRef) -> &mut OwnerRows {
        self.owners
            .entry(owner)
            .or_insert_with(|| OwnerRows::new(owner))
    }

    pub(crate) fn exact(&mut self, owner: OwnerRef, at: RowLocator, value: Vec<u8>) {
        self.owner(owner).rows.push(RowPart::Exact { at, value });
    }

    /// Records that `owner`'s part at `at` holds only while `on` does.
    pub(crate) fn depends(&mut self, owner: OwnerRef, at: &RowLocator, on: OwnerRef) {
        if on != owner {
            self.owner(owner)
                .dependencies
                .push(Dependency { at: at.clone(), on });
        }
    }

    pub(crate) fn unclassified(
        &mut self,
        at: RowLocator,
        owner: Option<OwnerRef>,
        reason: Unresolved,
    ) {
        self.unclassified.push(Unclassified { at, owner, reason });
    }

    pub(crate) fn structure(
        &mut self,
        at: RowLocator,
        value: Vec<u8>,
        dependencies: Vec<OwnerRef>,
    ) {
        self.structure.push(StructureRow {
            at,
            value,
            dependencies,
        });
    }

    pub(crate) fn dispatch(&mut self, client: OtherClient, at: RowLocator, value: Vec<u8>) {
        self.dispatched.push(DispatchRow { client, at, value });
    }

    /// Folds `other` in: an owner both read holds both reads' rows.
    pub(crate) fn merge(&mut self, other: Self) {
        for (owner, rows) in other.owners {
            match self.owners.entry(owner) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(rows);
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    slot.get_mut().absorb(rows);
                }
            }
        }
        self.structure.extend(other.structure);
        self.dispatched.extend(other.dispatched);
        self.unclassified.extend(other.unclassified);
    }

    pub(crate) fn owners(&self) -> impl Iterator<Item = &OwnerRows> {
        self.owners.values()
    }
}
