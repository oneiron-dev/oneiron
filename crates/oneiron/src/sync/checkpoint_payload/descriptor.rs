//! Each window root map a checkpoint reads, declared once (UC-10 PR 6): how
//! its keys read in a skeleton, where its values go, and whether it carries
//! a row in parts. A capture, the restore check and the BASE-window discard
//! projection ask [`root_entry`] where a value goes and [`key_refusal`]
//! whether its key may stand plaintext; a parted map's manifests are bound
//! to their keys over a whole group ([`super::PartedRows`]), by the binding
//! its row names. A map reaches none of them but through its row here, so
//! a map that carries parts declares how its manifests bind.

use super::owners;
use super::rows::named;
use super::{KeyClass, Placement, SyncPayloadOwners, SyncUnclassified};
use crate::sync::carrier_parts::is_part_key;
use crate::sync::ingest::{MESSAGE_WRITER_MAP, PEER_ORIGIN_MAP};
use crate::sync::schema::ASSET_BODY_REFS_MAP;
use crate::sync::selector::HELD_EDIT_CAUSALITY_MAP;
use crate::sync::turn_programs::{TURN_PROGRAM_ARMS_MAP, TURN_PROGRAM_WAKES_MAP};
use crate::sync::withdrawn_cutoffs::WITHDRAWN_CUTOFFS_MAP;
use crate::sync::{
    custody, document_pins, message_docs, note, office_proposals, origin_positions, repo_manifests,
    room_facts, room_turns, row_birth, source_audiences, turn_programs, typed_body_rows,
};

/// A group's held parts, by digest, as a binding joins a manifest from them.
pub(in crate::sync) type PartLookup<'p> = &'p dyn Fn(&str) -> Option<&'p [u8]>;

/// Whether the value under a key of a parted map is the row its key names,
/// its parts joined: `None` for a value that is no manifest, for one whose
/// parts do not all join, and for joined bytes that read as no row of the
/// map.
pub(super) type Binding = fn(&str, &[u8], PartLookup<'_>) -> Option<bool>;

/// How a map's keys read in a skeleton.
#[derive(Clone, Copy)]
enum Keys {
    /// An id in its one canonical spelling.
    Id,
    /// Payload whatever it spells.
    Payload,
    /// The family's own rule.
    Family(fn(&str) -> KeyClass),
    /// The family's own rule, by map.
    FamilyByMap(fn(&str, &str) -> KeyClass),
    /// The family's own rule, which refuses some keys outright.
    Refusing(fn(&str) -> Result<KeyClass, SyncUnclassified>),
}

/// Where a map's values go.
#[derive(Clone, Copy)]
enum Place {
    /// By the value and its key.
    Keyed(fn(&str, &[u8]) -> Placement),
    /// By the value, its key and its map.
    MapKeyed(fn(&str, &str, &[u8]) -> Placement),
    /// By the value and its key, an entity row by its kind.
    Kinded(fn(&str, &[u8], &dyn SyncPayloadOwners) -> Placement),
}

/// Whether a map carries a row past its bound in parts, each filed under
/// its digest (FIX 11790, FIX 10278).
#[derive(Clone, Copy)]
enum Parts {
    None,
    /// A manifest names the row it carries.
    Named,
    /// A manifest names no id of its row: only the joined row shows whose
    /// it is (UC-10 PR 1).
    Bound(Binding),
}

/// One window root map's row (or one codec's maps).
struct WindowMap {
    maps: &'static [&'static str],
    keys: Keys,
    place: Place,
    parts: Parts,
}

impl WindowMap {
    const fn new(maps: &'static [&'static str], keys: Keys, place: Place) -> Self {
        Self {
            maps,
            keys,
            place,
            parts: Parts::None,
        }
    }

    const fn parts(self, parts: Parts) -> Self {
        Self { parts, ..self }
    }

    const fn carries_parts(&self) -> bool {
        !matches!(self.parts, Parts::None)
    }
}

/// Every window root map an adapter here reads, in [`WINDOW_ROOTS`] order.
const MAPS: &[WindowMap] = &[
    WindowMap::new(&["entities"], Keys::Id, Place::Kinded(owners::entity)),
    WindowMap::new(
        &["edges"],
        Keys::Refusing(owners::edge_key),
        Place::Keyed(owners::edge),
    ),
    WindowMap::new(&["tombstones"], Keys::Id, Place::Keyed(owners::tombstone)),
    WindowMap::new(
        &[HELD_EDIT_CAUSALITY_MAP],
        Keys::Refusing(owners::held_edit_causality_key),
        Place::Keyed(owners::held_edit_causality),
    ),
    WindowMap::new(
        &["retained_claim_worlds"],
        Keys::Id,
        Place::Keyed(owners::retained_claim_world),
    ),
    WindowMap::new(
        &[row_birth::ROW_BIRTHS_MAP],
        Keys::Id,
        Place::Keyed(row_birth::checkpoint::entry),
    ),
    WindowMap::new(
        &[origin_positions::ORIGIN_POSITIONS_MAP],
        Keys::Id,
        Place::Keyed(origin_positions::checkpoint_entry),
    ),
    WindowMap::new(
        &[PEER_ORIGIN_MAP],
        Keys::Id,
        Place::Keyed(owners::peer_origin),
    ),
    WindowMap::new(
        &[MESSAGE_WRITER_MAP],
        Keys::Id,
        Place::Keyed(owners::message_writer),
    ),
    WindowMap::new(
        &[WITHDRAWN_CUTOFFS_MAP],
        Keys::Family(owners::withdrawn_cutoff_key),
        Place::Keyed(owners::withdrawn_cutoff),
    ),
    WindowMap::new(
        &note::MAPS,
        Keys::FamilyByMap(note::checkpoint::key_class),
        Place::MapKeyed(note::checkpoint::entry),
    ),
    WindowMap::new(
        &["entity_documents"],
        Keys::Id,
        Place::Keyed(owners::entity_document),
    ),
    WindowMap::new(
        &[custody::CUSTODY_MAP],
        Keys::Family(custody::checkpoint::key_class),
        Place::Keyed(custody::checkpoint::entry),
    ),
    WindowMap::new(
        &[room_turns::ROOM_TURNS_MAP],
        Keys::Id,
        Place::Keyed(room_turns::checkpoint::entry),
    )
    .parts(Parts::Bound(room_turns::checkpoint::bound)),
    // A side row's key may spell a platform handle.
    WindowMap::new(
        &[room_facts::ROOM_FACTS_MAP],
        Keys::Payload,
        Place::Keyed(room_facts::checkpoint::entry),
    )
    .parts(Parts::Bound(room_facts::checkpoint::bound)),
    WindowMap::new(
        &[document_pins::DOCUMENT_PINS_MAP],
        Keys::Family(document_pins::checkpoint::key_class),
        Place::Keyed(document_pins::checkpoint::entry),
    )
    .parts(Parts::Bound(document_pins::checkpoint::bound)),
    WindowMap::new(
        &[message_docs::MESSAGE_DOCS_MAP],
        Keys::Family(message_docs::checkpoint::key_class),
        Place::Keyed(message_docs::checkpoint::entry),
    )
    .parts(Parts::Named),
    WindowMap::new(
        &[office_proposals::OFFICE_PROPOSALS_MAP],
        Keys::Family(office_proposals::checkpoint::key_class),
        Place::Keyed(office_proposals::checkpoint::entry),
    ),
    WindowMap::new(
        &[typed_body_rows::TYPED_BODY_ROWS_MAP],
        Keys::Family(typed_body_rows::checkpoint::key_class),
        Place::Keyed(typed_body_rows::checkpoint::entry),
    )
    .parts(Parts::Named),
    WindowMap::new(
        &[repo_manifests::REPO_MANIFESTS_MAP],
        Keys::Family(repo_manifests::checkpoint::key_class),
        Place::Keyed(repo_manifests::checkpoint::entry),
    )
    .parts(Parts::Bound(repo_manifests::checkpoint::bound)),
    // FIX 5266: an arming rides under its registration, a wake under its
    // turn and registration, and a row of either names its actor.
    WindowMap::new(
        &[TURN_PROGRAM_ARMS_MAP],
        Keys::Id,
        Place::MapKeyed(turn_programs::checkpoint_entry),
    ),
    WindowMap::new(
        &[TURN_PROGRAM_WAKES_MAP],
        Keys::Family(owners::turn_program_wake_key),
        Place::MapKeyed(turn_programs::checkpoint_entry),
    ),
    WindowMap::new(
        &[ASSET_BODY_REFS_MAP],
        Keys::Id,
        Place::Keyed(owners::asset_body_ref),
    ),
    WindowMap::new(
        &[source_audiences::SOURCE_AUDIENCES_MAP],
        Keys::Family(source_audiences::checkpoint::key_class),
        Place::Keyed(source_audiences::checkpoint::entry),
    ),
];

/// Every window root map an adapter here reads: the roots a capture admits.
pub(crate) const WINDOW_ROOTS: [&str; 28] = window_roots(MAPS);

/// Every map of `rows`, in order; exactly `N` of them.
const fn window_roots<const N: usize>(rows: &[WindowMap]) -> [&'static str; N] {
    let mut roots = [""; N];
    let mut at = 0;
    let mut row = 0;
    while row < rows.len() {
        let maps = rows[row].maps;
        let mut map = 0;
        while map < maps.len() {
            roots[at] = maps[map];
            at += 1;
            map += 1;
        }
        row += 1;
    }
    assert!(at == N, "WINDOW_ROOTS names every map of every row");
    roots
}

/// The row of the window root map `root`, and the name it spells the map.
fn window_map(root: &str) -> Option<(&'static str, &'static WindowMap)> {
    MAPS.iter().find_map(|row| {
        let map = row.maps.iter().copied().find(|map| *map == root)?;
        Some((map, row))
    })
}

/// Where the value `value` under `key` in the window root map `root` goes.
/// `owners` places an entity row by its kind.
pub(crate) fn root_entry(
    root: &str,
    key: &str,
    value: &[u8],
    owners: &dyn SyncPayloadOwners,
) -> Placement {
    let Some((_, row)) = window_map(root) else {
        return Placement::unclassified(None, SyncUnclassified::UnknownRoot);
    };
    // FIX 11790: a part goes with the manifest that lists it.
    if row.carries_parts() && is_part_key(key) {
        return Placement::Part;
    }
    match row.place {
        Place::Keyed(place) => place(key, value),
        Place::MapKeyed(place) => place(root, key, value),
        Place::Kinded(place) => place(key, value, owners),
    }
}

/// Whether a key holding a digest of what it carries (a pin's, a part's, a
/// protected input's) may stand plaintext in a skeleton. A digest commits to
/// its value and would outlive the value's erase, so it does not: the key is
/// withheld in an atom of its own under its rightful holders
/// ([`owners::withheld_key`], [`withheld_part_key`],
/// [`owners::withheld_client_key`]; FIX 10278), and only a window whose
/// digest key no holder claims stays under the vault-wide seal. Call, behind
/// this one constant.
const DIGEST_KEYS_ARE_PLAIN: bool = false;

/// A key that spells payload, not an opaque id or a schema name.
const PAYLOAD_KEY: &str = "a window map key that is not an opaque id or a schema name";

/// A key holding a digest of what it carries.
const DIGEST_KEY: &str = "a window map key holding a digest of what it carries";

/// Why `key` of the window root map `root` cannot stand plaintext in a
/// skeleton; `None` for an opaque id or a schema name. Every key a capture
/// meets is asked, a deleted one's too.
pub(super) fn key_refusal(root: &str, key: &str) -> Option<SyncUnclassified> {
    let Some((_, row)) = window_map(root) else {
        return Some(SyncUnclassified::UnknownRoot);
    };
    // A part is filed under its digest (FIX 11790).
    let class = if row.carries_parts() && is_part_key(key) {
        KeyClass::Digest
    } else {
        match row.keys {
            Keys::Id => id_key(key),
            Keys::Payload => KeyClass::Payload,
            Keys::Family(class) => class(key),
            Keys::FamilyByMap(class) => class(root, key),
            Keys::Refusing(class) => match class(key) {
                Ok(class) => class,
                Err(refusal) => return Some(refusal),
            },
        }
    };
    match class {
        KeyClass::Opaque => None,
        KeyClass::Digest if DIGEST_KEYS_ARE_PLAIN => None,
        KeyClass::Digest => Some(SyncUnclassified::ActorSplit(DIGEST_KEY)),
        KeyClass::Payload => Some(SyncUnclassified::ActorSplit(PAYLOAD_KEY)),
    }
}

/// Whether the skeleton withholds `key` of `root` as a part's digest (FIX
/// 10278): a part of a parted window value, filed under its digest. Its key
/// goes with every holder a manifest names the part for
/// ([`super::parts::PartHolders`]), as its value does; the digest itself
/// names no one.
pub(super) fn withheld_part_key(root: &str, key: &str) -> bool {
    is_part_key(key) && window_map(root).is_some_and(|(_, row)| row.carries_parts())
}

/// The map `root` as its row spells it, and the binding of its manifests to
/// their keys: `None` for a map whose manifests name their row, or that
/// carries no parts.
pub(super) fn parted_map(root: &str) -> Option<(&'static str, Binding)> {
    let (map, row) = window_map(root)?;
    match row.parts {
        Parts::Bound(binding) => Some((map, binding)),
        Parts::None | Parts::Named => None,
    }
}

/// A key that is an id in its one canonical spelling.
fn id_key(key: &str) -> KeyClass {
    if named(key).is_some() {
        KeyClass::Opaque
    } else {
        KeyClass::Payload
    }
}
