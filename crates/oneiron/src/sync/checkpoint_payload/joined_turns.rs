//! A room turn row in parts, carried joined in a checkpoint (FIX 12153, FIX
//! 12412). A turn row past its whole-row bound rides as a manifest under the
//! turn's key and its parts under their digests (FIX 11790), so its actor
//! lives in the parts' bytes and in the digests that file them. A capture
//! group whose history holds one such row splits it from the joined row: one
//! copy of the turn naming no one under its holder, its actor split out
//! beside it ([`super::JoinedTurn`]), and every slot of its manifest, part
//! keys and parts derived ([`super::DerivedSlot`]). The join re-parts the
//! turn as it opened, with the split the window writes with ([`Transport`]):
//! the all-open turn gives back the captured manifest, keys and parts byte
//! for byte; a turn whose actor did not open gives its erased form's, the
//! parts past its last erased; and a turn none of whose copies opened erases
//! every derived slot. No digest of the captured row outlives it.
//!
//! This slice carries one parted turn per capture group: its every part
//! held, one canonical generic manifest naming them, each digest once, the
//! turn naming only its actor and addressing no one, and past its bound with
//! the actor erased too. Any other parted turn history keeps its window
//! whole, named, as before.

use std::collections::{BTreeMap, BTreeSet};

use loro::LoroValue;
use loro::checkpoint::{Atom, AtomId, OwnerId, Payload};

use super::{DerivedRole, Holder, Placement, ValueSplit};
use crate::error::Result;
use crate::store::checkpoint_payload::rows::bad_part;
use crate::sync::carrier_parts::{is_part_key, join_parts_from, split_parts};
use crate::sync::room_parts::{
    ROOM_TURN_MAX_ROW_BYTES, generic_manifest, generic_manifest_bytes, manifest,
};
use crate::sync::room_turns::ROOM_TURNS_MAP;
use crate::sync::room_turns::checkpoint::{ACTOR, entry_joined};

/// What one capture's history holds of the room turn map's parted rows, in
/// every version a first pass met: each manifest value with its turn key,
/// and each part's bytes by its key.
#[derive(Default)]
pub(super) struct TurnInventory {
    manifests: BTreeSet<(String, Vec<u8>)>,
    parts: BTreeMap<String, Vec<u8>>,
    /// A manifest no turn row is written as, or one part key holding two
    /// values: no turn is carried joined.
    unsupported: bool,
}

impl TurnInventory {
    /// Notes the value `value` under `key` of the root map `root`.
    pub(super) fn note(&mut self, root: &str, key: &str, value: &[u8]) {
        if root != ROOM_TURNS_MAP {
            return;
        }
        if is_part_key(key) {
            match self.parts.get(key) {
                Some(known) => self.unsupported |= known.as_slice() != value,
                None => {
                    self.parts.insert(key.to_owned(), value.to_vec());
                }
            }
        } else if generic_manifest(value).is_some() {
            self.manifests.insert((key.to_owned(), value.to_vec()));
        } else if manifest(value).is_some() {
            self.unsupported = true;
        }
    }
}

/// A turn row re-parted as the window writes a row past its bound: its
/// generic manifest, then each part's key and bytes, in order.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Transport {
    manifest: Vec<u8>,
    keys: Vec<String>,
    parts: Vec<Vec<u8>>,
}

impl Transport {
    /// `row` re-parted in at most `parts` parts, each under a key no other
    /// part has. A row within its whole-row bound would ride whole, so it
    /// refuses here, as does one needing more than `parts` parts.
    pub(super) fn of(row: &[u8], parts: usize) -> Result<Self> {
        if row.len() <= ROOM_TURN_MAX_ROW_BYTES {
            return Err(bad_part());
        }
        let (manifest, pieces) = split_parts(row)?;
        let keys: Vec<String> = pieces.iter().map(|(key, _)| key.clone()).collect();
        let distinct: BTreeSet<&String> = keys.iter().collect();
        if keys.len() > parts || distinct.len() != keys.len() {
            return Err(bad_part());
        }
        Ok(Self {
            manifest: generic_manifest_bytes(&manifest)?,
            keys,
            parts: pieces.into_iter().map(|(_, part)| part.to_vec()).collect(),
        })
    }

    /// What the derived slot `role` holds of this re-part; `None` for a part
    /// past its last, which the join erases.
    fn payload(&self, role: DerivedRole) -> Option<Payload> {
        let binary = |bytes: &[u8]| Payload::Value(LoroValue::Binary(bytes.to_vec().into()));
        match role {
            DerivedRole::Manifest => Some(binary(&self.manifest)),
            DerivedRole::PartKey(place) => self
                .keys
                .get(usize::try_from(place).ok()?)
                .map(|key| Payload::Key(key.clone())),
            DerivedRole::PartValue(place) => self
                .parts
                .get(usize::try_from(place).ok()?)
                .map(|part| binary(part)),
        }
    }
}

/// The atom the derived slot `id`, held by `holders`, puts back of
/// `transport`, its joined turn's re-part as the turn opened. `None`, so
/// erased, when the turn did not open (`transport` is `None`) or the part is
/// past the re-part's last. A capture proves its split and a restore joins
/// with this one rule.
pub(super) fn derived_atom(
    id: AtomId,
    holders: &[OwnerId],
    role: DerivedRole,
    transport: Option<&Transport>,
) -> Option<Atom> {
    Some(Atom {
        id,
        holders: holders.to_vec(),
        payload: transport?.payload(role)?,
    })
}

/// The parted turn a capture group carries joined, proved from its
/// inventory.
pub(super) struct TurnSource {
    /// The turn's id: its row's key.
    pub(super) key: String,
    /// Its manifest, spelled one way in every version the capture holds.
    manifest: Vec<u8>,
    /// Each part's place, by its key.
    places: BTreeMap<String, u32>,
    /// How many parts the row has.
    pub(super) parts: u32,
    /// The turn's one holder, as its whole row's.
    pub(super) holder: Holder,
    /// The turn naming no one, and its actor when it names one.
    pub(super) split: ValueSplit,
    /// The captured transport: the turn re-parted with its actor.
    pub(super) open: Transport,
}

impl TurnSource {
    /// The parted turn `inventory` proves this slice carries joined: one
    /// turn's one manifest in its canonical spelling, every part it lists
    /// held, each listed once, and no part it does not list; its joined row
    /// read as a whole row is, under its one holder, naming only its actor
    /// and addressing no one; and both that row and its erased form
    /// re-parting in its parts' place. `None` for any other history, whose
    /// window stays whole as before.
    pub(super) fn of(inventory: &TurnInventory) -> Option<Self> {
        if inventory.unsupported {
            return None;
        }
        let mut manifests = inventory.manifests.iter();
        let (key, manifest) = manifests.next()?;
        if manifests.next().is_some() {
            return None;
        }
        let listed = generic_manifest(manifest)?;
        let mut places = BTreeMap::new();
        for (place, part) in listed.keys().enumerate() {
            if places.insert(part, u32::try_from(place).ok()?).is_some() {
                return None;
            }
        }
        if inventory
            .parts
            .keys()
            .any(|part| !places.contains_key(part))
        {
            return None;
        }
        let joined = join_parts_from(&listed, |part| inventory.parts.get(part))?;
        let open = Transport::of(&joined, places.len()).ok()?;
        if open.manifest != *manifest {
            return None;
        }
        let placed = entry_joined(key, &joined);
        let (holder, split) = match placed {
            Placement::Split { mut holders, split } if holders.len() == 1 => {
                (holders.pop()?, split)
            }
            Placement::Owned(mut holders) if holders.len() == 1 => (
                holders.pop()?,
                ValueSplit {
                    no_one: joined,
                    actors: Vec::new(),
                },
            ),
            _ => return None,
        };
        if split.actors.len() > 1 || split.actors.iter().any(|(field, _)| field != ACTOR) {
            return None;
        }
        Transport::of(&split.no_one, places.len()).ok()?;
        Some(Self {
            key: key.clone(),
            manifest: manifest.clone(),
            parts: u32::try_from(places.len()).ok()?,
            places,
            holder,
            split,
            open,
        })
    }

    /// What the captured value `value` under `key` of `root` holds of this
    /// turn: its manifest, or a part's bytes. `None` for any other value.
    pub(super) fn value_role(&self, root: &str, key: &str, value: &[u8]) -> Option<DerivedRole> {
        if root != ROOM_TURNS_MAP {
            return None;
        }
        if key == self.key && value == self.manifest.as_slice() {
            return Some(DerivedRole::Manifest);
        }
        self.places
            .get(key)
            .map(|place| DerivedRole::PartValue(*place))
    }

    /// What the withheld key `key` of `root` holds of this turn: a part's
    /// key. `None` for any other key.
    pub(super) fn key_role(&self, root: &str, key: &str) -> Option<DerivedRole> {
        if root != ROOM_TURNS_MAP {
            return None;
        }
        self.places
            .get(key)
            .map(|place| DerivedRole::PartKey(*place))
    }
}
