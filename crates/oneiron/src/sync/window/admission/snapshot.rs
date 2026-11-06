//! Fast-snapshot section codec for window admission: header layout, section
//! split, root-as-latest rebuild, canonical-table check. Pure move from the
//! admission body; constants, bodies and order unchanged.

use loro::{ContainerID, LoroDoc};

/// Loro 1.16 lays a fast snapshot out as a header (magic, checksum, mode)
/// and three u32-length-prefixed sections: ops, latest state, root state.
const SNAPSHOT_HEADER: usize = 22;
/// A latest-state section Loro left out: the decode replays from the root.
pub(super) const EMPTY_STATE: &[u8] = b"E";

/// The sections of a fast snapshot, `None` for any other layout, so
/// admission refuses rather than guesses.
pub(super) fn snapshot_sections(snapshot: &[u8]) -> Option<[&[u8]; 3]> {
    let mut rest = snapshot.get(SNAPSHOT_HEADER..)?;
    let mut sections = [&[][..]; 3];
    for section in &mut sections {
        let (len, tail) = rest.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_le_bytes(*len)).ok()?;
        (*section, rest) = tail.split_at_checked(len)?;
    }
    rest.is_empty().then_some(sections)
}

/// The state a fast snapshot encodes at its root, read from that section
/// itself: loaded as the latest state, with no replay, so neither the
/// latest-state section nor a checkout can steer a read away from its bytes
/// (FIX 10165). A full snapshot can keep a root as well as a shallow one.
/// `None` when the bytes are no fast snapshot whose state sections read one
/// way, or the root does not load; `Some(None)` when it encodes no root.
pub(in crate::sync::window) fn encoded_root_state(snapshot: &[u8]) -> Option<Option<LoroDoc>> {
    let sections = snapshot_sections(snapshot)?;
    let [_, latest, root] = sections;
    if !(latest == EMPTY_STATE || state_section_is_canonical(latest))
        || !state_section_is_canonical(root)
    {
        return None;
    }
    if root.is_empty() {
        return Some(None);
    }
    let root = root_as_latest_state(snapshot, sections)?;
    LoroDoc::from_snapshot(&root).ok().map(Some)
}

/// `snapshot` with its root-state section copied over its latest-state
/// section, so a decode loads the encoded root as the doc's state and
/// replays nothing. The checksum is xxh32 over everything from byte 20.
pub(super) fn root_as_latest_state(snapshot: &[u8], [ops, _, root]: [&[u8]; 3]) -> Option<Vec<u8>> {
    let mut rebuilt = snapshot.get(..SNAPSHOT_HEADER)?.to_vec();
    for section in [ops, root, root] {
        rebuilt.extend_from_slice(&u32::try_from(section.len()).ok()?.to_le_bytes());
        rebuilt.extend_from_slice(section);
    }
    let checksum = xxhash_rust::xxh32::xxh32(&rebuilt[20..], u32::from_le_bytes(*b"LORO"));
    rebuilt[16..20].copy_from_slice(&checksum.to_le_bytes());
    Some(rebuilt)
}

/// Whether a state section reads one way through every Loro reader: empty,
/// or a table whose blocks validate and whose keys strictly increase, each
/// the canonical bytes of a container id or the frontiers entry. Loro's own
/// encoder writes only such tables.
pub(super) fn state_section_is_canonical(section: &[u8]) -> bool {
    if section.is_empty() {
        return true;
    }
    let Ok(table) = loro::kv_store::sstable::SsTable::import_all(section.to_vec().into(), true)
    else {
        return false;
    };
    let mut previous: Option<Vec<u8>> = None;
    table.iter().all(|(key, _)| {
        let key = &key[..];
        let canonical =
            key == b"fr" || ContainerID::try_from_bytes(key).is_ok_and(|id| id.to_bytes() == key);
        let increasing = previous.as_deref().is_none_or(|previous| previous < key);
        previous = Some(key.to_vec());
        canonical && increasing
    })
}
