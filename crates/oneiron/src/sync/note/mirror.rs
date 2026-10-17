//! Snapshot-consistent NOTE packing and selective-export closure.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::side_table::{self, HexId, Named, Raw, SideKey, SideTable};
use crate::sync::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use crate::sync::types::WindowKey;
use crate::sync::window::Withhold;

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

pub(crate) fn refresh(vault: &Vault, doc: &LoroDoc, window: &WindowKey) -> Result<bool> {
    refresh_for(vault, doc, window, Withhold::Unknown)
}

/// [`refresh`] for the machine an export serves. A proved machine's detached
/// copy packs the NOTEs of the private worlds that machine may read; the
/// stored window and every other door keep off what an unknown destination
/// may not read.
pub(crate) fn refresh_for(
    vault: &Vault,
    doc: &LoroDoc,
    window: &WindowKey,
    withhold: Withhold<'_>,
) -> Result<bool> {
    // NOTE rows and their text-plane carriers live in the shared base month.
    // Every caller (reverse, ordinary export, snapshot export, selector) uses
    // this door, so none may contaminate a world-only document.
    if window.world().is_some() {
        return Ok(false);
    }
    let ids = vault.entities_in_learned_range(
        window.start_timestamp().ok_or(invalid("NOTE window"))?,
        window.end_timestamp().ok_or(invalid("NOTE window"))?,
    )?;
    let mut state = State::default();
    let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
    let txn = vault.store.env.read_txn()?;
    let flagged = match withhold {
        Withhold::Worlds(_) | Withhold::Peer(_) => withhold.worlds_in(vault, &txn)?,
        Withhold::Nothing | Withhold::Unknown => Withhold::Unknown.worlds_in(vault, &txn)?,
    };
    let mut local = BTreeSet::new();
    let mut removed = BTreeSet::new();
    for (key, raw) in rows(doc, "entities")? {
        if EntityMetadataHeader::parse(&raw)
            .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_NOTE)
        {
            let note = id(&key)?;
            if raw.len() > ENTITY_METADATA_HEADER_LEN {
                state.cores.entry(note).or_insert(raw);
            }
            if blocked(vault, &txn, &tombstones, &note)? {
                removed.insert(note);
            }
        }
    }
    for note in ids {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &note)?
        else {
            continue;
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_NOTE)
        {
            continue;
        }
        // A NOTE a device-only world keeps is never packed into a window
        // that does not already carry it.
        if !state.cores.contains_key(&note) && held(vault, &txn, &flagged, &note)? {
            continue;
        }
        local.insert(note);
        if blocked(vault, &txn, &tombstones, &note)? {
            removed.insert(note);
        } else {
            state.cores.insert(note, raw.to_vec());
        }
    }
    // Only trusted local workflows are exported. Untrusted inbox or carried
    // peer rows are never promoted or replayed as local review decisions.
    for note in state.cores.keys() {
        if blocked(vault, &txn, &tombstones, note)? {
            removed.insert(*note);
        }
    }
    state.cores.retain(|note, _| !removed.contains(note));
    for note in local.difference(&removed) {
        // The head's document rides the text plane, never a window.
        let (head, _) = crate::note::documents::head_in(&vault.store, &txn, *note)?;
        let mut key_prefix = Vec::with_capacity(33);
        HexId(*note).encode_into(&mut key_prefix);
        key_prefix.push(b':');
        for (NoteForkKey(_, HexId(fork)), raw) in
            NOTE_PROPOSAL_DOC.scan_from(&vault.store, &txn, &key_prefix)?
        {
            if fork == head {
                continue;
            }
            state.docs.insert(
                (*note, fork),
                crate::note::documents::proposal_text(*note, &raw)?,
            );
        }
        state.heads.insert(*note, *note);
    }
    for (key, fork) in NOTE_FORK.scan(&vault.store, &txn)? {
        if !state.cores.contains_key(&fork.note) {
            continue;
        }
        if key != fork.fork {
            return Err(invalid("NOTE stored fork key"));
        }
        state.forks.insert(fork.fork, fork);
    }
    for (key, receipt) in NOTE_RECEIPT.scan(&vault.store, &txn)? {
        if !state.cores.contains_key(&receipt.note) {
            continue;
        }
        if key != receipt.id {
            return Err(invalid("NOTE stored receipt key"));
        }
        state.receipts.insert(receipt.id, receipt);
    }
    let scope = state.cores.keys().copied().collect();
    for (key, bundle) in NOTE_PROPOSAL_BUNDLE.scan(&vault.store, &txn)? {
        let notes = bundle_notes(&bundle);
        if notes.is_disjoint(&scope) {
            continue;
        }
        if !notes.is_subset(&scope) {
            return Err(invalid("NOTE proposal crosses window or deletion scope"));
        }
        if key != bundle.id {
            return Err(invalid("NOTE stored proposal key"));
        }
        state.bundles.insert(bundle.id, bundle);
    }
    if state.cores.is_empty() && removed.is_empty() && !is_native(doc) {
        return Ok(false);
    }
    state.drop_deleted(&removed);
    state.validate()?;
    // Never commit while the read transaction is held: Observer A opens a writer.
    drop(txn);
    let mut changed = false;
    for note in removed {
        map_delete(&doc.get_map("entities"), &note.to_hex())?;
        changed = true;
    }
    for (note, raw) in &state.cores {
        if map_get_bytes(&doc.get_map("entities"), &note.to_hex()).as_deref()
            != Some(raw.as_slice())
        {
            map_insert_bytes(&doc.get_map("entities"), &note.to_hex(), raw)?;
            changed = true;
        }
    }
    changed |= state.write(doc)?;
    // Once present, old snapshot set-ops can retain rejected/deleted fork text.
    // Every transport export must use the history-free outer window frontier.
    crate::sync::window::require_history_free_window(vault, window)?;
    if changed {
        doc.commit_with(loro::CommitOptions::new().origin(crate::sync::bridge::BRIDGE_ORIGIN));
    }
    Ok(changed)
}

/// The NOTEs among `ids` an export of `source` drops, judged in the export's
/// own read transaction `txn` against the flags it read there: blocked, or
/// kept on this device by a device-only world.
pub(crate) fn dropped_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    flagged: &BTreeSet<EntityId>,
    source: &LoroDoc,
    ids: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut dropped = BTreeSet::new();
    if !is_native(source) {
        return Ok(dropped);
    }
    let state = codec::read(source)?;
    let tombstones = TombstoneIndex::build(&source.get_map("tombstones"));
    for note in ids {
        if state.cores.contains_key(note)
            && (blocked(vault, txn, &tombstones, note)? || held(vault, txn, flagged, note)?)
        {
            dropped.insert(*note);
        }
    }
    Ok(dropped)
}

/// [`copy_selected`] for a door with no snapshot of its own: the NOTEs in
/// `out` are judged in a read transaction of their own.
pub(crate) fn copy_judged(vault: &Vault, source: &LoroDoc, out: &LoroDoc) -> Result<()> {
    let ids = rows(out, "entities")?
        .iter()
        .map(|(key, _)| id(key))
        .collect::<Result<BTreeSet<_>>>()?;
    let txn = vault.store.env.read_txn()?;
    let flagged = crate::settings::device_local_worlds_at(
        vault,
        &txn,
        crate::claim::CallerLocality::OffDevice,
    )?;
    let dropped = dropped_in(vault, &txn, &flagged, source, &ids)?;
    drop(txn);
    copy_selected(source, out, &dropped)
}

/// Copy only complete workflows whose NOTE owners already passed selection:
/// every NOTE in `out` but those the export judged `dropped`, so nothing is
/// withheld after the export's own snapshot. A partial bundle is an error,
/// not permission to leak its shared explainer.
pub(crate) fn copy_selected(
    source: &LoroDoc,
    out: &LoroDoc,
    dropped: &BTreeSet<EntityId>,
) -> Result<()> {
    if !is_native(source) {
        return Ok(());
    }
    let mut state = codec::read(source)?;
    let mut keep = BTreeSet::new();
    for (key, _) in rows(out, "entities")? {
        let note = id(&key)?;
        if state.cores.contains_key(&note) && !dropped.contains(&note) {
            keep.insert(note);
        } else if state.cores.contains_key(&note) {
            map_delete(&out.get_map("entities"), &key)?;
        }
    }
    state.retain(&keep)?;
    state.validate()?;
    state.write(out)?;
    Ok(())
}
