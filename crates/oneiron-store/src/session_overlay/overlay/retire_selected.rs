//! Selected-artifact retirement for a natively saved subset (FIX 13687).
//!
//! [`SessionOverlay::retire_saved_artifacts`] retires exactly the overlay rows
//! a successful native base commit just landed for an explicit saved set —
//! staged entities (`saved`) and their document slots (`document_slots`) —
//! without requiring a turn closure. It is the selected-save counterpart of
//! [`SessionOverlay::retire_promoted_closure`], which stays untouched; that
//! helper keeps serving turn closures cut as [`PromotePlan`]s.
//!
//! Contract, mirroring the existing helper:
//!
//! * Called ONLY after the native base commit succeeds. This API never mints
//!   a capability and never lands a base row itself.
//! * Every retired row is removed OUTRIGHT, never tombstoned: a tombstone
//!   would mask the base row the native commit just wrote.
//! * A row drops only when the CURRENT overlay row still byte-matches what
//!   `snapshot` captured. Any later room mutation stays, with its journal.
//! * Journal entries retire by snapshot identity: the exact snapshot seqs
//!   whose replayed subject is in `saved` go; entries published after the
//!   snapshot (new seqs) and entries of unsaved subjects stay.
//! * Per-entity text rows retire only as one snapshot-matched footprint,
//!   so masked native text is not shadowed by its staged source. Shared
//!   accumulator halves, vector/HNSW, PPR, phonetic, queue and attempt rows
//!   and the session short-id ordinal stay in place.
//!
//! Owned footprints come from the SNAPSHOT — its typed journal, its staged
//! entity headers, its staged edge keys, its short-id reverse values, and
//! its staged birth/head/docslot/pin rows — never from caller-supplied keys.
//! `saved` and `document_slots` only NAME the subjects and slots; every key
//! below is derived from actual snapshot content plus the actual key builders
//! and declared prefixes cited beside each family.
//!
//! [`PromotePlan`]: super::super::journal::PromotePlan
use std::collections::BTreeSet;
use std::sync::Arc;

use zeroize::Zeroize;

use oneiron_base::edge::EdgeKind;
use oneiron_contracts::entity_id::{ENTITY_ID_LEN, EntityId};
use oneiron_contracts::error::{Error, Result};
use oneiron_contracts::record_layout::EntityMetadataHeader;

use crate::batch_op::BatchOp;
use crate::index_keys::{encode_edge_key, encode_temporal_key, encode_type_key};
use crate::long_interval::LONG_INTERVAL_THRESHOLD_SECS;

use super::super::journal::replayed_subject;
use super::super::keyspace::{
    KeyspaceState, OverlayKeyspace, OverlayState, OverlayValue, drop_overlay_row,
};
use super::super::snapshot::OverlaySnapshot;
use super::lifecycle::{OverlayLifecycleState, SessionOverlay};
use oneiron_contracts::error::OffRecordError;

// VaultMeta families below spell the exact declared prefixes owned by the
// `oneiron` side-table declarations. Birth/scope prefixes reuse the
// compile-checked [`crate::overlay_bookkeeping`] constants; the NOTE
// head/pin prefixes are copied verbatim from the declarations cited, since
// this lower crate cannot import the upper `oneiron` tables.

/// `NOTE_HEAD` (`note_head:v1:`, `side_table/decls/vault_meta_m_r.rs:105`):
/// a NOTE's current head + seq. Key: id16 (the note), raw.
// NOTE_HEAD binding: `note/documents.rs:41-42` (`SideTable<EntityId, ..>`;
// `EntityId` keys spell raw bytes, `side_table/key.rs`).
const NOTE_HEAD_PREFIX: &[u8] = b"note_head:v1:";
/// `INDEX_SOURCE_TEXT` (`side_table/decls/vault_meta_f_l.rs`), keyed by id16.
const INDEX_SOURCE_TEXT_PREFIX: &[u8] = b"index_source:text:v1:";
/// `NOTE_HEAD_DOC` (`note_head_doc:v1:`, `vault_meta_m_r.rs:108`): one row
/// per head document a NOTE's text plane ever held. Key: id16 (note) + id16
/// (head), raw-concatenated (`note/documents.rs:44-47`).
const NOTE_HEAD_DOC_PREFIX: &[u8] = b"note_head_doc:v1:";
/// `NOTE_PIN_SOURCE` (`note.pin/source/`, `vault_meta_m_r.rs:89-91`): the
/// pin row, keyed by the cited source document. Key: hex32(document) ":"
/// hex32(citing) ":" hex64(hash) (`note/side_keys.rs` `HexHexHash`;
/// staged at `note/document_store.rs:140-142`).
const NOTE_PIN_SOURCE_PREFIX: &[u8] = b"note.pin/source/";
/// `NOTE_PIN_CLAIM` (`note.pin/claim/`, `vault_meta_m_r.rs:77-79`): reverse
/// pin index keyed by the cited claim. Key: hex32(claim) ":" hex32(citing)
/// ":" hex64(hash) (staged at `note/document_store.rs:143-144`).
const NOTE_PIN_CLAIM_PREFIX: &[u8] = b"note.pin/claim/";
/// `NOTE_PIN_CITING` (`note.pin/citing/`, `vault_meta_m_r.rs:74-76`):
/// reverse pin index keyed by the citing document. Key: hex32(citing) ":"
/// hex32(document) ":" hex64(hash) (staged at `note/document_store.rs:145-146`).
const NOTE_PIN_CITING_PREFIX: &[u8] = b"note.pin/citing/";

// SyncState document families (`side_table/decls/sync_state.rs`), over the
// document-row port (`oneiron::ports::document_rows` + `lmdb_document_rows`):
// a slot id spells 32 lower-case hex characters in every key.

/// `DOCUMENT_SNAPSHOT` (`sync_state.rs:77`): one slot's snapshot. Key:
/// `d:e:` + hex32(slot).
const DOCUMENT_SNAPSHOT_PREFIX: &[u8] = b"d:e:";
/// `DOCUMENT_STATE_VECTOR` (`sync_state.rs:454`): one slot's cached state
/// vector. Key: `sv:e:` + hex32(slot).
const DOCUMENT_STATE_VECTOR_PREFIX: &[u8] = b"sv:e:";
/// `DOCUMENT_SHALLOW_SINCE` (`sync_state.rs:452`): one slot's shallow-since
/// version vector. Key: `ssv:e:` + hex32(slot).
const DOCUMENT_SHALLOW_SINCE_PREFIX: &[u8] = b"ssv:e:";
/// `DOCUMENT_UPDATE` (`sync_state.rs:484`): one slot's pending updates.
/// Key: `u:e:` + hex32(slot) + ":" + seq (`{seq:08x}` or `{generation:020}`,
/// `lmdb_document_rows.rs` `UpdateSeq`).
const DOCUMENT_UPDATE_PREFIX: &[u8] = b"u:e:";
/// `SYNC_M_U_SEQ_E` (`sync_state.rs:233-235`): the counter numbering a
/// slot's appended updates. Key: `m:u_seq:e:` + hex32(slot).
const DOCUMENT_UPDATE_SEQ_PREFIX: &[u8] = b"m:u_seq:e:";

/// A slot id as spelled in every document key: 32 lower-case hex.
const SLOT_HEX_LEN: usize = 32;
/// A pin hash as staged: blake3 of the pin value, 64 lower-case hex
/// (`note/document_store.rs:139`).
const PIN_HASH_HEX_LEN: usize = 64;

impl SessionOverlay {
    // Budget failures belong exclusively to preflight, before the base commit.
    // This apply helper deliberately has no budget input or budget-error branch.
    /// Retires a natively saved selected subset from the live overlay
    /// (FIX 13687). Called ONLY after the native base commit for `saved`
    /// and `document_slots` succeeds.
    ///
    /// `snapshot` must be a snapshot of THIS overlay instance: a lease from
    /// another overlay is refused with [`Error::InvariantViolation`]. The
    /// caller captures the snapshot before its base writer runs (under the
    /// same session state lock as its composed view, so both read the same
    /// published state) and passes the same capture here after commit.
    ///
    /// Every drop below is conditional on the current row still
    /// byte-matching the snapshot capture; a row the room restaged after
    /// the snapshot stays, as does any journal entry published after it.
    pub fn retire_saved_artifacts(
        self: &Arc<Self>,
        snapshot: &OverlaySnapshot,
        saved: &BTreeSet<EntityId>,
        document_slots: &BTreeSet<EntityId>,
    ) -> Result<()> {
        if !Arc::ptr_eq(&snapshot.lease.overlay, self) {
            return Err(Error::InvariantViolation(
                "selected retirement snapshot belongs to another session overlay",
            ));
        }
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| Error::InvariantViolation("session overlay lifecycle mutex poisoned"))?;
        if lifecycle.state == OverlayLifecycleState::Gone {
            return Err(Error::OffRecord(
                OffRecordError::OffRecordOverlayLeaseClosed {
                    generation: lifecycle.generation,
                },
            ));
        }
        let mut next = self.state.load_full().as_ref().clone();
        let snap = snapshot.state.as_ref();

        // The snapshot journal seqs owned by saved subjects, with the Put
        // and edge footprints the journaled ops derive. Any other op shape
        // retires journal-only, like the existing helper.
        let mut retired = BTreeSet::new();
        for entry in snapshot.journal_entries() {
            if !replayed_subject(&entry.op).is_some_and(|id| saved.contains(&id)) {
                continue;
            }
            retired.insert(entry.seq);
            match &entry.op {
                BatchOp::Put {
                    id,
                    entity_type,
                    occurred,
                    learned_at,
                    ..
                } => drop_put_footprint(
                    &mut next,
                    snap,
                    id,
                    *entity_type,
                    occurred.start,
                    occurred.end,
                    *learned_at,
                ),
                BatchOp::Edge { src, kind, tgt, .. }
                | BatchOp::PublicEdgeWithCreatedAt { src, kind, tgt, .. }
                | BatchOp::EdgeWithCreatedAt { src, kind, tgt, .. } => {
                    drop_edge_footprint(&mut next, snap, src, *kind, tgt);
                }
                _ => {}
            }
        }

        // Entity rows that may ride no journal Put (a `ManifestDbs`-generic
        // writer stages without journaling): the snapshot's own staged
        // header derives the same index footprint. Short-id, birth, scope
        // and NOTE-head singles are per-subject keys, still snapshot-gated.
        for id in saved {
            drop_snapshot_matched(&mut next, snap, OverlayKeyspace::Entities, id.as_bytes());
            if let Some(header) = snapshot_present(snap, OverlayKeyspace::Entities, id.as_bytes())
                .and_then(EntityMetadataHeader::parse)
            {
                drop_put_footprint(
                    &mut next,
                    snap,
                    id,
                    header.entity_type,
                    header.occurred_start,
                    header.occurred_end,
                    header.learned_at,
                );
            }
            drop_text_footprint(&mut next, snap, id);
            drop_short_id_pair(&mut next, snap, id);
            drop_id_prefixed_row(
                &mut next,
                snap,
                OverlayKeyspace::VaultMeta,
                crate::overlay_bookkeeping::PROVENANCE_ROW_BIRTH_PREFIX,
                id,
            );
            drop_id_prefixed_row(
                &mut next,
                snap,
                OverlayKeyspace::VaultMeta,
                crate::overlay_bookkeeping::SCOPE_RECORD_PREFIX,
                id,
            );
            drop_id_prefixed_row(
                &mut next,
                snap,
                OverlayKeyspace::VaultMeta,
                NOTE_HEAD_PREFIX,
                id,
            );
        }

        // Staged rows whose keys the snapshot owns but no single subject key
        // derives: edges staged without a journal op, born-from index rows,
        // head markers, pin rows and pending document updates.
        drop_staged_edges(&mut next, snap, saved);
        drop_prefixed_rows_where(
            &mut next,
            snap,
            OverlayKeyspace::VaultMeta,
            crate::overlay_bookkeeping::PROVENANCE_BIRTH_BY_TRIGGER_PREFIX,
            ENTITY_ID_LEN,
            saved,
        );
        drop_prefixed_rows_where(
            &mut next,
            snap,
            OverlayKeyspace::VaultMeta,
            NOTE_HEAD_DOC_PREFIX,
            0,
            saved,
        );
        drop_pin_rows(&mut next, snap, NOTE_PIN_SOURCE_PREFIX, false, saved);
        drop_pin_rows(&mut next, snap, NOTE_PIN_CLAIM_PREFIX, false, saved);
        drop_pin_rows(&mut next, snap, NOTE_PIN_CITING_PREFIX, true, saved);
        drop_document_slots(&mut next, snap, document_slots);

        Arc::make_mut(&mut next.journal).retain(|entry| !retired.contains(&entry.seq));
        next.recalculate_bytes();
        self.state.store(Arc::new(next));
        drop(lifecycle);
        // A room stretch's charge follows what its overlay retains (FIX
        // 5991, 10104).
        self.charge_now();
        Ok(())
    }
}

/// A snapshot-staged Present row, for the value-match guard. Tombstones and
/// absent rows never match: only an owned Present capture retires.
fn snapshot_present<'a>(
    state: &'a OverlayState,
    keyspace: OverlayKeyspace,
    key: &[u8],
) -> Option<&'a [u8]> {
    match state.keyspaces[keyspace.slot()].as_ref() {
        KeyspaceState::Single { rows, .. } => match rows.get(key) {
            Some(OverlayValue::Present(value)) => Some(value.as_slice()),
            _ => None,
        },
        KeyspaceState::DupSort { .. } => None,
    }
}

/// Outright-removes `key` of `keyspace` from the live `next` state, but ONLY
/// when the snapshot staged the same Present bytes there: a later room
/// mutation (a new value, a tombstone, a removal) stays.
fn drop_snapshot_matched(
    next: &mut OverlayState,
    snap: &OverlayState,
    keyspace: OverlayKeyspace,
    key: &[u8],
) {
    let Some(want) = snapshot_present(snap, keyspace, key) else {
        return;
    };
    let Some(have) = snapshot_present(next, keyspace, key) else {
        return;
    };
    if want == have {
        drop_overlay_row(next, keyspace, key);
    }
}

/// Retire only this id's captured text revision. A later text rewrite owns
/// its whole footprint even when some of its terms have unchanged postings.
fn drop_text_footprint(next: &mut OverlayState, snap: &OverlayState, id: &EntityId) {
    let key = id.as_bytes().as_slice();
    let mut source_key = INDEX_SOURCE_TEXT_PREFIX.to_vec();
    source_key.extend_from_slice(key);
    let same = |space, key: &[u8]| {
        snapshot_present(snap, space, key)
            .is_some_and(|want| snapshot_present(next, space, key) == Some(want))
    };
    if !same(OverlayKeyspace::TextForward, key) || !same(OverlayKeyspace::VaultMeta, &source_key) {
        return;
    }
    let KeyspaceState::DupSort { rows, .. } =
        snap.keyspaces[OverlayKeyspace::TextPostings.slot()].as_ref()
    else {
        return;
    };
    for (term, captured) in rows {
        let Some(want) = captured.present.get(key) else {
            continue;
        };
        drop_text_posting(next, term, key, want);
    }
    for space in [
        OverlayKeyspace::TextForward,
        OverlayKeyspace::TextDocFieldLengths,
        OverlayKeyspace::TextMeta,
    ] {
        drop_snapshot_matched(next, snap, space, key);
    }
    drop_snapshot_matched(next, snap, OverlayKeyspace::VaultMeta, &source_key);
}

/// Remove an owned present duplicate, never a base duplicate or a mask.
fn drop_text_posting(next: &mut OverlayState, term: &[u8], id: &[u8], want: &[u8]) {
    let KeyspaceState::DupSort { rows, .. } =
        Arc::make_mut(&mut next.keyspaces[OverlayKeyspace::TextPostings.slot()])
    else {
        return;
    };
    let Some(delta) = rows.get_mut(term) else {
        return;
    };
    if delta.present.get(id).map(Vec::as_slice) != Some(want) {
        return;
    }
    if let Some((mut identity, mut value)) = delta.present.remove_entry(id) {
        identity.zeroize();
        value.zeroize();
    }
    if delta.present.is_empty() && delta.deleted.is_empty() && !delta.delete_base {
        if let Some((mut term, delta)) = rows.remove_entry(term) {
            term.zeroize();
            drop(delta);
        }
    }
}

/// The entity + type + temporal footprint of one Put, each row
/// snapshot-gated. Same key builders as the existing helper.
#[allow(clippy::too_many_arguments)]
fn drop_put_footprint(
    next: &mut OverlayState,
    snap: &OverlayState,
    id: &EntityId,
    entity_type: u8,
    occurred_start: u64,
    occurred_end: u64,
    learned_at: u64,
) {
    drop_snapshot_matched(next, snap, OverlayKeyspace::Entities, id.as_bytes());
    drop_snapshot_matched(
        next,
        snap,
        OverlayKeyspace::TypeIndex,
        &encode_type_key(entity_type, id),
    );
    drop_snapshot_matched(
        next,
        snap,
        OverlayKeyspace::TemporalOccurredStart,
        &encode_temporal_key(occurred_start, id),
    );
    if occurred_start != occurred_end {
        drop_snapshot_matched(
            next,
            snap,
            OverlayKeyspace::TemporalOccurredEnd,
            &encode_temporal_key(occurred_end, id),
        );
    }
    drop_snapshot_matched(
        next,
        snap,
        OverlayKeyspace::TemporalLearned,
        &encode_temporal_key(learned_at, id),
    );
    if occurred_end.saturating_sub(occurred_start) > LONG_INTERVAL_THRESHOLD_SECS {
        drop_snapshot_matched(
            next,
            snap,
            OverlayKeyspace::TemporalLongIntervals,
            &encode_temporal_key(occurred_end, id),
        );
    }
}

/// Both directions of one edge, snapshot-gated.
fn drop_edge_footprint(
    next: &mut OverlayState,
    snap: &OverlayState,
    src: &EntityId,
    kind: EdgeKind,
    tgt: &EntityId,
) {
    drop_snapshot_matched(
        next,
        snap,
        OverlayKeyspace::EdgesOut,
        &encode_edge_key(src, kind, tgt),
    );
    drop_snapshot_matched(
        next,
        snap,
        OverlayKeyspace::EdgesIn,
        &encode_edge_key(tgt, kind, src),
    );
}

/// The in-room alias pair, via the reverse row's stored forward key — the
/// same trick as the existing helper, but read from the snapshot capture
/// and value-matched on both halves.
fn drop_short_id_pair(next: &mut OverlayState, snap: &OverlayState, id: &EntityId) {
    if let Some(forward_key) =
        snapshot_present(snap, OverlayKeyspace::ShortIdsReverse, id.as_bytes())
    {
        drop_snapshot_matched(next, snap, OverlayKeyspace::ShortIds, forward_key);
        drop_snapshot_matched(next, snap, OverlayKeyspace::ShortIdsReverse, id.as_bytes());
    }
}

/// One `prefix + id16` VaultMeta row (`ROW_BIRTH`, `SCOPE_RECORD`,
/// `NOTE_HEAD` all key by the raw subject id).
fn drop_id_prefixed_row(
    next: &mut OverlayState,
    snap: &OverlayState,
    keyspace: OverlayKeyspace,
    prefix: &[u8],
    id: &EntityId,
) {
    let mut key = Vec::with_capacity(prefix.len().saturating_add(ENTITY_ID_LEN));
    key.extend_from_slice(prefix);
    key.extend_from_slice(id.as_bytes());
    drop_snapshot_matched(next, snap, keyspace, &key);
}

/// Snapshot-staged edge rows whose EDGE SOURCE is saved, in both
/// directions. `EdgesOut` keys spell `[src16|kind|tgt16]` and `EdgesIn`
/// keys `[tgt16|kind|src16]` (`index_keys::encode_edge_key`), so the source
/// segment is the first 16 bytes out and the last 16 bytes in. Undecodable
/// keys stay: only attributable rows retire.
fn drop_staged_edges(next: &mut OverlayState, snap: &OverlayState, saved: &BTreeSet<EntityId>) {
    for (keyspace, src_at) in [
        (OverlayKeyspace::EdgesOut, 0),
        (OverlayKeyspace::EdgesIn, ENTITY_ID_LEN + 1),
    ] {
        let KeyspaceState::Single { rows, .. } = snap.keyspaces[keyspace.slot()].as_ref() else {
            continue;
        };
        for (key, value) in rows {
            if !matches!(value, OverlayValue::Present(_)) || key.len() != 2 * ENTITY_ID_LEN + 1 {
                continue;
            }
            let Some(segment) = key.get(src_at..src_at + ENTITY_ID_LEN) else {
                continue;
            };
            let Ok(segment) = <[u8; ENTITY_ID_LEN]>::try_from(segment) else {
                continue;
            };
            if EntityId::from_bytes(segment).is_ok_and(|id| saved.contains(&id)) {
                drop_snapshot_matched(next, snap, keyspace, key);
            }
        }
    }
}

/// Snapshot-staged `prefix + id16 + id16` VaultMeta rows whose segment at
/// byte `id_at` (past the prefix) names a saved subject: the born-from
/// index (`BIRTH_BY_TRIGGER`, segment at 16: the born row owns its index
/// row, `store/birth_record/mod.rs:erase_row_birth_in_txn`) and the head
/// markers (`NOTE_HEAD_DOC`, segment at 0: the note owns its markers).
fn drop_prefixed_rows_where(
    next: &mut OverlayState,
    snap: &OverlayState,
    keyspace: OverlayKeyspace,
    prefix: &[u8],
    id_at: usize,
    saved: &BTreeSet<EntityId>,
) {
    let KeyspaceState::Single { rows, .. } = snap.keyspaces[keyspace.slot()].as_ref() else {
        return;
    };
    for (key, value) in rows {
        if !matches!(value, OverlayValue::Present(_)) {
            continue;
        }
        let Some(rest) = key.strip_prefix(prefix) else {
            continue;
        };
        if rest.len() != 2 * ENTITY_ID_LEN {
            continue;
        }
        let Some(segment) = rest.get(id_at..id_at + ENTITY_ID_LEN) else {
            continue;
        };
        let Ok(segment) = <[u8; ENTITY_ID_LEN]>::try_from(segment) else {
            continue;
        };
        if EntityId::from_bytes(segment).is_ok_and(|id| saved.contains(&id)) {
            drop_snapshot_matched(next, snap, keyspace, key);
        }
    }
}

/// Snapshot-staged pin rows of one `note.pin/*` table whose CITING document
/// is saved. The citing segment is the first id for `NOTE_PIN_CITING` and
/// the second for `NOTE_PIN_SOURCE`/`NOTE_PIN_CLAIM` (see the prefix docs).
/// A row the citing note does not own (a pin an unsaved note holds over a
/// saved claim) stays with its citer.
fn drop_pin_rows(
    next: &mut OverlayState,
    snap: &OverlayState,
    prefix: &[u8],
    citing_first: bool,
    saved: &BTreeSet<EntityId>,
) {
    const PIN_KEY_LEN: usize = SLOT_HEX_LEN + 1 + SLOT_HEX_LEN + 1 + PIN_HASH_HEX_LEN;
    let KeyspaceState::Single { rows, .. } =
        snap.keyspaces[OverlayKeyspace::VaultMeta.slot()].as_ref()
    else {
        return;
    };
    for (key, value) in rows {
        if !matches!(value, OverlayValue::Present(_)) {
            continue;
        }
        let Some(rest) = key.strip_prefix(prefix) else {
            continue;
        };
        if rest.len() != PIN_KEY_LEN
            || rest[SLOT_HEX_LEN] != b':'
            || rest[2 * SLOT_HEX_LEN + 1] != b':'
        {
            continue;
        }
        let citing = if citing_first {
            &rest[..SLOT_HEX_LEN]
        } else {
            &rest[SLOT_HEX_LEN + 1..2 * SLOT_HEX_LEN + 1]
        };
        if parse_hex_id(citing).is_some_and(|id| saved.contains(&id)) {
            drop_snapshot_matched(next, snap, OverlayKeyspace::VaultMeta, key);
        }
    }
}

/// One slot's document rows: the snapshot + state vector + shallow-since +
/// update-counter singles, and every staged pending update of the slot.
/// Slots name head ids, which need not be saved entities themselves, so this
/// filters by `document_slots`, not by `saved`.
fn drop_document_slots(
    next: &mut OverlayState,
    snap: &OverlayState,
    document_slots: &BTreeSet<EntityId>,
) {
    let slots: BTreeSet<String> = document_slots.iter().map(EntityId::to_hex).collect();
    for slot in &slots {
        for prefix in [
            DOCUMENT_SNAPSHOT_PREFIX,
            DOCUMENT_STATE_VECTOR_PREFIX,
            DOCUMENT_SHALLOW_SINCE_PREFIX,
            DOCUMENT_UPDATE_SEQ_PREFIX,
        ] {
            let mut key = Vec::with_capacity(prefix.len().saturating_add(SLOT_HEX_LEN));
            key.extend_from_slice(prefix);
            key.extend_from_slice(slot.as_bytes());
            drop_snapshot_matched(next, snap, OverlayKeyspace::SyncState, &key);
        }
    }
    let KeyspaceState::Single { rows, .. } =
        snap.keyspaces[OverlayKeyspace::SyncState.slot()].as_ref()
    else {
        return;
    };
    for (key, value) in rows {
        if !matches!(value, OverlayValue::Present(_)) {
            continue;
        }
        let Some(rest) = key.strip_prefix(DOCUMENT_UPDATE_PREFIX) else {
            continue;
        };
        // `hex32(slot) ":" seq`: 8 hex digits for an appended sequence, 20
        // decimal digits for a commit generation (`UpdateSeq`).
        if rest.len() != SLOT_HEX_LEN + 1 + 8 && rest.len() != SLOT_HEX_LEN + 1 + 20 {
            continue;
        }
        if rest[SLOT_HEX_LEN] != b':' {
            continue;
        }
        if parse_hex_id(&rest[..SLOT_HEX_LEN]).is_some_and(|id| document_slots.contains(&id)) {
            drop_snapshot_matched(next, snap, OverlayKeyspace::SyncState, key);
        }
    }
}

/// A 32 lower-case hex id in its canonical spelling (`DocumentSlot` rule:
/// only the canonical spelling names a slot, `ports/document_rows.rs`).
fn parse_hex_id(hex: &[u8]) -> Option<EntityId> {
    let hex = std::str::from_utf8(hex).ok()?;
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}
