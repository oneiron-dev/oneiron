//! The `AUTHORITY_OVERLAY` rows of this vault's AUTHORITY_LOG (census
//! L5-22; DEC-0005 #vault:8, "verifies without naming").
//!
//! A row whose op names something a person typed or chose is stored in its
//! scaffold form; its values and the seed of their commitments are its
//! overlay record, sealed under the erasable key of the subject the row
//! names (`store::authority_overlay_custody`) and kept here under the row's
//! entry hash. The append funnel writes the record in the writer that
//! appends the row, before the batch door reads the row back. An in-vault
//! reader opens a sealed row with its record; once the subject's key is
//! retired, or before the record reaches this install, the row reads as
//! erased: its scaffold still verifies, and nothing it made counts
//! ("Missing history never counts as permission").

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use super::*;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::store::authority_overlay_custody::{self as custody, SealedOverlay};

const AUTHORITY_OVERLAY: SideTable<AuthorityEntryHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_OVERLAY);

/// The most bytes one sealed `AUTHORITY_OVERLAY` row holds (census L5-22
/// 1a-ii). A row travels whole beside its body: inline on a tail or range
/// page, or on its body's offset-0 part (`AUTHORITY_ENTRY_PART_MAX`, 2 MiB),
/// so it leaves at least half of that part to the body. Some overlay leaves
/// have no cap of their own (a grant's repository bounds, a work result's
/// reason refs), so the row is bounded here: refused where it is sealed and
/// where it arrives.
pub(crate) const AUTHORITY_OVERLAY_ROW_MAX: usize = 1024 * 1024;

fn overlay_row_too_large() -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(
        "authority overlay row past AUTHORITY_OVERLAY_ROW_MAX",
    ))
}

/// One row's overlay record, prepared before its writer opens: the record's
/// canonical bytes and the subject whose key will seal them.
pub(super) struct PreparedOverlay {
    hash: AuthorityEntryHash,
    subject: EntityId,
    record: Zeroizing<Vec<u8>>,
}

/// Checks `body`, the canonical bytes `entry` encodes to, with the overlay
/// record `entry` carries, and prepares that record for the append funnel.
/// `None` when the entry seals nothing.
///
/// # Errors
/// A body that does not open with its own record, or an op with no overlay
/// subject.
pub(super) fn prepare_overlay(
    entry: &AuthorityLogEntry,
    body: &[u8],
) -> Result<Option<PreparedOverlay>> {
    let record = authority_entry_overlay(entry)?;
    open_authority_log_entry_body(body, record.as_ref())?;
    let Some(record) = record else {
        return Ok(None);
    };
    Ok(Some(PreparedOverlay {
        hash: *blake3::hash(body).as_bytes(),
        subject: authority_overlay_subject(&entry.op)?,
        record: Zeroizing::new(encode_authority_overlay_record(&record)?),
    }))
}

/// Seals `overlay` under its subject's key and stores it in `w`, the writer
/// that appends its row.
///
/// # Errors
/// A sealed row past [`AUTHORITY_OVERLAY_ROW_MAX`]; an archived vault, an
/// erased subject, custody and storage faults.
pub(super) fn put_overlay_in_txn(
    store: &Store,
    w: &mut RwTxn<'_>,
    overlay: &PreparedOverlay,
) -> Result<()> {
    let sealed = custody::seal(store, w, &overlay.subject, &overlay.hash, &overlay.record)?;
    let row = sealed.to_bytes();
    if row.len() > AUTHORITY_OVERLAY_ROW_MAX {
        return Err(overlay_row_too_large());
    }
    AUTHORITY_OVERLAY.put(store, w, &overlay.hash, &row)
}

/// Decodes `body`, a signed AUTHORITY_LOG body of this vault, in `txn`, as
/// the fold takes it: an unsealed row, or a sealed one opened with its
/// `AUTHORITY_OVERLAY` record, whole; a sealed row whose record does not
/// open here as structure only.
///
/// # Errors
/// A body that does not verify; an overlay row that is not a sealed overlay
/// row, or names another subject than the row's op does.
pub(crate) fn decode_vault_authority_fold_row_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    body: &[u8],
) -> Result<FoldRow> {
    decode_authority_body_with_overlays_in_txn(store, txn, body, None)
}

/// [`decode_vault_authority_fold_row_in_txn`] for a body that arrives with the
/// overlay rows its route carried (census L5-22 1a-ii): a sealed body's
/// record is this vault's `AUTHORITY_OVERLAY` row when one is held here,
/// else its carried row, opened under this vault's custody. Nothing is
/// written: the writer that admits the body stages its carried row with
/// [`stage_carried_overlays_in_txn`].
///
/// # Errors
/// As [`decode_vault_authority_fold_row_in_txn`], and a carried row that is not
/// a sealed overlay row.
pub(crate) fn decode_carried_authority_fold_row_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    body: &[u8],
    overlays: &CarriedOverlays,
) -> Result<FoldRow> {
    decode_authority_body_with_overlays_in_txn(store, txn, body, Some(overlays))
}

/// [`decode_carried_authority_fold_row_in_txn`] for a door that needs the whole
/// entry: a sealed body whose record does not open here answers the
/// overlay-unavailable error (`is_authority_overlay_unavailable`).
///
/// # Errors
/// As [`decode_carried_authority_fold_row_in_txn`], and a row whose record
/// does not open here.
pub(crate) fn open_carried_authority_body_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    body: &[u8],
    overlays: &CarriedOverlays,
) -> Result<AuthorityLogEntry> {
    match decode_carried_authority_fold_row_in_txn(store, txn, body, overlays)? {
        FoldRow::Open(entry) => Ok(entry),
        FoldRow::PassThrough(_) => Err(authority_overlay_unavailable()),
    }
}

fn decode_authority_body_with_overlays_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    body: &[u8],
    carried: Option<&CarriedOverlays>,
) -> Result<FoldRow> {
    if !authority_body_is_sealed(body)? {
        return Ok(FoldRow::Open(open_authority_log_entry_body(body, None)?));
    }
    // Each path verifies the body's signatures once: with its record, or
    // over its scaffold when the record does not open here.
    let hash = *blake3::hash(body).as_bytes();
    let row = match AUTHORITY_OVERLAY.get(store, txn, &hash)? {
        Some(row) => Some(row),
        None => carried.and_then(|overlays| overlays.get(&hash).cloned()),
    };
    let opened = match row {
        Some(row) => {
            let sealed = SealedOverlay::from_bytes(&row)?;
            custody::open(store, txn, &hash, &sealed)?.map(|record| (sealed, record))
        }
        None => None,
    };
    let Some((sealed, record)) = opened else {
        return Ok(FoldRow::PassThrough(verify_authority_public_row(body)?));
    };
    let record = decode_authority_overlay_record(&record)?;
    let entry = open_authority_log_entry_body(body, Some(&record))?;
    if authority_overlay_subject(&entry.op)? != sealed.subject {
        return Err(Error::CorruptedIndex("authority overlay subject"));
    }
    Ok(FoldRow::Open(entry))
}

/// [`decode_vault_authority_fold_row_in_txn`] for a door or reader that needs
/// the whole entry: a sealed row whose record does not open here answers
/// the overlay-unavailable error (`is_authority_overlay_unavailable`).
///
/// # Errors
/// As [`decode_vault_authority_fold_row_in_txn`], and a row whose record
/// does not open here.
pub(crate) fn open_vault_authority_body_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    body: &[u8],
) -> Result<AuthorityLogEntry> {
    match decode_vault_authority_fold_row_in_txn(store, txn, body)? {
        FoldRow::Open(entry) => Ok(entry),
        FoldRow::PassThrough(_) => Err(authority_overlay_unavailable()),
    }
}

/// The overlay rows a route carries beside a batch of signed bodies to
/// another machine of this vault (census L5-22 1a-ii), keyed by each body's
/// entry hash: the opaque `AUTHORITY_OVERLAY` bytes, never opened. Plaintext
/// and seeds never travel; a receiver opens a row only under the subject's
/// key that key custody delivered to it.
pub(crate) type CarriedOverlays = BTreeMap<AuthorityEntryHash, Vec<u8>>;

/// The overlay rows this vault holds for the sealed rows among `bodies`,
/// read in `txn`, the read that took the bodies. A sealed row whose overlay
/// is not held here has no entry, and its receiver reads it as unavailable;
/// an unsealed row never has one.
///
/// # Errors
/// A body that is not a signed entry; storage faults.
pub(crate) fn carried_overlays_in_txn<'b>(
    store: &Store,
    txn: &RoTxn<'_>,
    bodies: impl IntoIterator<Item = &'b [u8]>,
) -> Result<CarriedOverlays> {
    let mut overlays = CarriedOverlays::new();
    for body in bodies {
        if !authority_body_is_sealed(body)? {
            continue;
        }
        let hash = *blake3::hash(body).as_bytes();
        if let Some(row) = AUTHORITY_OVERLAY.get(store, txn, &hash)? {
            overlays.insert(hash, row);
        }
    }
    Ok(overlays)
}

/// Stages in `w`, the writer that will admit `bodies`, the carried overlay
/// row of each sealed body among them, before any of them is opened. A row
/// must parse as a sealed overlay row and is kept as it came, never
/// resealed; a row already held here stays; a carried row for no sealed
/// body of the batch is not stored. The open that admits each body then
/// checks that its row opens for that entry and names the entry's subject,
/// and a body with no row reads as unavailable. A body that is not a signed
/// entry stages nothing: its admission refuses it.
///
/// # Errors
/// A carried row past [`AUTHORITY_OVERLAY_ROW_MAX`] or that is not a sealed
/// overlay row; storage faults.
pub(crate) fn stage_carried_overlays_in_txn<'b>(
    store: &Store,
    w: &mut RwTxn<'_>,
    bodies: impl IntoIterator<Item = &'b [u8]>,
    overlays: &CarriedOverlays,
) -> Result<()> {
    if overlays.is_empty() {
        return Ok(());
    }
    for body in bodies {
        if !authority_body_is_sealed(body).unwrap_or(false) {
            continue;
        }
        let hash = *blake3::hash(body).as_bytes();
        let Some(row) = overlays.get(&hash) else {
            continue;
        };
        if row.len() > AUTHORITY_OVERLAY_ROW_MAX {
            return Err(overlay_row_too_large());
        }
        SealedOverlay::from_bytes(row)?;
        if !AUTHORITY_OVERLAY.contains(store, w, &hash)? {
            AUTHORITY_OVERLAY.put(store, w, &hash, row)?;
        }
    }
    Ok(())
}

/// Each sealed row of `subject` this vault holds an overlay row for: its
/// entry hash and its overlay row. No index by subject: a key event reads
/// every overlay row's head, and key events are rare.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
fn subject_overlays_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    subject: &EntityId,
) -> Result<Vec<(AuthorityEntryHash, SealedOverlay)>> {
    let mut rows = Vec::new();
    for (hash, bytes) in AUTHORITY_OVERLAY.scan(store, txn)? {
        let sealed = SealedOverlay::from_bytes(&bytes)?;
        if sealed.subject == *subject {
            rows.push((hash, sealed));
        }
    }
    Ok(rows)
}

/// The projects the rows of `rows` that are stored here and open in `txn`
/// may change, each row as a put of it would touch them; with `index`, each
/// such row's agent-grant member posting is staged too. Both hooks are keyed
/// upserts and sets: running them again for a row changes nothing.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
fn open_row_hooks_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    rows: &[(AuthorityEntryHash, SealedOverlay)],
    index: bool,
) -> Result<BTreeSet<EntityId>> {
    let mut touched = BTreeSet::new();
    for (hash, _) in rows {
        let Some(entry) = stored_authority_row(store, txn, hash)? else {
            continue;
        };
        if index {
            crate::federation::index_agent_grant_member_in_txn(store, txn, &entry, hash)?;
        }
        touched.extend(crate::workspace_roster::projects_touched_by_put(
            store,
            txn,
            (
                authority_log_entity_id_from_hash(hash)?,
                crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
            ),
            None,
            Some(&FoldRow::Open(entry)),
        )?);
    }
    Ok(touched)
}

/// Installs in `txn` the overlay key of `subject` under ref `key_ref` that
/// key custody delivered here (census L5-22 1a-iii; RULING 11:52, "the row
/// opens and the fold counts it from then on, with no reimport and no
/// stall"): the key, its ref row and its ready mark
/// (`store::authority_overlay_custody`), then the openness epoch and the
/// authority generation, so no cached fold answers past it and none resumes
/// from a base folded before it. The rows the key opens get the Open-only
/// hooks their puts left waiting: the agent-grant member posting and the
/// project touches, whose frontiers refresh once. Nothing a put already did
/// runs again: no sequence observation, first-seen time, total, store order
/// or signature.
///
/// Every call moves the epoch and runs the hooks, the same key delivered
/// again included: a delivery an aborted writer left half done (the key
/// file live, no mark) completes on its retry.
///
/// # Errors
/// As `store::authority_overlay_custody::install_key_in_txn`; a stored row
/// of `subject` whose hooks fail.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn install_authority_overlay_key_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    subject: &EntityId,
    key_ref: &[u8; 32],
    secret: &crate::store::CustodySecret,
) -> Result<()> {
    custody::install_key_in_txn(store, txn, subject, key_ref, secret)?;
    note_authority_overlay_openness_change_in_txn(store, txn)?;
    let rows = subject_overlays_in_txn(store, txn, subject)?;
    let touched = open_row_hooks_in_txn(store, txn, &rows, true)?;
    store
        .project_writes
        .refresh_project_frontiers(store, txn, store.privacy_posture, &touched)
}

/// Retires `subject` in `txn` (census L5-22 1a-iii; RULING 11:52, "an erased
/// row stays a pass-through for good"): every overlay key of it this
/// install knows, and the delivered `refs` of keys retired elsewhere, held
/// here or not, are staged to retire and lose their ready marks
/// (`store::authority_overlay_custody`), and the openness epoch and the
/// authority generation move, so from the commit on no row of `subject`
/// opens and nothing it made counts. The projects its open rows touched are
/// gathered before they close and refresh once after. A later install of
/// any key of `subject` is refused. The caller commits, then runs custody's
/// finisher (`Store::finish_erasable_retirements`). Agent-grant member
/// postings stay: their reader counts only rows the fold holds valid.
///
/// # Errors
/// As `store::authority_overlay_custody::retire_subject_keys_in_txn`;
/// storage faults.
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) fn retire_authority_overlay_subject_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    subject: &EntityId,
    refs: &[[u8; 32]],
) -> Result<()> {
    let rows = subject_overlays_in_txn(store, txn, subject)?;
    let touched = open_row_hooks_in_txn(store, txn, &rows, false)?;
    let heads: Vec<SealedOverlay> = rows.into_iter().map(|(_, sealed)| sealed).collect();
    custody::retire_subject_keys_in_txn(store, txn, subject, &heads, refs)?;
    note_authority_overlay_openness_change_in_txn(store, txn)?;
    store
        .project_writes
        .refresh_project_frontiers(store, txn, store.privacy_posture, &touched)
}
