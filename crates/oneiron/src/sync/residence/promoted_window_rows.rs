//! The item rows an opened-item update writes on the thin residence lane, and
//! their admission: judged before the update reaches the home document and
//! again at commit.

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroValue};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::federation::FederationGrantScope;
use crate::sync::selector::SyncSelector;

/// The item rows an opened-item update writes, each with the body it writes,
/// as [`admit_promoted_window_update`] decoded them. A writer that commits
/// the update judges them again in its own transaction
/// ([`admit_promoted_window_rows_in_txn`]), so a grant, pact or selection
/// that narrowed after the admission's read is met at commit.
#[derive(Debug, Clone, Default)]
pub struct PromotedWindowRows(Vec<(EntityId, Vec<u8>)>);

/// Inspect every incoming operation before an opened-item update reaches
/// the observed home document. Only writes to EXISTING selected items with
/// a stable birth scope can run on the thin residence lane. Other operation
/// families use their own admitted doors; they are not smuggled as item edits.
/// Answers the rows it admitted, for a recheck at commit.
pub fn admit_promoted_window_update(
    vault: &Vault,
    source: &LoroDoc,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    proof: &crate::authority::VerifiedSlip,
    update: &[u8],
) -> Result<PromotedWindowRows> {
    let rows = promoted_window_rows(source, update)?;
    let txn = vault.store.env.read_txn()?;
    admit_promoted_window_rows_in_txn(vault, &txn, &rows, scope, selector, proof)?;
    Ok(rows)
}

/// [`admit_promoted_window_update`]'s judgement of each row in `txn`: the
/// per-item write door (`selector::admit_promoted_entity_write_in_txn`) for
/// every row, under the grant, pact and selection `txn` sees.
pub fn admit_promoted_window_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    rows: &PromotedWindowRows,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    proof: &crate::authority::VerifiedSlip,
) -> Result<()> {
    admit_promoted_window_rows_at(
        vault,
        txn,
        rows,
        scope,
        (selector, proof),
        crate::unix_seconds_now(),
    )
}

/// [`admit_promoted_window_rows_in_txn`] with the grant's expiry judged at
/// `now_secs`, one clock reading for every row.
fn admit_promoted_window_rows_at(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    rows: &PromotedWindowRows,
    scope: FederationGrantScope,
    (selector, proof): (&SyncSelector, &crate::authority::VerifiedSlip),
    now_secs: u64,
) -> Result<()> {
    rows.0.iter().try_for_each(|(id, blob)| {
        crate::sync::selector::admit_promoted_entity_write_in_txn(
            vault,
            txn,
            *id,
            blob,
            scope,
            (selector, proof),
            now_secs,
        )
    })
}

/// [`admit_promoted_window_update`], every row judged in one read and with
/// one clock reading for its grant's expiry, then `then` in that same read
/// with that same reading: what the caller keeps of the admission (an own
/// device's burst holds the update under the device's authority as read
/// there: #9226 review round 2).
pub(in crate::sync) fn admit_promoted_window_update_then<T>(
    vault: &Vault,
    source: &LoroDoc,
    (scope, selector, proof): (
        FederationGrantScope,
        &SyncSelector,
        &crate::authority::VerifiedSlip,
    ),
    update: &[u8],
    then: impl FnOnce(&heed::RoTxn<'_>, u64) -> Result<T>,
) -> Result<T> {
    let rows = promoted_window_rows(source, update)?;
    let txn = vault.store.env.read_txn()?;
    let now_secs = crate::unix_seconds_now();
    admit_promoted_window_rows_at(vault, &txn, &rows, scope, (selector, proof), now_secs)?;
    then(&txn, now_secs)
}

/// Whether every row of `rows` may still go to the machine `peer` proved,
/// judged in `txn` (MEMBER-SYNC Astra T2): the promotion's pre-write check
/// read each world's privacy for that machine before the writer opened, so a
/// world whose read setting came to keep it off that machine since refuses
/// the write at commit, as [`crate::claim::ResidenceReadContext::rows_may_leave`]
/// refuses a read.
///
/// # Errors
///
/// A credential, grant or member the residence read refuses in `txn`;
/// storage errors.
pub fn promoted_window_rows_may_leave_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    rows: &PromotedWindowRows,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    proof: &crate::authority::VerifiedSlip,
    peer: crate::machine_destination::PeerMachine,
) -> Result<bool> {
    let ids: Vec<EntityId> = rows.0.iter().map(|(id, _)| *id).collect();
    crate::claim::ResidenceReadContext::load_in(vault, txn, proof, peer, scope, selector)?
        .rows_may_leave(txn, &ids)
}

/// The item rows `update` writes on `source`: every operation an item-body
/// insert into `entities`, or a birth write restating the carrier `source`
/// already holds; anything else is refused.
fn promoted_window_rows(source: &LoroDoc, update: &[u8]) -> Result<PromotedWindowRows> {
    let malformed = || Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied);
    let metadata = LoroDoc::decode_import_blob_meta(update, true).map_err(|_| malformed())?;
    if metadata.mode.is_snapshot() {
        return Err(malformed());
    }
    let candidate = source.fork();
    let status = candidate.import(update).map_err(|_| malformed())?;
    if status.pending.is_some() {
        return Err(malformed());
    }
    let operations =
        candidate.export_json_updates(&metadata.partial_start_vv, &metadata.partial_end_vv);
    if !crate::sync::loro_support::json_covers_blob(&operations, &metadata) {
        return Err(malformed());
    }
    let entities = ContainerID::new_root("entities", ContainerType::Map);
    let births = ContainerID::new_root(crate::sync::row_birth::ROW_BIRTHS_MAP, ContainerType::Map);
    let mut rows = Vec::new();
    for op in operations.changes.into_iter().flat_map(|change| change.ops) {
        let JsonOpContent::Map(MapOp::Insert {
            key,
            value: LoroValue::Binary(blob),
        }) = op.content
        else {
            return Err(malformed());
        };
        // A row is born once, never on this lane: a birth write here may
        // only restate the carrier the home window already holds.
        if op.container == births {
            let held = crate::sync::loro_support::map_get_bytes(
                &source.get_map(crate::sync::row_birth::ROW_BIRTHS_MAP),
                &key,
            );
            if held.as_deref() != Some(&blob[..]) {
                return Err(malformed());
            }
            continue;
        }
        if op.container != entities {
            return Err(malformed());
        }
        let id = EntityId::from_hex(&key).map_err(|_| malformed())?;
        if key != id.to_hex() {
            return Err(malformed());
        }
        rows.push((id, blob.to_vec()));
    }
    Ok(PromotedWindowRows(rows))
}

/// The entities a promoted window's update lands, read from the update's own
/// operations on a fork of `source`: every binary insert into the entities
/// map with a well-formed id. Anything else the update carries (a birth
/// restatement, an engine-translated hold) names no landed row and is not
/// listed. An update that does not decode, arrives as a snapshot, or leaves
/// pending dependencies is refused, as admission refuses it.
pub(crate) fn promoted_window_update_rows(
    source: &LoroDoc,
    update: &[u8],
) -> Result<Vec<EntityId>> {
    let malformed = || Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied);
    let metadata = LoroDoc::decode_import_blob_meta(update, true).map_err(|_| malformed())?;
    if metadata.mode.is_snapshot() {
        return Err(malformed());
    }
    let candidate = source.fork();
    let status = candidate.import(update).map_err(|_| malformed())?;
    if status.pending.is_some() {
        return Err(malformed());
    }
    let operations =
        candidate.export_json_updates(&metadata.partial_start_vv, &metadata.partial_end_vv);
    if !crate::sync::loro_support::json_covers_blob(&operations, &metadata) {
        return Err(malformed());
    }
    let entities = ContainerID::new_root("entities", ContainerType::Map);
    let mut rows = std::collections::BTreeSet::new();
    for op in operations.changes.into_iter().flat_map(|change| change.ops) {
        if op.container != entities {
            continue;
        }
        let JsonOpContent::Map(MapOp::Insert {
            key,
            value: LoroValue::Binary(_),
        }) = op.content
        else {
            continue;
        };
        let id = EntityId::from_hex(&key).map_err(|_| malformed())?;
        if key != id.to_hex() {
            return Err(malformed());
        }
        rows.insert(id);
    }
    Ok(rows.into_iter().collect())
}
