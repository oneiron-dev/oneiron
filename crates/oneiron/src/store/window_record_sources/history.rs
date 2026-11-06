//! Remove only transport facts retaining operations the owner's cut removed.

use loro::VersionVector;

use super::{SOURCES, decode_source_from_row};
use crate::entity_doc::RecordDocumentHistoryCut;
use crate::error::Result;

pub(crate) fn remove_history_in_txn(cut: RecordDocumentHistoryCut<'_, '_>) -> Result<()> {
    let (store, txn, entity, incarnation, before, after) = cut.into_parts();
    let rows = SOURCES
        .iter_raw_from(store, txn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, bytes) in rows {
        let mut full_key = SOURCES.decl().prefix.to_vec();
        full_key.extend_from_slice(&key);
        let Some((owner, _, _, head)) = decode_source_from_row(&full_key, &bytes) else {
            continue;
        };
        if owner != entity || head.native().incarnation != incarnation {
            continue;
        }
        // The canonical head decoder already checked both vectors. An empty
        // shallow vector is the full-history floor, not a missing cut receipt.
        let Ok(version) = VersionVector::decode(&head.native().version) else {
            continue;
        };
        let floor = if head.native().shallow.is_empty() {
            VersionVector::default()
        } else {
            let Ok(floor) = VersionVector::decode(&head.native().shallow) else {
                continue;
            };
            floor
        };
        let intersects = after.iter().any(|(peer, end)| {
            let start = before.get(peer).copied().unwrap_or(0).max(0);
            let retained_start = floor.get(peer).copied().unwrap_or(0).max(0);
            let retained_end = version.get(peer).copied().unwrap_or(0).max(0);
            start.max(retained_start) < (*end).max(0).min(retained_end)
        });
        if intersects {
            // Key spelling was checked by decode_source_from_row.
            let key = String::from_utf8(key).expect("validated record source key");
            SOURCES.delete(store, txn, &key)?;
        }
    }
    Ok(())
}
