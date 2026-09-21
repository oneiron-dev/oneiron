//! Full-window UPDATE locality admission without live document side effects.

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroValue};

use crate::batch::EntityMetadataHeader;
use crate::error::SyncError;
use crate::registry::ENTITY_TYPE_DIAGNOSTIC;
use crate::sync::loro_support::map_for_each_value_bytes;
use crate::{Error, Result};

/// Refuses diagnostic carriers before a full-window update can mutate the
/// live document, materialize rows, persist bytes or fan out to another peer.
///
/// Inspect the incoming operation range, not just final map state: a put
/// followed by a delete still carries the diagnostic body in wire history.
/// A snapshot also carries live state outside its retained operation range.
/// Missing causal dependencies are refused rather than relaying uninspected
/// pending operations; a peer can negotiate the missing prefix and retry.
pub fn validate_window_update_locality(doc: &LoroDoc, update: &[u8]) -> Result<()> {
    let decode_error = |source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "window locality admission",
            source,
        })
    };
    let metadata = LoroDoc::decode_import_blob_meta(update, true).map_err(decode_error)?;
    let candidate = if metadata.mode.is_snapshot() {
        LoroDoc::from_snapshot(update).map_err(decode_error)?
    } else {
        let candidate = doc.fork();
        let imported = candidate.import(update).map_err(decode_error)?;
        if imported.pending.is_some() {
            return Err(Error::InvalidConfig(
                "window update has unresolved dependencies".into(),
            ));
        }
        candidate
    };
    let is_diagnostic = |blob: &[u8]| {
        EntityMetadataHeader::parse(blob)
            .is_some_and(|header| header.entity_type == ENTITY_TYPE_DIAGNOSTIC)
    };
    if metadata.mode.is_snapshot() {
        let mut diagnostic = false;
        map_for_each_value_bytes(&candidate.get_map("entities"), |_, blob| {
            diagnostic |= blob.is_some_and(is_diagnostic);
        });
        if diagnostic {
            return Err(Error::InvalidConfig(
                "diagnostic observations are local-only".into(),
            ));
        }
    }
    let entities = ContainerID::new_root("entities", ContainerType::Map);
    let operations =
        candidate.export_json_updates(&metadata.partial_start_vv, &metadata.partial_end_vv);
    // A fork of a shallow window may no longer retain operations repeated in
    // this input. Refuse an incomplete inspection instead of forwarding bytes
    // whose history is unavailable to the admission check.
    let expected = metadata
        .partial_end_vv
        .iter()
        .try_fold(0_usize, |total, (peer, end)| {
            let start = metadata.partial_start_vv.get(peer).copied().unwrap_or(0);
            let count = usize::try_from(end.checked_sub(start)?).ok()?;
            total.checked_add(count)
        });
    let inspected = operations
        .changes
        .iter()
        .flat_map(|change| &change.ops)
        .try_fold(0_usize, |total, op| total.checked_add(op.content.op_len()));
    if expected.is_none() || expected != inspected {
        return Err(Error::InvalidConfig(
            "window update history is unavailable".into(),
        ));
    }
    for op in operations.changes.into_iter().flat_map(|change| change.ops) {
        if op.container == entities
            && let JsonOpContent::Map(MapOp::Insert {
                value: LoroValue::Binary(blob),
                ..
            }) = op.content
            && is_diagnostic(&blob)
        {
            return Err(Error::InvalidConfig(
                "diagnostic observations are local-only".into(),
            ));
        }
    }
    Ok(())
}
