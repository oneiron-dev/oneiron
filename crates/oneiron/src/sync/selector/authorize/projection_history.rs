//! Byte coverage for the new bootstrap supplier's fresh native projection.

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroValue};

use crate::error::SyncError;
use crate::{Error, Result};

/// Checks the actual input snapshot, including its independently encoded
/// root and every retained operation, against a caller-authorized projection.
/// This is not a grant check: `selected` must come from the final member's
/// native selection on the staged writer. No existing sync door uses this
/// fresh-projection schema.
pub(super) fn check_projection_history(update: &[u8], selected: &LoroDoc) -> Result<()> {
    let decode = |source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "shared replica projection",
            source,
        })
    };
    let metadata = LoroDoc::decode_import_blob_meta(update, true).map_err(decode)?;
    if !metadata.mode.is_snapshot() {
        return Err(invalid());
    }
    let original = LoroDoc::from_snapshot(update).map_err(decode)?;
    let permitted = selected.get_deep_value();
    check_state(&original, &permitted)?;
    if let Some(root) = crate::sync::window::original_snapshot_root(update)? {
        check_state(&root, &permitted)?;
    }
    let history = original.export_json_updates_without_peer_compression(
        &metadata.partial_start_vv,
        &metadata.partial_end_vv,
    );
    let expected = metadata
        .partial_end_vv
        .iter()
        .try_fold(0_usize, |total, (peer, end)| {
            let start = metadata.partial_start_vv.get(peer).copied().unwrap_or(0);
            let count = usize::try_from(end.checked_sub(start)?).ok()?;
            total.checked_add(count)
        });
    let inspected = history
        .changes
        .iter()
        .flat_map(|change| &change.ops)
        .try_fold(0_usize, |total, op| total.checked_add(op.content.op_len()));
    if expected.is_none() || expected != inspected {
        return Err(invalid());
    }
    for change in history.changes {
        // A fresh projection commits its selected rows, never a source
        // document's historical commit messages.
        if change.msg.as_ref().is_some_and(|message| !message.is_empty()) {
            return Err(invalid());
        }
        for operation in change.ops {
            let ContainerID::Root {
                name,
                container_type: ContainerType::Map,
            } = operation.container
            else {
                return Err(invalid());
            };
            let JsonOpContent::Map(MapOp::Insert { key, value }) = operation.content else {
                return Err(invalid());
            };
            check_value(&permitted, name.as_str(), &key, &value)?;
        }
    }
    Ok(())
}

fn check_state(source: &LoroDoc, permitted: &LoroValue) -> Result<()> {
    let LoroValue::Map(roots) = source.get_deep_value() else {
        return Err(invalid());
    };
    let LoroValue::Map(allowed_roots) = permitted else {
        return Err(invalid());
    };
    for (root, value) in roots.iter() {
        let LoroValue::Map(entries) = value else {
            return Err(invalid());
        };
        if !matches!(allowed_roots.get(root), Some(LoroValue::Map(_))) {
            return Err(invalid());
        }
        for (key, value) in entries.iter() {
            check_value(permitted, root, key, value)?;
        }
    }
    Ok(())
}

fn check_value(permitted: &LoroValue, root: &str, key: &str, value: &LoroValue) -> Result<()> {
    let LoroValue::Binary(carried) = value else {
        return Err(invalid());
    };
    let LoroValue::Map(roots) = permitted else {
        return Err(invalid());
    };
    let Some(LoroValue::Map(entries)) = roots.get(root) else {
        return Err(invalid());
    };
    match entries.get(key) {
        Some(LoroValue::Binary(allowed)) if carried == allowed => Ok(()),
        _ => Err(invalid()),
    }
}

fn invalid() -> Error {
    Error::InvalidConfig("shared replica input is not its authorized fresh projection".into())
}
