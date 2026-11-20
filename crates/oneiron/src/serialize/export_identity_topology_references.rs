//! A type-76 identity-topology row keeps its typed byte slots in an export
//! without secrets (RESTORE-KEEPS-MERGES-AND-SPLITS, REVIEW-9756 P1-1).
//!
//! The opaque-byte rule nulls every binary value of a body it cannot type, so
//! a merge's sources and survivor, a split's entity, heads and reassignment
//! items, and the evidence refs left an archive taken without secrets as nil,
//! and the owner's restore could decide none of them again. When the
//! identity-topology codec decodes a body whole, its pinned layout types every
//! byte slot: each goes out as its bytes, read for credentials first, as a
//! CLAIM's id slots do. Free bytes stay under the opaque-byte rule: an
//! operation part's slice of a larger record (its text cannot be read whole
//! from one part) and an amended body. Text slots keep the text rule.

use rmpv::Value as Mp;

use super::{ExportSecrets, ExportValue};

/// Puts back the typed byte slots of `bytes`, a type-76 body, into
/// `exported`, its tree under the opaque-byte rule. Under
/// [`ExportSecrets::Included`] every slot is kept already.
pub(super) fn export_identity_topology_references(
    bytes: &[u8],
    value: &Mp,
    exported: &mut ExportValue,
    secrets: ExportSecrets,
) {
    if secrets == ExportSecrets::Included
        || crate::identity_topology::decode_identity_topology_event_body(bytes).is_err()
    {
        return;
    }
    keep_typed_bytes(value, exported, None);
}

/// Walks `value` and its export `exported` side by side; `key` names the map
/// slot the value sits under. A tree the text rule nulled or reshaped is left
/// as it is.
fn keep_typed_bytes(value: &Mp, exported: &mut ExportValue, key: Option<&str>) {
    match (value, exported) {
        (Mp::Binary(bytes), out) => {
            if !key.is_some_and(crate::identity_topology::is_free_byte_slot)
                && crate::batch::secret_scan::scan_file_content("", bytes).is_none()
            {
                *out = ExportValue::EntityReference(bytes.clone());
            }
        }
        (Mp::Array(values), ExportValue::Array(out)) if values.len() == out.len() => {
            for (value, out) in values.iter().zip(out.iter_mut()) {
                keep_typed_bytes(value, out, key);
            }
        }
        (Mp::Map(entries), ExportValue::Map(out)) if entries.len() == out.len() => {
            for ((name, value), (_, out)) in entries.iter().zip(out.iter_mut()) {
                keep_typed_bytes(value, out, name.as_str());
            }
        }
        _ => {}
    }
}
