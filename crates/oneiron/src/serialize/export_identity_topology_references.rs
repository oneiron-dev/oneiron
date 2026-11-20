//! A type-76 merge or split keeps its typed byte slots in an export without
//! secrets (RESTORE-KEEPS-MERGES-AND-SPLITS, REVIEW-9756 rounds 1 and 2).
//!
//! The opaque-byte rule nulls every binary value of a body it cannot type, so
//! a merge's sources and survivor, a split's entity, heads and reassignment
//! items, and the evidence refs left an archive taken without secrets as nil,
//! and the owner's restore could decide none of them again. The
//! identity-topology codec types every byte slot of an inline merge or split
//! it decodes whole: each goes out as its bytes, read for credentials first,
//! as a CLAIM's id slots do. Text slots keep the text rule.
//!
//! Only those rows: the restore decides nothing else, and neither body names
//! another decision, so no kept slot names a decision the archive withholds.
//! Every other type-76 row (an operation manifest or part, an undo, a
//! resolution, a facet) stays under the opaque-byte rule whole, as before. A
//! merge or split keeps its slots only when the body its export restores is
//! an inline merge or split again: the import's round trip then reads the same
//! tree back. One whose credential scan nulls a slot the codec needs stays
//! under the rule whole too.

use rmpv::Value as Mp;

use super::{ExportSecrets, ExportValue};

/// Puts back the typed byte slots of `bytes`, a type-76 body, into
/// `exported`, its tree under the opaque-byte rule, when `bytes` is an inline
/// merge or split. Under [`ExportSecrets::Included`] every slot is kept
/// already.
pub(super) fn export_identity_topology_references(
    bytes: &[u8],
    value: &Mp,
    exported: &mut ExportValue,
    secrets: ExportSecrets,
) {
    if secrets == ExportSecrets::Included
        || !crate::identity_topology::is_inline_merge_or_split_body(bytes)
    {
        return;
    }
    let mut kept = exported.clone();
    keep_typed_bytes(value, &mut kept);
    if restores_inline_merge_or_split(&kept) {
        *exported = kept;
    }
}

/// Whether the body an import restores from `kept` (the bytes
/// [`super::ExportBody::to_bytes`] writes for it) is an inline merge or split
/// the codec decodes whole.
fn restores_inline_merge_or_split(kept: &ExportValue) -> bool {
    let mut bytes = Vec::new();
    kept.to_msgpack()
        .is_ok_and(|tree| rmpv::encode::write_value(&mut bytes, &tree).is_ok())
        && crate::identity_topology::is_inline_merge_or_split_body(&bytes)
}

/// Walks `value` and its export `exported` side by side, keeping each binary
/// value the credential scan passes. A tree the text rule nulled or reshaped
/// is left as it is.
fn keep_typed_bytes(value: &Mp, exported: &mut ExportValue) {
    match (value, exported) {
        (Mp::Binary(bytes), out) => {
            if crate::batch::secret_scan::scan_file_content("", bytes).is_none() {
                *out = ExportValue::EntityReference(bytes.clone());
            }
        }
        (Mp::Array(values), ExportValue::Array(out)) if values.len() == out.len() => {
            for (value, out) in values.iter().zip(out.iter_mut()) {
                keep_typed_bytes(value, out);
            }
        }
        (Mp::Map(entries), ExportValue::Map(out)) if entries.len() == out.len() => {
            for ((_, value), (_, out)) in entries.iter().zip(out.iter_mut()) {
                keep_typed_bytes(value, out);
            }
        }
        _ => {}
    }
}
