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
//! Every other type-76 row (an undo, a resolution, a facet) stays under the
//! opaque-byte rule whole, as before. A merge or split keeps its slots only
//! when the body its export restores is an inline merge or split again: the
//! import's round trip then reads the same tree back. One whose credential
//! scan nulls a slot the codec needs stays under the rule whole too.
//!
//! A merge or split too large for one record in participants but not in
//! bytes is recorded as a manifest and one part, whose payload is the
//! decision's inline body byte for byte
//! (NO-SECRETS-ARCHIVE-MULTIPART-TOPOLOGY-DECISION). Its manifest keeps its
//! payload digest, and its part keeps its root and its payload when the
//! inline rule above, read over that payload as over an inline row, keeps
//! every slot of it as it is: the part then carries no text that rule would
//! null. Either row keeps its slots only when its export restores its own
//! bytes exactly. A decision recorded over two or more parts holds slices no
//! credential scan reads whole, so its parts stay under the rule whole, and
//! the restore names it incomplete, as before. An export carries a part only
//! where it carries the decision the part belongs to (the whole-vault
//! snapshot's entity loop).

use rmpv::Value as Mp;

use super::{ExportSecrets, ExportValue};
use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;

/// Puts back the typed byte slots of `bytes`, a type-76 body, into
/// `exported`, its tree under the opaque-byte rule, when `bytes` is an inline
/// merge or split, or the manifest or part of a merge or split recorded in
/// one part. Under [`ExportSecrets::Included`] every slot is kept already.
pub(super) fn export_identity_topology_references(
    bytes: &[u8],
    value: &Mp,
    exported: &mut ExportValue,
    secrets: ExportSecrets,
) {
    if secrets == ExportSecrets::Included {
        return;
    }
    let inline = crate::identity_topology::is_inline_merge_or_split_body(bytes);
    if !inline
        && !crate::identity_topology::is_one_part_merge_or_split_manifest(bytes)
        && !crate::identity_topology::one_part_merge_or_split_payload(bytes)
            .is_some_and(|payload| inline_rule_keeps_whole(&payload))
    {
        return;
    }
    let mut kept = exported.clone();
    keep_typed_bytes(value, &mut kept);
    let restores = if inline {
        restores_inline_merge_or_split(&kept)
    } else {
        restored_body(&kept).is_some_and(|restored| restored == bytes)
    };
    if restores {
        *exported = kept;
    }
}

/// The body an import restores from `kept`: the bytes
/// [`super::ExportBody::to_bytes`] writes for it.
fn restored_body(kept: &ExportValue) -> Option<Vec<u8>> {
    let tree = kept.to_msgpack().ok()?;
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &tree).ok()?;
    Some(bytes)
}

/// Whether the body an import restores from `kept` is an inline merge or
/// split the codec decodes whole.
fn restores_inline_merge_or_split(kept: &ExportValue) -> bool {
    restored_body(kept)
        .is_some_and(|bytes| crate::identity_topology::is_inline_merge_or_split_body(&bytes))
}

/// Whether the rule an inline merge or split meets in an export without
/// secrets, read over `payload` (a decision's inline body that one record
/// cannot hold) as over an inline row, keeps every slot of it as it is: each
/// text passes the text rule and each byte slot the credential scan.
fn inline_rule_keeps_whole(payload: &[u8]) -> bool {
    let mut cursor = payload;
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return false;
    };
    if !cursor.is_empty() {
        return false;
    }
    let mut kept =
        super::export_value::nulled_value_tree(&value, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT);
    keep_typed_bytes(&value, &mut kept);
    restored_body(&kept).is_some_and(|restored| restored == payload)
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
