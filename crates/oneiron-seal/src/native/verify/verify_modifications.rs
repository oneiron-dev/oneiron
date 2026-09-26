//! Conservative, shared pre-sign and post-sign incremental-revision analysis.
//!
//! Only the native writer's DSS and DocTimeStamp object shapes are allowed
//! after a signer. Unknown objects, redefinitions and ambiguous revisions
//! default to suspicious; structural indicators are not verdicts on their own.

use super::verify_sig_pipeline::{check_byte_range, collect_signatures};
use crate::api::{ModificationLevel, ModificationStatus, SealResourceLimits, VerifyAnomaly};
use lopdf::{Dictionary, Document, LoadOptions, Object, ObjectId};
use std::collections::BTreeSet;

const MAX_REVISIONS: usize = 32;
fn parsed(bytes: &[u8], limits: &SealResourceLimits) -> Option<Document> {
    let options = LoadOptions {
        strict: true,
        max_decompressed_size: Some(limits.max_input_bytes),
        ..LoadOptions::default()
    };
    let doc = Document::load_mem_with_options(bytes, options).ok()?;
    (doc.objects.len() <= limits.max_pdf_objects).then_some(doc)
}

fn name(obj: &Object, value: &[u8]) -> bool {
    matches!(obj, Object::Name(n) if n == value)
}
fn is_xref(obj: &Object) -> bool {
    let Object::Stream(stream) = obj else {
        return false;
    };
    matches!(stream.dict.get(b"Type"), Ok(t) if name(t, b"XRef"))
        && stream.dict.iter().all(|(key, _)| {
            [
                b"Type".as_slice(),
                b"W",
                b"Index",
                b"Prev",
                b"Root",
                b"Length",
                b"Size",
                b"ID",
                b"Info",
                b"Filter",
                b"DecodeParms",
            ]
            .contains(&key.as_slice())
        })
}
fn changed_ids(before: &Document, after: &Document) -> Option<BTreeSet<ObjectId>> {
    // A previous object may be redefined with identical effective content;
    // compare xref positions, not just the merged object map.
    let mut changed = BTreeSet::new();
    for (id, obj) in &before.objects {
        let current = after.objects.get(id)?;
        let old_xref = before.reference_table.get(id.0);
        let new_xref = after.reference_table.get(id.0);
        if current != obj || format!("{old_xref:?}") != format!("{new_xref:?}") {
            changed.insert(*id);
        }
    }
    for id in after.objects.keys() {
        if !before.objects.contains_key(id) {
            changed.insert(*id);
        }
    }
    Some(changed)
}
fn unchanged_except(old: &Dictionary, new: &Dictionary, key: &[u8]) -> bool {
    let mut a = old.clone();
    let mut b = new.clone();
    a.remove(key);
    b.remove(key);
    a == b
}
fn only_xref_extra(
    after: &Document,
    changed: &mut BTreeSet<ObjectId>,
    before: &Document,
    bytes: &[u8],
) -> bool {
    let extra: Vec<_> = changed
        .iter()
        .copied()
        .filter(|id| !before.objects.contains_key(id) && after.objects.get(id).is_some_and(is_xref))
        .collect();
    if extra.len() > 1 {
        return false;
    }
    for id in extra {
        // The single xref stream must be the *actual* startxref target, not
        // an orphan /Type /XRef object used to conceal an unrelated append.
        let Ok(target) = super::super::pdf::last_startxref(bytes) else {
            return false;
        };
        if !matches!(
            after.reference_table.cross_reference_type,
            lopdf::xref::XrefType::CrossReferenceStream
        ) || !matches!(after.reference_table.get(id.0),
                Some(lopdf::xref::XrefEntry::Normal { offset, .. }) if u64::from(*offset)==target)
        {
            return false;
        }
        changed.remove(&id);
    }
    true
}
fn ref_obj(obj: &Object) -> Option<ObjectId> {
    match obj {
        Object::Reference(id) => Some(*id),
        _ => None,
    }
}
fn dss_delta(
    before: &Document,
    after: &Document,
    bytes: &[u8],
    mut changed: BTreeSet<ObjectId>,
) -> bool {
    if before.trailer.get(b"Root").ok() != after.trailer.get(b"Root").ok() {
        return false;
    }
    let Ok(root) = after.trailer.get(b"Root").and_then(Object::as_reference) else {
        return false;
    };
    let (Ok(old), Ok(new)) = (before.get_dictionary(root), after.get_dictionary(root)) else {
        return false;
    };
    if !changed.remove(&root) || !unchanged_except(old, new, b"DSS") {
        return false;
    }
    let Some(dss_id) = new.get(b"DSS").ok().and_then(ref_obj) else {
        return false;
    };
    if before.objects.contains_key(&dss_id) || !changed.remove(&dss_id) {
        return false;
    }
    let Ok(dss) = after.get_dictionary(dss_id) else {
        return false;
    };
    if !matches!(dss.get(b"Type"), Ok(t) if name(t,b"DSS"))
        || !dss.iter().all(|(key, _)| {
            [b"Type".as_slice(), b"Certs", b"OCSPs", b"CRLs"].contains(&key.as_slice())
        })
    {
        return false;
    }
    let mut material_count = 0;
    for key in [b"Certs".as_slice(), b"OCSPs", b"CRLs"] {
        if let Ok(value) = dss.get(key) {
            let Ok(Object::Array(entries)) = after.dereference(value).map(|(_, v)| v) else {
                return false;
            };
            for entry in entries {
                let Some(id) = ref_obj(entry) else {
                    return false;
                };
                if before.objects.contains_key(&id) || !changed.remove(&id) {
                    return false;
                }
                let Ok(Object::Stream(stream)) = after.get_object(id) else {
                    return false;
                };
                if !stream.dict.iter().all(|(k, _)| k.as_slice() == b"Length") {
                    return false;
                }
                material_count += 1;
            }
        }
    }
    material_count > 0 && only_xref_extra(after, &mut changed, before, bytes) && changed.is_empty()
}
fn doc_timestamp_delta(
    before: &Document,
    after: &Document,
    bytes: &[u8],
    mut changed: BTreeSet<ObjectId>,
) -> bool {
    if before.trailer.get(b"Root").ok() != after.trailer.get(b"Root").ok() {
        return false;
    }
    let (Ok(old_sigs), Ok(new_sigs)) = (collect_signatures(before), collect_signatures(after))
    else {
        return false;
    };
    if new_sigs.len() != old_sigs.len() + 1 {
        return false;
    }
    let Some(new_ts) = new_sigs.last() else {
        return false;
    };
    if !new_ts.is_doc_ts
        || !check_byte_range(bytes, new_ts)
        || new_ts.byte_range[2].checked_add(new_ts.byte_range[3]) != Some(bytes.len() as u64)
    {
        return false;
    }
    let Ok(root) = after.trailer.get(b"Root").and_then(Object::as_reference) else {
        return false;
    };
    let (Ok(old_cat), Ok(new_cat)) = (before.get_dictionary(root), after.get_dictionary(root))
    else {
        return false;
    };
    // The writer either redefines the AcroForm or creates it and updates
    // the catalog's sole AcroForm entry.
    if changed.contains(&root) {
        if !unchanged_except(old_cat, new_cat, b"AcroForm") {
            return false;
        }
        changed.remove(&root);
    } else if old_cat != new_cat {
        return false;
    }
    let Some(af_id) = new_cat.get(b"AcroForm").ok().and_then(ref_obj) else {
        return false;
    };
    let Ok(new_af) = after.get_dictionary(af_id) else {
        return false;
    };
    let Ok(Object::Array(fields)) = new_af.get(b"Fields") else {
        return false;
    };
    let Some(field_id) = fields.last().and_then(ref_obj) else {
        return false;
    };
    if before.objects.contains_key(&field_id) || !changed.remove(&field_id) {
        return false;
    }
    if let Ok(old_af) = before.get_dictionary(af_id) {
        let mut old_other = old_af.clone();
        let mut new_other = new_af.clone();
        for key in [b"Fields".as_slice(), b"SigFlags"] {
            old_other.remove(key);
            new_other.remove(key);
        }
        if !changed.remove(&af_id) || old_other != new_other {
            return false;
        }
        let Ok(Object::Array(prior)) = old_af.get(b"Fields") else {
            return false;
        };
        if fields.len() != prior.len() + 1 || fields[..prior.len()] != prior[..] {
            return false;
        }
    } else if !changed.remove(&af_id) || fields.len() != 1 {
        return false;
    }
    if !matches!(new_af.get(b"SigFlags"), Ok(Object::Integer(3))) {
        return false;
    }
    let Ok(field) = after.get_dictionary(field_id) else {
        return false;
    };
    if !matches!(field.get(b"FT"),Ok(t) if name(t,b"Sig"))
        || !field
            .iter()
            .all(|(k, _)| [b"FT".as_slice(), b"T", b"V"].contains(&k.as_slice()))
    {
        return false;
    }
    let Some(sig_id) = field.get(b"V").ok().and_then(ref_obj) else {
        return false;
    };
    if before.objects.contains_key(&sig_id) || !changed.remove(&sig_id) {
        return false;
    }
    let Ok(sig) = after.get_dictionary(sig_id) else {
        return false;
    };
    if !matches!(sig.get(b"Type"),Ok(t) if name(t,b"DocTimeStamp"))
        || !matches!(sig.get(b"SubFilter"),Ok(t) if name(t,b"ETSI.RFC3161"))
        || !sig.iter().all(|(k, _)| {
            [
                b"Type".as_slice(),
                b"Filter",
                b"SubFilter",
                b"ByteRange",
                b"Contents",
            ]
            .contains(&k.as_slice())
        })
    {
        return false;
    }
    only_xref_extra(after, &mut changed, before, bytes) && changed.is_empty()
}

/// Candidate EOF ends are bounded; a fake marker within a content stream
/// makes the analysis fail closed if its prefix does not parse as a revision.
pub(super) fn revision_boundaries(bytes: &[u8]) -> Vec<usize> {
    bytes
        .windows(5)
        .enumerate()
        .filter_map(|(i, w)| (w == b"%%EOF").then_some(i + 5))
        .take(MAX_REVISIONS + 1) // sentinel: fail closed before allocating unbounded rows
        .collect()
}

/// Structural indicators are deliberately separate from the modification
/// decision and from the cryptographic verdict.
pub(super) fn structural_anomalies(
    bytes: &[u8],
    boundaries: &[usize],
    limits: &SealResourceLimits,
) -> Vec<VerifyAnomaly> {
    let mut out = Vec::new();
    if boundaries.len() > MAX_REVISIONS {
        return out;
    }
    let mut previous = None;
    for &end in boundaries {
        let Some(current) = parsed(&bytes[..end], limits) else {
            continue;
        };
        if let Some(prior) = &previous
            && let Some(changed) = changed_ids(prior, &current)
        {
            if changed.is_empty() && !out.contains(&VerifyAnomaly::PointerOnlyRevision) {
                out.push(VerifyAnomaly::PointerOnlyRevision);
            }
            if changed.iter().any(|id| {
                prior
                    .objects
                    .get(id)
                    .zip(current.objects.get(id))
                    .is_some_and(|(a, b)| std::mem::discriminant(a) != std::mem::discriminant(b))
            }) && !out.contains(&VerifyAnomaly::RetypedObject)
            {
                out.push(VerifyAnomaly::RetypedObject);
            }
        }
        previous = Some(current);
    }
    out
}

/// Count object headers in the new byte segment, not only objects retained
/// by lopdf's merged xref. An unreferenced extra object must not ride along
/// with an otherwise permitted evidence update. False positives in a stream
/// fail closed; this whitelist accepts the native writer's exact line shape.
fn revision_headers(segment: &[u8], max_objects: usize) -> Option<BTreeSet<ObjectId>> {
    let mut ids = BTreeSet::new();
    for line in segment.split(|b| *b == b'\n') {
        let Some(prefix) = line.strip_suffix(b" obj") else {
            continue;
        };
        let mut parts = prefix.split(|b| *b == b' ');
        let (Some(num), Some(generation), None) = (parts.next(), parts.next(), parts.next()) else {
            return None;
        };
        let num = std::str::from_utf8(num).ok()?.parse::<u32>().ok()?;
        let generation = std::str::from_utf8(generation).ok()?.parse::<u16>().ok()?;
        if !ids.insert((num, generation)) || ids.len() > max_objects.min(10_000) {
            return None;
        }
    }
    Some(ids)
}

fn accounted_headers(
    bytes: &[u8],
    before_end: usize,
    next_end: usize,
    changed: &BTreeSet<ObjectId>,
    next: &Document,
    limits: &SealResourceLimits,
) -> bool {
    let Some(mut headers) = revision_headers(&bytes[before_end..next_end], limits.max_pdf_objects)
    else {
        return false;
    };
    // lopdf may keep the xref stream in the xref table without exposing it
    // in Document.objects. Its real startxref target is the only exception.
    if matches!(
        next.reference_table.cross_reference_type,
        lopdf::xref::XrefType::CrossReferenceStream
    ) && let Ok(offset) = super::super::pdf::last_startxref(&bytes[..next_end])
        && let Ok(at) = usize::try_from(offset)
        && let Some(header) = bytes
            .get(at..)
            .and_then(|b| b.split(|c| *c == b'\n').next())
        && let Some(xref_id) =
            revision_headers(&[header, b"\n"].concat(), 1).and_then(|ids| ids.into_iter().next())
        && !changed.contains(&xref_id)
    {
        headers.remove(&xref_id);
    }
    headers == *changed
}

/// The same default-deny revision core checks unsigned input before signing
/// and classifies each append after the first signed revision at verification.
pub(crate) fn analyze_modifications(
    bytes: &[u8],
    signer_end: Option<u64>,
    limits: &SealResourceLimits,
) -> ModificationStatus {
    let mut ends = revision_boundaries(bytes);
    if ends.is_empty() || ends.len() > MAX_REVISIONS {
        return ModificationStatus::Suspicious;
    }
    let Some(final_end) = ends.last().copied() else {
        return ModificationStatus::Suspicious;
    };
    if !bytes[final_end..]
        .iter()
        .all(|b| *b == b'\r' || *b == b'\n')
        || bytes.len() - final_end > 4
    {
        return ModificationStatus::Suspicious;
    }
    let first = match signer_end {
        Some(end) => {
            let Ok(end) = usize::try_from(end) else {
                return ModificationStatus::Suspicious;
            };
            let Some(index) = ends.iter().position(|&e| {
                e == end
                    || (e < end
                        && end - e <= 4
                        && bytes[e..end].iter().all(|b| *b == b'\r' || *b == b'\n'))
            }) else {
                return ModificationStatus::Suspicious;
            };
            index
        }
        None => 0,
    };
    if first == ends.len() - 1 {
        return ModificationStatus::Clean(ModificationLevel::None);
    }
    let mut previous_end = ends[first];
    let Some(mut prev) = parsed(&bytes[..previous_end], limits) else {
        return ModificationStatus::Suspicious;
    };
    for next_end in ends.drain(first + 1..) {
        let Some(next) = parsed(&bytes[..next_end], limits) else {
            return ModificationStatus::Suspicious;
        };
        let Some(changed) = changed_ids(&prev, &next) else {
            return ModificationStatus::Suspicious;
        };
        let allowed = signer_end.is_some()
            && accounted_headers(bytes, previous_end, next_end, &changed, &next, limits)
            && (dss_delta(&prev, &next, &bytes[..next_end], changed.clone())
                || doc_timestamp_delta(&prev, &next, &bytes[..next_end], changed));
        if !allowed {
            return ModificationStatus::Suspicious;
        }
        prev = next;
        previous_end = next_end;
    }
    ModificationStatus::Clean(ModificationLevel::LtaUpdates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_revision_scan_counts_unreferenced_objects_and_rejects_duplicates() {
        let body = b"\n12 0 obj\n<<>>\nendobj\n13 0 obj\n<<>>\nendobj\n";
        assert_eq!(
            revision_headers(body, 5),
            Some(BTreeSet::from([(12, 0), (13, 0)]))
        );
        assert_eq!(revision_headers(b"\n12 0 obj\n12 0 obj\n", 5), None);
        assert_eq!(revision_headers(body, 1), None);
    }

    #[test]
    fn revision_markers_are_bounded_before_any_prefix_parsing_or_report_allocation() {
        let bytes = b"%%EOF".repeat(1000);
        assert_eq!(revision_boundaries(&bytes).len(), MAX_REVISIONS + 1);
        assert_eq!(
            analyze_modifications(&bytes, None, &SealResourceLimits::default()),
            ModificationStatus::Suspicious
        );
    }
}
