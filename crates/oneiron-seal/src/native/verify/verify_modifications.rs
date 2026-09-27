//! Conservative, shared pre-sign and post-sign incremental-revision analysis.
//!
//! Only the native writer's DSS and DocTimeStamp object shapes are allowed
//! after a signer. Unknown objects, redefinitions and ambiguous revisions
//! default to suspicious; structural indicators are not verdicts on their own.

use super::super::pdf::{self, RevisionFacts};
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
/// The writer changes only /Prev and /Size in a table trailer. Xref
/// streams also replace their framing keys; document identity and metadata
/// pointers must remain byte-for-byte equal across each renewal.
fn trailer_allowed(before: &pdf::RevisionFact, after: &pdf::RevisionFact) -> bool {
    if std::mem::discriminant(&before.xref_style) != std::mem::discriminant(&after.xref_style)
        || after.prev_xref != Some(before.xref_offset)
    {
        return false;
    }
    let (Ok(Object::Integer(old_size)), Ok(Object::Integer(new_size))) =
        (before.trailer.get(b"Size"), after.trailer.get(b"Size"))
    else {
        return false;
    };
    if *new_size <= *old_size {
        return false;
    }
    let mut old = before.trailer.clone();
    let mut new = after.trailer.clone();
    for key in [
        b"Prev".as_slice(),
        b"Size",
        b"Type",
        b"W",
        b"Index",
        b"Length",
        b"Filter",
        b"DecodeParms",
    ] {
        old.remove(key);
        new.remove(key);
    }
    old == new
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

/// Structural indicators are deliberately separate from the modification
/// decision and from the cryptographic verdict.
pub(super) fn structural_anomalies(
    bytes: &[u8],
    facts: &RevisionFacts,
    limits: &SealResourceLimits,
) -> Vec<VerifyAnomaly> {
    let mut out = Vec::new();
    if facts.has_duplicates() {
        out.push(VerifyAnomaly::DuplicateObjectNumber);
    }
    let mut previous: Option<Document> = None;
    for revision in &facts.revisions {
        let Some(current) = parsed(&bytes[..revision.byte_end], limits) else {
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

/// The same default-deny revision core checks unsigned input before signing
/// and classifies each append after the first signed revision at verification.
pub(crate) fn analyze_modifications(
    bytes: &[u8],
    signer_end: Option<u64>,
    limits: &SealResourceLimits,
    facts: &RevisionFacts,
) -> ModificationStatus {
    let ends = facts.ends();
    if ends.is_empty() || ends.len() > MAX_REVISIONS {
        return ModificationStatus::Suspicious;
    }
    let Some(final_end) = ends.last().copied() else {
        return ModificationStatus::Suspicious;
    };
    if pdf::eof_tail(bytes) != Some(final_end) {
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
    let Some(mut prev) = parsed(&bytes[..ends[first]], limits) else {
        return ModificationStatus::Suspicious;
    };
    for (index, &next_end) in ends.iter().enumerate().skip(first + 1) {
        let Some(next) = parsed(&bytes[..next_end], limits) else {
            return ModificationStatus::Suspicious;
        };
        let Some(changed) = changed_ids(&prev, &next) else {
            return ModificationStatus::Suspicious;
        };
        let allowed = signer_end.is_some()
            && trailer_allowed(&facts.revisions[index - 1], &facts.revisions[index])
            && facts.accounts_for(index, &changed)
            && (dss_delta(&prev, &next, &bytes[..next_end], changed.clone())
                || doc_timestamp_delta(&prev, &next, &bytes[..next_end], changed));
        if !allowed {
            return ModificationStatus::Suspicious;
        }
        prev = next;
    }
    ModificationStatus::Clean(ModificationLevel::LtaUpdates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_revision_scan_counts_unreferenced_objects_and_rejects_duplicates() {
        let bytes = std::fs::read(format!(
            "{}/tests/fixtures/pdf-input/classic_1page.pdf",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let facts = pdf::analyze_revision_facts(&bytes, &SealResourceLimits::default()).unwrap();
        let ids: BTreeSet<_> = facts.revisions[0]
            .definitions
            .iter()
            .map(|d| d.id)
            .collect();
        assert_eq!(ids, BTreeSet::from([(1, 0), (2, 0), (3, 0)]));
        assert!(!facts.has_duplicates());
        assert!(
            pdf::analyze_revision_facts(
                b"%PDF-1.4\n12 0 obj\n12 0 obj\n%%EOF",
                &SealResourceLimits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn revision_markers_are_bounded_before_any_prefix_parsing_or_report_allocation() {
        let mut bytes = std::fs::read(format!(
            "{}/tests/fixtures/pdf-input/classic_1page.pdf",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        for _ in 0..=MAX_REVISIONS {
            let state =
                super::super::super::pdf::reparse_revision(&bytes, &SealResourceLimits::default())
                    .unwrap();
            let id = state.max_obj + 1;
            bytes = super::super::super::pdf::append_revision(
                &bytes,
                &state,
                &super::super::super::pdf::RevisionKind::Dss {
                    material_objects: vec![(id, b"<< /Type /DSS >>".to_vec())],
                    dss_obj: id,
                },
                0,
            )
            .unwrap()
            .bytes;
        }
        assert!(pdf::analyze_revision_facts(&bytes, &SealResourceLimits::default()).is_err());
        assert!(
            pdf::analyze_revision_facts(b"%%EOF%%EOF", &SealResourceLimits::default()).is_err()
        );
    }
}
