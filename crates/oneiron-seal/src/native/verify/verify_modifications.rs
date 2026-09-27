//! Conservative, shared pre-sign and post-sign incremental-revision analysis.
//!
//! Only the native writer's DSS and DocTimeStamp object shapes are allowed
//! after a signer. Unknown objects, redefinitions and ambiguous revisions
//! default to suspicious; structural indicators are not verdicts on their own.

use super::verify_revision_tokens::{
    revision_headers, scan_headers, stream_delimiter, stream_payloads,
};
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
fn trailer_allowed(
    before: &Document,
    after: &Document,
    prior_bytes: &[u8],
    next_bytes: &[u8],
) -> bool {
    if std::mem::discriminant(&before.reference_table.cross_reference_type)
        != std::mem::discriminant(&after.reference_table.cross_reference_type)
    {
        return false;
    }
    let Ok(previous_xref) = super::super::pdf::last_startxref(prior_bytes) else {
        return false;
    };
    // lopdf merges /Prev links into one Document and does not retain /Prev
    // in Document.trailer. Read the current xref framing, not arbitrary page
    // content, and prove its one /Prev points to the previous revision.
    let Ok(current_xref) = super::super::pdf::last_startxref(next_bytes) else {
        return false;
    };
    let Ok(offset) = usize::try_from(current_xref) else {
        return false;
    };
    let Some(xref) = next_bytes.get(offset..) else {
        return false;
    };
    let end = if matches!(
        after.reference_table.cross_reference_type,
        lopdf::xref::XrefType::CrossReferenceStream
    ) {
        xref.windows(b"stream\n".len())
            .position(|w| w == b"stream\n")
    } else {
        xref.windows(b"startxref".len())
            .rposition(|w| w == b"startxref")
    };
    let Some(header) = end.and_then(|i| xref.get(..i)) else {
        return false;
    };
    let prev: Vec<_> = header
        .windows(b"/Prev".len())
        .enumerate()
        .filter_map(|(i, w)| (w == b"/Prev").then_some(i + b"/Prev".len()))
        .collect();
    if prev.len() != 1 {
        return false;
    }
    let digits = header[prev[0]..]
        .iter()
        .copied()
        .skip_while(|b| *b == b' ')
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    if digits.is_empty()
        || std::str::from_utf8(&digits)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            != Some(previous_xref)
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

/// Return the actual final EOF marker end, allowing at most four CR/LF bytes.
pub(super) fn eof_tail(bytes: &[u8]) -> Option<usize> {
    let mut end = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b'\r' | b'\n') {
        end -= 1;
        if bytes.len() - end > 4 {
            return None;
        }
    }
    bytes[..end].ends_with(b"%%EOF").then_some(end)
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

/// Locate the revision footer whose `startxref` points to `at`. A raw
/// `%%EOF` inside a stream is not a revision boundary. Work stays bounded by
/// the validated input size and MAX_REVISIONS in the caller.
fn revision_footer(bytes: &[u8], at: usize, upper: usize) -> Option<(usize, usize)> {
    let section = bytes.get(at..upper)?;
    for (i, window) in section.windows(b"startxref".len()).enumerate().rev() {
        if window != b"startxref" {
            continue;
        }
        let mut cursor = at + i + b"startxref".len();
        while matches!(bytes.get(cursor), Some(b' ' | b'\r' | b'\n')) {
            cursor += 1;
        }
        let first = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if first == cursor
            || bytes
                .get(first..cursor)?
                .iter()
                .try_fold(0usize, |value, b| {
                    value.checked_mul(10)?.checked_add(usize::from(*b - b'0'))
                })
                != Some(at)
        {
            continue;
        }
        while matches!(bytes.get(cursor), Some(b' ' | b'\r' | b'\n')) {
            cursor += 1;
        }
        if bytes.get(cursor..cursor + 5) == Some(b"%%EOF") && cursor + 5 <= upper {
            return Some((at + i, cursor + 5));
        }
    }
    None
}

/// The previous xref is read only from the current xref/trailer header.
/// lopdf's merged trailer deliberately drops /Prev.
fn xref_previous(bytes: &[u8], at: usize, footer_start: usize) -> Option<Option<usize>> {
    let section = bytes.get(at..footer_start)?;
    let header = if section.starts_with(b"xref") {
        section
    } else {
        let (stream_at, _) = stream_delimiter(section)?;
        &section[..stream_at]
    };
    let mut found = None;
    for (i, w) in header.windows(b"/Prev".len()).enumerate() {
        if w != b"/Prev" {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let mut cursor = i + b"/Prev".len();
        while header.get(cursor) == Some(&b' ') {
            cursor += 1;
        }
        let first = cursor;
        while header.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if first == cursor {
            return None;
        }
        found = Some(header[first..cursor].iter().try_fold(0usize, |value, b| {
            value.checked_mul(10)?.checked_add(usize::from(*b - b'0'))
        })?);
    }
    Some(found)
}

/// Follow the validated xref `/Prev` chain and its matching startxref/EOF
/// footers. Never infer revisions from raw `%%EOF` occurrences in streams.
pub(super) fn revision_boundaries(bytes: &[u8]) -> Vec<usize> {
    let Some(mut upper) = eof_tail(bytes) else {
        return Vec::new();
    };
    let Ok(start) = super::super::pdf::last_startxref(bytes) else {
        return Vec::new();
    };
    let Ok(mut at) = usize::try_from(start) else {
        return Vec::new();
    };
    let mut ends = Vec::new();
    for _ in 0..=MAX_REVISIONS {
        if at >= upper {
            return Vec::new();
        }
        let Some((footer, end)) = revision_footer(bytes, at, upper) else {
            return Vec::new();
        };
        if ends.is_empty() && end != upper {
            return Vec::new();
        }
        ends.push(end);
        let Some(prev) = xref_previous(bytes, at, footer) else {
            return Vec::new();
        };
        let Some(prev) = prev else {
            ends.reverse();
            return ends;
        };
        if prev >= at {
            return Vec::new();
        }
        upper = at;
        at = prev;
    }
    ends.reverse(); // MAX_REVISIONS + 1 is the fail-closed sentinel.
    ends
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
    let mut prior_end = 0;
    for &end in boundaries {
        let Some(current) = parsed(&bytes[..end], limits) else {
            prior_end = end;
            continue;
        };
        let spans = stream_payloads(&current, &bytes[..end], limits.max_pdf_objects);
        if scan_headers(
            &bytes[prior_end..end],
            prior_end,
            limits.max_pdf_objects,
            &spans,
        )
        .is_some_and(|scan| scan.duplicate)
            && !out.contains(&VerifyAnomaly::DuplicateObjectNumber)
        {
            out.push(VerifyAnomaly::DuplicateObjectNumber);
        }
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
        prior_end = end;
    }
    out
}

fn accounted_headers(
    bytes: &[u8],
    before_end: usize,
    next_end: usize,
    changed: &BTreeSet<ObjectId>,
    next: &Document,
    limits: &SealResourceLimits,
) -> bool {
    let spans = stream_payloads(next, &bytes[..next_end], limits.max_pdf_objects);
    let Some(scan) = scan_headers(
        &bytes[before_end..next_end],
        before_end,
        limits.max_pdf_objects,
        &spans,
    ) else {
        return false;
    };
    if scan.duplicate {
        return false;
    }
    let mut headers = scan.ids;
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
    if eof_tail(bytes) != Some(final_end) {
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
            && trailer_allowed(&prev, &next, &bytes[..previous_end], &bytes[..next_end])
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
        assert_eq!(revision_boundaries(&bytes).len(), MAX_REVISIONS + 1);
        assert_eq!(
            analyze_modifications(&bytes, None, &SealResourceLimits::default()),
            ModificationStatus::Suspicious
        );
        assert!(revision_boundaries(b"%%EOF%%EOF").is_empty());
    }
}
