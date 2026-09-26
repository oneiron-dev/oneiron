//! Bounded revision snapshots and default-deny classification of post-sign changes.
//! A lawful LTA append may add only DSS evidence or a validated document
//! timestamp. No unknown PDF object type is allowed by default.
use std::collections::BTreeSet;

use crate::api::{
    Anomaly, ModificationLevel, Modifications, RevisionKind, RevisionReport, SignatureKind,
    SignatureReport, VerifyCheckKind, VerifyCheckStatus,
};
use lopdf::{Document, LoadOptions, Object, ObjectId};

const MAX_REVISIONS: usize = 32;

fn bounds(bytes: &[u8]) -> Option<Vec<usize>> {
    let mut ends = Vec::new();
    for (at, marker) in bytes.windows(5).enumerate() {
        if marker != b"%%EOF" {
            continue;
        }
        // Only a startxref directly preceding EOF counts as a revision.
        // A marker embedded in a stream or PDF string is not a revision.
        let head = &bytes[at.saturating_sub(80)..at];
        let Some(sx) = head.windows(9).rposition(|w| w == b"startxref") else {
            continue;
        };
        let number = head[sx + 9..]
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect::<Vec<_>>();
        let Ok(num) = std::str::from_utf8(&number).ok()?.parse::<usize>() else {
            continue;
        };
        if num >= at || num.checked_add(4).and_then(|n| bytes.get(num..n)).is_none() {
            continue;
        }
        if ends.len() >= MAX_REVISIONS {
            return None;
        }
        ends.push(at + 5);
    }
    let last = *ends.last()?;
    let tail = &bytes[last..];
    if tail.len() > 4 || tail.iter().any(|b| !matches!(b, b'\r' | b'\n')) {
        return None;
    }
    *ends.last_mut()? = bytes.len();
    Some(ends)
}

fn loaded(bytes: &[u8]) -> Option<Document> {
    Document::load_mem_with_options(
        bytes,
        LoadOptions {
            strict: true,
            max_decompressed_size: Some(bytes.len()),
            ..LoadOptions::default()
        },
    )
    .ok()
}
fn changed(before: &Document, after: &Document) -> Option<BTreeSet<ObjectId>> {
    if before
        .objects
        .keys()
        .any(|id| !after.objects.contains_key(id))
    {
        return None;
    }
    Some(
        after
            .objects
            .iter()
            .filter(|(id, obj)| before.objects.get(id) != Some(obj))
            .map(|(id, _)| *id)
            .collect(),
    )
}
fn is_xref(obj: &Object) -> bool {
    let d = match obj {
        Object::Dictionary(d) => d,
        Object::Stream(s) => &s.dict,
        _ => return false,
    };
    d.get(b"Type")
        .is_ok_and(|ty| matches!(ty, Object::Name(n) if n == b"XRef"))
}

fn without(dict: &lopdf::Dictionary, keys: &[&[u8]]) -> lopdf::Dictionary {
    let mut clone = dict.clone();
    for key in keys {
        clone.remove(key);
    }
    clone
}
fn ref_id(obj: &Object) -> Option<ObjectId> {
    obj.as_reference().ok()
}
fn catalog_id(doc: &Document) -> Option<ObjectId> {
    ref_id(doc.trailer.get(b"Root").ok()?)
}

fn dss_allowed(before: &Document, after: &Document, ids: &BTreeSet<ObjectId>) -> bool {
    let (Some(old_catalog), Some(new_catalog)) = (before.catalog().ok(), after.catalog().ok())
    else {
        return false;
    };
    if without(old_catalog, &[b"DSS"]) != without(new_catalog, &[b"DSS"]) {
        return false;
    }
    let Some(dss_ref) = new_catalog.get(b"DSS").ok().and_then(ref_id) else {
        return false;
    };
    if !ids.contains(&dss_ref)
        || before.objects.contains_key(&dss_ref)
        || !catalog_id(after).is_some_and(|id| ids.contains(&id))
    {
        return false;
    }
    let Some(dss) = after
        .get_object(dss_ref)
        .ok()
        .and_then(|o| o.as_dict().ok())
    else {
        return false;
    };
    if !matches!(dss.get(b"Type"), Ok(Object::Name(n)) if n == b"DSS") {
        return false;
    }
    if dss
        .iter()
        .any(|(k, _)| ![b"Type".as_slice(), b"Certs", b"OCSPs", b"CRLs"].contains(&k.as_slice()))
    {
        return false;
    }
    let mut allowed = BTreeSet::from([dss_ref]);
    if let Some(id) = catalog_id(after) {
        allowed.insert(id);
    }
    for key in [b"Certs".as_slice(), b"OCSPs", b"CRLs"] {
        let Ok(value) = dss.get(key) else {
            continue;
        };
        let Some(arr) = after
            .dereference(value)
            .ok()
            .and_then(|(_, o)| o.as_array().ok())
        else {
            return false;
        };
        if let Some(id) = ref_id(value) {
            allowed.insert(id);
        }
        for entry in arr {
            let Some(id) = ref_id(entry) else {
                return false;
            };
            let Some(obj) = after.get_object(id).ok() else {
                return false;
            };
            if !matches!(obj, Object::Stream(_)) {
                return false;
            }
            allowed.insert(id);
        }
    }
    ids.iter().all(|id| {
        (allowed.contains(id)
            && (!before.objects.contains_key(id) || Some(*id) == catalog_id(after)))
            || (!before.objects.contains_key(id) && after.objects.get(id).is_some_and(is_xref))
    })
}

fn doc_timestamp_allowed(
    before: &Document,
    after: &Document,
    ids: &BTreeSet<ObjectId>,
    sig: &SignatureReport,
) -> bool {
    if sig.kind != SignatureKind::DocumentTimestamp
        || sig.checks.iter().all(|c| {
            c.kind != VerifyCheckKind::DocumentTimestamp || c.status != VerifyCheckStatus::Pass
        })
    {
        return false;
    }
    let (Some(old_catalog), Some(new_catalog)) = (before.catalog().ok(), after.catalog().ok())
    else {
        return false;
    };
    if without(old_catalog, &[b"AcroForm"]) != without(new_catalog, &[b"AcroForm"]) {
        return false;
    }
    let Some(af_obj) = new_catalog.get(b"AcroForm").ok() else {
        return false;
    };
    let Some(af) = after
        .dereference(af_obj)
        .ok()
        .and_then(|(_, o)| o.as_dict().ok())
    else {
        return false;
    };
    let Some(fields) = af
        .get(b"Fields")
        .ok()
        .and_then(|o| after.dereference(o).ok())
        .and_then(|(_, o)| o.as_array().ok())
    else {
        return false;
    };
    let Some(last_field) = fields.last().and_then(ref_id) else {
        return false;
    };
    if let Ok(old_af_obj) = old_catalog.get(b"AcroForm") {
        let Some(old_af) = before
            .dereference(old_af_obj)
            .ok()
            .and_then(|(_, o)| o.as_dict().ok())
        else {
            return false;
        };
        if without(old_af, &[b"Fields", b"SigFlags"]) != without(af, &[b"Fields", b"SigFlags"]) {
            return false;
        }
        let Some(old_fields) = old_af
            .get(b"Fields")
            .ok()
            .and_then(|o| before.dereference(o).ok())
            .and_then(|(_, o)| o.as_array().ok())
        else {
            return false;
        };
        if fields.len() != old_fields.len() + 1 || fields[..old_fields.len()] != old_fields[..] {
            return false;
        }
    } else if fields.len() != 1 {
        return false;
    }
    let Some(field) = after
        .get_object(last_field)
        .ok()
        .and_then(|o| o.as_dict().ok())
    else {
        return false;
    };
    if field
        .iter()
        .any(|(k, _)| ![b"FT".as_slice(), b"T", b"V"].contains(&k.as_slice()))
        || !matches!(field.get(b"FT"), Ok(Object::Name(n)) if n == b"Sig")
    {
        return false;
    }
    let Some(ts_id) = field.get(b"V").ok().and_then(ref_id) else {
        return false;
    };
    let Some(ts) = after.get_object(ts_id).ok().and_then(|o| o.as_dict().ok()) else {
        return false;
    };
    if !matches!(ts.get(b"Type"), Ok(Object::Name(n)) if n == b"DocTimeStamp") {
        return false;
    }
    let mut allowed = BTreeSet::from([last_field, ts_id]);
    if let Some(id) = catalog_id(after) {
        allowed.insert(id);
    }
    if let Some(id) = ref_id(af_obj) {
        allowed.insert(id);
    }
    ids.iter().all(|id| {
        (allowed.contains(id)
            && (!before.objects.contains_key(id)
                || Some(*id) == catalog_id(after)
                || Some(*id) == ref_id(af_obj)))
            || (!before.objects.contains_key(id) && after.objects.get(id).is_some_and(is_xref))
    })
}

/// A classification failure is NotRun, never Clean. Unknown changed objects
/// are Suspicious even when their signature bytes still verify.
pub(super) fn classify(
    bytes: &[u8],
    signatures: &[SignatureReport],
) -> (Vec<RevisionReport>, Modifications, Vec<Anomaly>) {
    let Some(ends) = bounds(bytes) else {
        return (vec![], Modifications::NotRun, vec![]);
    };
    let mut revisions = Vec::new();
    let mut anomalies = Vec::new();
    let mut previous: Option<Document> = None;
    let mut first_signer = None;
    let mut modification = ModificationLevel::None;
    let mut suspicious = false;
    let mut work = 0usize;
    for (index, end) in ends.into_iter().enumerate() {
        work = work.saturating_add(end);
        if work > 2 * 1024 * 1024 * 1024 {
            return (revisions, Modifications::NotRun, anomalies);
        }
        let Some(doc) = loaded(&bytes[..end]) else {
            return (revisions, Modifications::NotRun, anomalies);
        };
        let signed = signatures.iter().find(|s| {
            s.byte_range.covers_to.is_some_and(|n| {
                n <= end as u64
                    && end as u64 - n <= 4
                    && bytes[n as usize..end]
                        .iter()
                        .all(|b| *b == b'\r' || *b == b'\n')
            })
        });
        let mut kind = if index == 0 {
            RevisionKind::Original
        } else if let Some(sig) = signed {
            match sig.kind {
                SignatureKind::Signature => RevisionKind::Signature,
                SignatureKind::DocumentTimestamp => RevisionKind::DocumentTimestamp,
            }
        } else if doc
            .catalog()
            .ok()
            .and_then(|d| d.get(b"DSS").ok())
            .is_some()
        {
            RevisionKind::Dss
        } else {
            RevisionKind::Other
        };
        if let Some(before) = &previous {
            let Some(ids) = changed(before, &doc) else {
                return (revisions, Modifications::NotRun, anomalies);
            };
            if ids.is_empty() {
                anomalies.push(Anomaly::PointerOnlyRevision);
            }
            if ids.iter().any(|id| {
                before
                    .objects
                    .get(id)
                    .zip(doc.objects.get(id))
                    .is_some_and(|(old, new)| {
                        std::mem::discriminant(old) != std::mem::discriminant(new)
                    })
            }) {
                anomalies.push(Anomaly::RetypedObject);
            }
            if first_signer.is_some() {
                let allowed = match kind {
                    RevisionKind::Dss => dss_allowed(before, &doc, &ids),
                    RevisionKind::DocumentTimestamp => {
                        signed.is_some_and(|s| doc_timestamp_allowed(before, &doc, &ids, s))
                    }
                    _ => false,
                };
                if allowed {
                    modification = ModificationLevel::LtaUpdates;
                } else {
                    kind = RevisionKind::Other;
                    suspicious = true;
                }
            }
            // Re-emitting a catalog, page, or AcroForm object is normal for a
            // signed/archival revision. Flag only unexpected rewrites, not
            // every lawful incremental update as a duplicate anomaly.
            if kind == RevisionKind::Other && ids.iter().any(|id| before.objects.contains_key(id)) {
                anomalies.push(Anomaly::DuplicateObjectNumber);
            }
        }
        if signed.is_some_and(|s| s.kind == SignatureKind::Signature) && first_signer.is_none() {
            first_signer = Some(index);
        }
        revisions.push(RevisionReport {
            index,
            kind,
            byte_end: end as u64,
            signed_by: signed.map(|s| s.id.clone()),
        });
        previous = Some(doc);
    }
    (
        revisions,
        if suspicious {
            Modifications::Suspicious
        } else {
            Modifications::Clean(modification)
        },
        anomalies,
    )
}
