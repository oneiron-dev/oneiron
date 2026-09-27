//! Bounded revision snapshots and default-deny classification of post-sign changes.
//! A lawful LTA append may add only DSS evidence or a validated document
//! timestamp. No unknown PDF object type is allowed by default.
use std::collections::BTreeSet;

use super::super::pdf;
use super::verify_evidence::EnvelopeEvidence;
use crate::api::SealResourceLimits;
use crate::api::{
    Anomaly, ModificationLevel, Modifications, RevisionKind, RevisionReport, SignatureKind,
    VerifyCheck, VerifyCheckKind, VerifyCheckStatus,
};
use lopdf::{Document, Object, ObjectId};

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
/// Only the section's actual native xref STREAM is infrastructure. A new
/// object declaring `/Type /XRef` elsewhere is still an unknown change.
fn is_written_xref_stream(before: &Document, after: &Document, id: ObjectId) -> bool {
    let Some(Object::Stream(stream)) = after.objects.get(&id) else {
        return false;
    };
    if !matches!(after.reference_table.get(id.0),
        Some(lopdf::xref::XrefEntry::Normal { offset, generation })
            if *generation == id.1 && *offset as usize == after.xref_start)
    {
        return false;
    }
    let d = &stream.dict;
    if d.iter().any(|(key, _)| {
        ![
            b"Type".as_slice(),
            b"W",
            b"Index",
            b"Size",
            b"Prev",
            b"Root",
            b"Info",
            b"ID",
            b"Length",
        ]
        .contains(&key.as_slice())
    }) {
        return false;
    }
    matches!(d.get(b"Type"), Ok(Object::Name(n)) if n == b"XRef")
        && matches!(d.get(b"Length"), Ok(Object::Integer(n))
            if usize::try_from(*n).ok() == Some(stream.content.len()))
        && matches!(d.get(b"Prev"), Ok(Object::Integer(n))
            if usize::try_from(*n).ok() == Some(before.xref_start))
        && matches!(d.get(b"Size"), Ok(Object::Integer(n)) if *n > 0)
        && d.get(b"Root").ok() == after.trailer.get(b"Root").ok()
        && matches!(d.get(b"W"), Ok(Object::Array(w))
            if w.as_slice() == [Object::Integer(1), Object::Integer(8), Object::Integer(2)])
        && matches!(d.get(b"Index"), Ok(Object::Array(index))
            if !index.is_empty() && index.len() % 2 == 0
                && index.iter().all(|v| matches!(v, Object::Integer(n) if *n >= 0)))
}

fn without(dict: &lopdf::Dictionary, keys: &[&[u8]]) -> lopdf::Dictionary {
    let mut clone = dict.clone();
    for key in keys {
        clone.remove(key);
    }
    clone
}
/// Native incremental appends preserve effective document metadata. `/Size`
/// and xref-stream decoding/index fields are structural; every other trailer
/// entry (notably `/Root`, `/Info`, `/ID`) must remain byte-for-byte equal.
fn preserves_trailer(before: &Document, after: &Document) -> bool {
    let structural = [
        b"Size".as_slice(),
        b"Prev",
        b"Type",
        b"W",
        b"Index",
        b"Length",
        b"Filter",
        b"DecodeParms",
    ];
    let mut old = before.trailer.clone();
    let mut new = after.trailer.clone();
    for key in structural {
        old.remove(key);
        new.remove(key);
    }
    old == new
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
    if !preserves_trailer(before, after)
        || without(old_catalog, &[b"DSS"]) != without(new_catalog, &[b"DSS"])
    {
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
            let Object::Stream(stream) = obj else {
                return false;
            };
            // The native DSS writer emits only an exact-length stream.
            // An extra dictionary key is not an engine renewal shape.
            if stream.dict.len() != 1
                || !matches!(stream.dict.get(b"Length"), Ok(Object::Integer(n))
                    if usize::try_from(*n).ok() == Some(stream.content.len()))
            {
                return false;
            }
            allowed.insert(id);
        }
    }
    ids.iter().all(|id| {
        (allowed.contains(id)
            && (!before.objects.contains_key(id) || Some(*id) == catalog_id(after)))
            || (!before.objects.contains_key(id) && is_written_xref_stream(before, after, *id))
    })
}

fn doc_timestamp_allowed(
    before: &Document,
    after: &Document,
    ids: &BTreeSet<ObjectId>,
    sig_kind: SignatureKind,
    sig_checks: &[VerifyCheck],
) -> bool {
    if sig_kind != SignatureKind::DocumentTimestamp
        || sig_checks.iter().all(|c| {
            c.kind != VerifyCheckKind::DocumentTimestamp || c.status != VerifyCheckStatus::Pass
        })
    {
        return false;
    }
    let (Some(old_catalog), Some(new_catalog)) = (before.catalog().ok(), after.catalog().ok())
    else {
        return false;
    };
    if !preserves_trailer(before, after)
        || without(old_catalog, &[b"AcroForm"]) != without(new_catalog, &[b"AcroForm"])
    {
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
    if ts.len() != 5
        || !matches!(ts.get(b"Type"), Ok(Object::Name(n)) if n == b"DocTimeStamp")
        || !matches!(ts.get(b"Filter"), Ok(Object::Name(n)) if n == b"Adobe.PPKLite")
        || !matches!(ts.get(b"SubFilter"), Ok(Object::Name(n)) if n == b"ETSI.RFC3161")
        || !matches!(ts.get(b"ByteRange"), Ok(Object::Array(items)) if items.len() == 4)
        || !matches!(ts.get(b"Contents"), Ok(Object::String(..)))
    {
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
            || (!before.objects.contains_key(id) && is_written_xref_stream(before, after, *id))
    })
}

/// A classification failure is NotRun, never Clean. Unknown changed objects
/// are Suspicious even when their signature bytes still verify.
pub(super) fn classify(
    bytes: &[u8],
    signatures: &[EnvelopeEvidence],
    ends: Option<&[usize]>,
    limits: &SealResourceLimits,
) -> (Vec<RevisionReport>, Modifications, Vec<Anomaly>) {
    let Some(ends) = ends else {
        return (vec![], Modifications::NotRun, vec![]);
    };
    let mut revisions = Vec::new();
    let mut anomalies = Vec::new();
    let mut previous: Option<Document> = None;
    let mut first_signer = None;
    let mut modification = ModificationLevel::None;
    let mut suspicious = false;
    let mut work = 0usize;
    for (index, end) in ends.iter().copied().enumerate() {
        work = work.saturating_add(end);
        if work > 2 * 1024 * 1024 * 1024 {
            return (revisions, Modifications::NotRun, anomalies);
        }
        let Some(doc) = pdf::load_snapshot(&bytes[..end], limits) else {
            return (revisions, Modifications::NotRun, anomalies);
        };
        let signed = signatures
            .iter()
            .find(|s| s.revision.is_some_and(|r| r.index == index));
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
                    RevisionKind::DocumentTimestamp => signed.is_some_and(|s| {
                        doc_timestamp_allowed(before, &doc, &ids, s.kind, &s.checks)
                    }),
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
    // Missing ownership cannot mean "no modifications". A valid discovered
    // envelope must bind to a proven revision before we can classify appends.
    if signatures.iter().any(|s| {
        s.byte_range.well_formed
            && !revisions
                .iter()
                .any(|r| r.signed_by.as_deref() == Some(s.id.as_str()))
    }) {
        return (revisions, Modifications::NotRun, anomalies);
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test fixture construction is infallible here"
    )]
    use super::super::verify_tests_fixtures_dss_a::tests::{AT_UNIX, test_ca};
    use super::super::verify_tests_lta_probes::tests::base_input;
    use super::super::verify_tests_time_lta_a::tests::{
        append_doc_ts_revision, append_sig_revision, tsa_ca, verify_engine,
    };
    use super::*;
    use crate::api::PdfSealEngine;

    #[test]
    fn fake_xref_tag_cannot_waive_doc_timestamp_whitelist() {
        let signer = test_ca("ts-fake-xref");
        let tsa = tsa_ca();
        let signed = append_sig_revision(&base_input(), &signer, "ts-fake-xref", None, AT_UNIX);
        let stamped = append_doc_ts_revision(&signed, &tsa, AT_UNIX);
        let engine = verify_engine(vec![signer.cert_der, tsa.cert_der], AT_UNIX);
        let report = engine.verify_sealed_pdf(&stamped).unwrap();
        let before = Document::load_mem(&signed).unwrap();
        let mut after = Document::load_mem(&stamped).unwrap();
        let mut ids = changed(&before, &after).unwrap();
        assert!(doc_timestamp_allowed(
            &before,
            &after,
            &ids,
            report.signatures[1].kind,
            &report.signatures[1].checks
        ));
        let fake_id = (
            after.trailer.get(b"Size").unwrap().as_i64().unwrap() as u32,
            0,
        );
        let mut fake = lopdf::Dictionary::new();
        fake.set("Type", Object::Name(b"XRef".to_vec()));
        fake.set("Unknown", Object::string_literal("changed"));
        after.objects.insert(fake_id, Object::Dictionary(fake));
        ids.insert(fake_id);
        assert!(!doc_timestamp_allowed(
            &before,
            &after,
            &ids,
            report.signatures[1].kind,
            &report.signatures[1].checks
        ));
    }
}
