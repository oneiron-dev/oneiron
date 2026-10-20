//! DSS validation: Cert/CRL/OCSP array decoding, issuer binding and coverage rules, DSS-revision coverage measurement.

use lopdf::{Document, Object};

use crate::api::{Counter, VerifyCheckKind, VerifyFindingCode, note_current};

use super::super::pdf;
use super::verify_revocation::{crl_entry_valid, issued_by, ocsp_entry_valid};
use super::verify_sig_pipeline::Checks;

/// Validate the DSS revision when the catalog carries `/DSS` (§7.5/§7.7):
/// global arrays only, and every present entry must cryptographically
/// validate — CRLs against an embedded/anchored issuer cert with a fresh
/// thisUpdate/nextUpdate window and no in-scope serial on its revoked list,
/// OCSP responses with signature, responder authorization, cert-serial
/// binding, freshness, and a `good` cert status. The material must also
/// speak about the document's covered CMS signer/TSA chains: every covered
/// certificate must appear in `/Certs` or be a trust anchor. A present DSS
/// with no arrays at all is evidence-free and fails. Present-but-invalid
/// evidence fails ValidationMaterial; it is never AbsentAllowed. A trailer
/// `/Root` that cannot be read as a catalog (e.g. a spec-invalid direct
/// dictionary) is present-but-unreadable, not absent: it classifies
/// Invalid so a `/DSS` hidden inside it cannot dodge the failed-evidence
/// classification.
///
/// Each DSS stream decodes under `max_stream_bytes`, the per-stream bound
/// the caller sets (the verifier sets none: every stream decodes whole);
/// the material is read whole however much it decodes to in all (Rule 5).
/// Returns the bytes this extraction decoded, for the `[limits]` DSS-decode
/// row; the largest single stream goes to the running analysis's counts.
pub(super) fn verify_dss(
    doc: &Document,
    anchors: &[EmbeddedCert],
    covered: &[EmbeddedCert],
    at_unix: u64,
    max_stream_bytes: usize,
    checks: &mut Checks,
) -> usize {
    let mut decoded = 0;
    check_dss(
        doc,
        anchors,
        covered,
        at_unix,
        max_stream_bytes,
        &mut decoded,
        checks,
    );
    decoded
}

/// [`verify_dss`], adding what it decodes to `decoded`.
fn check_dss(
    doc: &Document,
    anchors: &[EmbeddedCert],
    covered: &[EmbeddedCert],
    at_unix: u64,
    max_stream_bytes: usize,
    decoded: &mut usize,
    checks: &mut Checks,
) {
    let catalog = match pdf::catalog(doc) {
        Some(c) => c,
        None => {
            if doc.trailer.has(b"Root") {
                checks.record(
                    VerifyCheckKind::ValidationMaterial,
                    false,
                    VerifyFindingCode::ValidationMaterialInvalid,
                );
            } else {
                checks.absent(VerifyCheckKind::ValidationMaterial);
            }
            return;
        }
    };
    let Ok(dss_obj) = catalog.get(b"DSS") else {
        checks.absent(VerifyCheckKind::ValidationMaterial);
        return;
    };
    let dss = pdf::resolve(doc, dss_obj).and_then(|o| o.as_dict().ok());
    let Some(dss) = dss else {
        checks.record(
            VerifyCheckKind::ValidationMaterial,
            false,
            VerifyFindingCode::ValidationMaterialInvalid,
        );
        return;
    };
    if dss.has(b"VRI") {
        checks.record(
            VerifyCheckKind::ValidationMaterial,
            false,
            VerifyFindingCode::ValidationMaterialInvalid,
        );
        return;
    }
    let ok = dss_material_valid(
        doc,
        dss,
        anchors,
        covered,
        at_unix,
        max_stream_bytes,
        decoded,
    );
    checks.record(
        VerifyCheckKind::ValidationMaterial,
        ok,
        VerifyFindingCode::ValidationMaterialInvalid,
    );
}

fn dss_material_valid(
    doc: &Document,
    dss: &lopdf::Dictionary,
    anchors: &[EmbeddedCert],
    covered: &[EmbeddedCert],
    at_unix: u64,
    max_stream_bytes: usize,
    decoded: &mut usize,
) -> bool {
    // Each entry decodes under the per-stream codec bound; the total across
    // all three arrays is counted, never capped, so material past the old
    // shared budget is read whole rather than called malformed.
    let certs = dss_array(doc, dss, b"Certs", max_stream_bytes, decoded);
    let crls = dss_array(doc, dss, b"CRLs", max_stream_bytes, decoded);
    let ocsps = dss_array(doc, dss, b"OCSPs", max_stream_bytes, decoded);
    // A present DSS with all arrays absent is evidence-free: it must not
    // inflate a B-T document into B-LT.
    if matches!(certs, DssArray::Absent)
        && matches!(crls, DssArray::Absent)
        && matches!(ocsps, DssArray::Absent)
    {
        return false;
    }
    // /Certs first: CRL and OCSP issuer lookups draw from it. A
    // present-but-empty array breaks profile completeness.
    let embedded: Vec<EmbeddedCert> = match certs {
        DssArray::Absent => Vec::new(),
        DssArray::Malformed => return false,
        DssArray::Entries(entries) => {
            if entries.is_empty() {
                return false;
            }
            let mut v = Vec::with_capacity(entries.len());
            for e in &entries {
                let Some(c) = EmbeddedCert::from_der(e) else {
                    return false;
                };
                v.push(c);
            }
            v
        }
    };
    // Binding (§7.5 step 3): the validation set (embedded + anchors) must
    // include every certificate of the CMS signer/TSA chains this report
    // covers; unrelated /Certs must not authenticate the material.
    let bound = covered.iter().all(|c| {
        embedded
            .iter()
            .chain(anchors.iter())
            .any(|e| e.der == c.der)
    });
    if !bound {
        return false;
    }
    // Every CRL entry must be valid; collect the key-bound issuer certs the
    // valid CRLs authenticated under so the coverage rule below can match
    // them against each covered certificate's ACTUAL issuer (name+key).
    let crl_issuers: Vec<&EmbeddedCert> = match crls {
        DssArray::Absent => Vec::new(),
        DssArray::Malformed => return false,
        DssArray::Entries(entries) => {
            if entries.is_empty() {
                return false;
            }
            let mut v = Vec::with_capacity(entries.len());
            for e in &entries {
                let Some(issuer) = crl_entry_valid(e, &embedded, anchors, covered, at_unix) else {
                    return false;
                };
                v.push(issuer);
            }
            v
        }
    };
    // Every OCSP entry must be valid; collect the DERs of the target
    // certificates the valid responses bind to with a `good` status.
    let mut ocsp_targets: Vec<Vec<u8>> = Vec::new();
    match ocsps {
        DssArray::Absent => {}
        DssArray::Malformed => return false,
        DssArray::Entries(entries) => {
            if entries.is_empty() {
                return false;
            }
            for e in &entries {
                let Some(targets) = ocsp_entry_valid(e, &embedded, anchors, at_unix) else {
                    return false;
                };
                ocsp_targets.extend(targets);
            }
        }
    }
    // Revocation coverage (§7.5 steps 2-3): every covered NON-ANCHOR chain
    // certificate needs at least one valid evidence item speaking ABOUT it
    // — a CRL whose key-bound issuer is that certificate's ACTUAL issuer
    // (the covered cert's own signature verifies under the CRL-signing
    // key) or an OCSP SingleResponse bound to it with `cert_status` good.
    // Anchor certificates ride anchor trust and need no coverage. A
    // cert-only DSS, evidence about an irrelevant issuer, or evidence
    // authenticated by a same-subject/different-key shadow fails here —
    // never AbsentAllowed.
    let covered_ok = covered.iter().all(|c| {
        if anchors.iter().any(|a| a.der == c.der) {
            return true;
        }
        crl_issuers.iter().any(|i| issued_by(c, i)) || ocsp_targets.contains(&c.der)
    });
    if !covered_ok {
        return false;
    }
    true
}

/// A parsed certificate with its source DER (signature verification takes
/// the DER form).
pub(crate) struct EmbeddedCert {
    pub(super) der: Vec<u8>,
    pub(super) cert: x509_cert::Certificate,
}

impl EmbeddedCert {
    pub(crate) fn from_der(der_bytes: &[u8]) -> Option<Self> {
        use der::Decode;
        Some(Self {
            der: der_bytes.to_vec(),
            cert: x509_cert::Certificate::from_der(der_bytes).ok()?,
        })
    }
}

pub(super) enum DssArray {
    Absent,
    Entries(Vec<Vec<u8>>),
    Malformed,
}

/// Extract the decoded stream contents of one DSS array. Filtered streams
/// (e.g. a FlateDecode-wrapped CRL) are decoded through the bounded
/// decompression path; a malformed filter, a failed decode, or one stream
/// expanding past `max_stream_bytes` (a bound only a caller that sets one
/// holds; the verifier decodes whole) is Malformed, never a silent skip.
/// Every decoded length is added to `decoded`, the extraction's total,
/// which no bound stops, and noted as one stream's.
pub(super) fn dss_array(
    doc: &Document,
    dss: &lopdf::Dictionary,
    key: &[u8],
    max_stream_bytes: usize,
    decoded: &mut usize,
) -> DssArray {
    let Ok(arr_obj) = dss.get(key) else {
        return DssArray::Absent;
    };
    let Some(arr) = pdf::resolve(doc, arr_obj).and_then(|o| o.as_array().ok()) else {
        return DssArray::Malformed;
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let Some(stream) = pdf::resolve(doc, item).and_then(|o| o.as_stream().ok()) else {
            return DssArray::Malformed;
        };
        let Ok(data) = stream.decompressed_content_with_limit(max_stream_bytes) else {
            return DssArray::Malformed;
        };
        note_current(Counter::StreamDecodeBytes, data.len());
        *decoded = decoded.saturating_add(data.len());
        out.push(data);
    }
    DssArray::Entries(out)
}

/// Follow a reference chain exactly as the evaluation's resolver does,
/// recording every traversed object id (link and target alike) into a set
/// shared across all chains, so repetitions of one chain collapse to its
/// unique objects. A chain is followed whole however long (Rule 5): a link
/// met twice in this chain is a cycle, and a missing object a dangling
/// link; either leaves the terminal object's coverage unprovable (`None`)
/// and the caller fails closed. An id already in `ids` was reached by a
/// chain collected whole before, so the rest of this one is there too: the
/// walk stops at it, and N occurrences of one deep chain cost N steps, not
/// N times its length. `work` counts the steps of every chain, for the
/// `[limits]` DSS reference-work row.
pub(super) fn collect_reference_chain(
    doc: &Document,
    id: lopdf::ObjectId,
    ids: &mut std::collections::BTreeSet<lopdf::ObjectId>,
    work: &mut usize,
) -> Option<()> {
    let mut chain = std::collections::BTreeSet::new();
    let mut current = id;
    loop {
        *work = work.saturating_add(1);
        if ids.contains(&current) {
            break;
        }
        if !chain.insert(current) {
            return None;
        }
        let Ok(next) = doc.objects.get(&current)?.as_reference() else {
            break;
        };
        current = next;
    }
    ids.extend(chain);
    Some(())
}

/// Byte offset the effective `/DSS` revision provably ends before: the
/// smallest xref-table offset beyond the newest DSS-related object (the
/// final catalog, the `/DSS` dictionary, and its `/Certs` `/OCSPs` `/CRLs`
/// array and stream objects), or the final `startxref` when no later object
/// exists. Objects of one revision precede that revision's xref, so a
/// DocTimeStamp whose ByteRange end reaches this offset covers every byte
/// of the revision the `/DSS` lives in; an earlier end validates evidence
/// no timestamp attests. `None` when coverage is unprovable (no `/DSS`,
/// compressed or missing xref entries, unparsable catalog): the
/// archival-time selection must then fall back to the verification clock so
/// stale evidence fails instead of laundering through an unrelated old
/// timestamp.
///
/// The measured id set must mirror the EVALUATION dereference paths exactly:
/// the shared resolver follows reference CHAINS whole, so every traversed
/// object is collected — a bare-reference link collected without its target
/// would let terminal evidence sit past the measured offsets, planted in a
/// revision no DocTimeStamp attests (probe_c regression). The evaluation
/// and this measurement resolve through the same uncapped walk, so neither
/// stops where the other goes on.
pub(super) fn dss_revision_end(doc: &Document, bytes: &[u8]) -> Option<u64> {
    let mut work = 0usize;
    let collected = dss_object_ids(doc, &mut work);
    note_current(Counter::DssReferenceWork, work);
    let ids = collected?;
    let mut newest = None;
    for (num, generation) in ids {
        match doc.reference_table.get(num) {
            Some(lopdf::xref::XrefEntry::Normal {
                offset,
                generation: g,
            }) if *g == generation => {
                let offset = u64::from(*offset);
                newest = Some(newest.map_or(offset, |n: u64| n.max(offset)));
            }
            _ => return None, // compressed or missing: coverage unprovable
        }
    }
    let newest = newest?;
    doc.reference_table
        .entries
        .values()
        .filter_map(|e| match e {
            lopdf::xref::XrefEntry::Normal { offset, .. } => Some(u64::from(*offset)),
            _ => None,
        })
        .filter(|o| *o > newest)
        .min()
        .or_else(|| pdf::last_startxref(bytes).ok())
}

/// Every object id the effective `/DSS` reaches through the chains the
/// evaluation follows: the trailer's `/Root` and catalog, the `/DSS`
/// dictionary, and its `/Certs` `/OCSPs` `/CRLs` arrays and their entries.
/// `work` counts the reference steps taken, on a failed measurement too.
fn dss_object_ids(
    doc: &Document,
    work: &mut usize,
) -> Option<std::collections::BTreeSet<lopdf::ObjectId>> {
    let catalog = pdf::catalog(doc)?;
    let dss_obj = catalog.get(b"DSS").ok()?;
    let mut ids: std::collections::BTreeSet<lopdf::ObjectId> = std::collections::BTreeSet::new();
    if let Ok(root) = doc.trailer.get(b"Root").and_then(Object::as_reference) {
        collect_reference_chain(doc, root, &mut ids, work)?;
    }
    if let Object::Reference(id) = dss_obj {
        collect_reference_chain(doc, *id, &mut ids, work)?;
    }
    let dss = pdf::resolve(doc, dss_obj).and_then(|o| o.as_dict().ok())?;
    for key in [b"Certs".as_slice(), b"OCSPs".as_slice(), b"CRLs".as_slice()] {
        let Ok(arr_obj) = dss.get(key) else {
            continue;
        };
        if let Object::Reference(id) = arr_obj {
            collect_reference_chain(doc, *id, &mut ids, work)?;
        }
        let Some(arr) = pdf::resolve(doc, arr_obj).and_then(|o| o.as_array().ok()) else {
            continue;
        };
        for item in arr {
            if let Object::Reference(id) = item {
                collect_reference_chain(doc, *id, &mut ids, work)?;
            }
        }
    }
    Some(ids)
}
