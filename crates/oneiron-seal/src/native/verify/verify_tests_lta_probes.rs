//! Verifier tests D: span-craft and probe archival tests, flate CRL, object limit, typeless and orphan signature tests.

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]
    use std::sync::Arc;

    use lopdf::{Document, LoadOptions, Object, Stream};

    use super::super::super::{cms, engine, pdf, profile};
    use super::super::verify_dss_core::dss_revision_end;
    use super::super::verify_sig_pipeline::collect_signatures;
    use super::super::verify_tests_fixtures_dss_a::tests::*;
    use super::super::verify_tests_time_lta_a::tests::*;
    use crate::api::{
        FetchPolicy, PadesProfile, PdfSealEngine, SealConfig, SealResourceLimits,
        SignatureAlgorithm, VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode,
    };
    use crate::error::{InputInvalidCode, SealError};

    /// Catalog body for hand-built revisions: the current catalog plus a
    /// /DSS key. Reads /Pages and /AcroForm from the revision state.
    fn catalog_body(state: &pdf::RevisionState, dss_num: Option<u32>) -> Vec<u8> {
        let pages = state
            .root_dict
            .get(b"Pages")
            .and_then(Object::as_reference)
            .unwrap();
        let af = state.acroform.unwrap();
        let dss = dss_num
            .map(|n| format!(" /DSS {n} 0 R"))
            .unwrap_or_default();
        format!(
            "<< /Type /Catalog /Pages {} {} R /AcroForm {} {} R{dss} >>",
            pages.0, pages.1, af.0, af.1
        )
        .into_bytes()
    }

    /// Parse as the verifier does and return (doc, doc-ts br_end) for the
    /// single DocTimeStamp in the file.
    fn doc_and_ts_br_end(bytes: &[u8]) -> (Document, u64) {
        let doc = Document::load_mem_with_options(
            bytes,
            LoadOptions {
                strict: true,
                max_decompressed_size: Some(SealResourceLimits::default().max_input_bytes),
                ..LoadOptions::default()
            },
        )
        .unwrap();
        let sigs = collect_signatures(&doc).unwrap();
        let ts = sigs.iter().find(|e| e.is_doc_ts).unwrap();
        (doc, ts.byte_range[2] + ts.byte_range[3])
    }

    pub(crate) fn base_input() -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/pdf-input/classic_1page.pdf",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    /// Probe A (the re-checker's first shape): one incremental revision
    /// carrying an effective /DSS, a DocTimeStamp dictionary BEFORE the /DSS
    /// objects in byte order, and filler objects after the newest
    /// DSS-related object. The doc-ts /ByteRange span2 ends exactly at the
    /// first filler object — the value dss_revision_end computes — which is
    /// BEFORE the revision's own xref/trailer. Returns (final bytes,
    /// anchors, br_end, revision xref offset, newest DSS-object offset).
    fn span_craft_fixture() -> (Vec<u8>, Vec<Vec<u8>>, u64, u64, u64) {
        let signer = test_ca("span-signer");
        let signer2 = test_ca("span-signer-two");
        let tsa = tsa_ca();
        let b1 = append_sig_revision(&base_input(), &signer, "span-a", Some(&tsa), AT_UNIX);
        let state = pdf::reparse_revision(&b1, &SealResourceLimits::default()).unwrap();
        let m = state.max_obj;
        let crl = build_crl(&signer, AT_UNIX - 60, Some(AT_UNIX + 3600), None, vec![]);
        let material = profile::DssMaterial {
            certs_der: vec![signer.cert_der.clone(), tsa.cert_der.clone()],
            ocsps_der: Vec::new(),
            crls_der: vec![crl],
        };
        // ts object first (m+1), then the DSS material (m+3..=dss_num);
        // m+2 is the /FT /Sig field binding the doc-ts (botfix7 P1: only
        // field-/V-reachable signature dictionaries are evaluated). The
        // effective /AcroForm keeps its existing fields and gains the
        // doc-ts field's reference — the field must also survive the NEXT
        // production revision's register_field, which rewrites /Fields from
        // the reparsed state (so the new reference must be IN the state).
        let (mut dss_objs, dss_num) = profile::build_dss_objects(&material, m + 3).unwrap();
        let (ts_body, br_rel, lt_rel) = doc_ts_body(64 * 1024);
        let field_body =
            format!("<< /FT /Sig /T (Span-DocTimeStamp) /V {} 0 R >>", m + 1).into_bytes();
        let cat_body = catalog_body(&state, Some(dss_num));
        let af = state.acroform.unwrap();
        let mut next_fields: Vec<String> = state
            .acroform_fields
            .iter()
            .filter_map(|o| o.as_reference().ok())
            .map(|r| format!("{} {} R", r.0, r.1))
            .collect();
        next_fields.push(format!("{} 0 R", m + 2));
        let af_body = format!("<< /Fields [{}] /SigFlags 3 >>", next_fields.join(" ")).into_bytes();
        let mut objs: Vec<(u32, Vec<u8>)> =
            vec![(m + 1, ts_body), (m + 2, field_body), (af.0, af_body)];
        objs.append(&mut dss_objs);
        objs.push((state.root.0, cat_body));
        let filler1 = dss_num + 1;
        objs.push((filler1, b"<< /Probe /FillerOne >>".to_vec()));
        objs.push((dss_num + 2, b"<< /Probe /FillerTwo >>".to_vec()));
        let (mut bytes, written) = emit_revision(&b1, &state, &objs, None);
        let at = |num: u32| written.iter().find(|w| w.0 == num).copied().unwrap();
        let (_, _, ts_body_start) = at(m + 1);
        let (_, x, _) = at(filler1);
        let newest_dss = at(state.root.0).1;
        let capacity = 64 * 1024;
        let lt = (ts_body_start as usize) + lt_rel;
        let gt = lt + 1 + capacity * 2;
        let br = [0, lt as u64, gt as u64 + 1, x - (gt as u64 + 1)];
        patch_br(&mut bytes, (ts_body_start as usize) + br_rel, br);
        let imprint = pdf::hash_byte_range(&bytes, br).unwrap();
        let token = mint_token(&tsa, &imprint, AT_UNIX);
        fill_contents(&mut bytes, lt, gt, &token);
        let rev_xref = pdf::last_startxref(&bytes).unwrap();
        let b3 = append_sig_revision(&bytes, &signer2, "span-b", None, 0);
        let anchors = vec![signer.cert_der, signer2.cert_der, tsa.cert_der];
        (b3, anchors, x, rev_xref, newest_dss)
    }

    #[test]
    fn probe_a_filler_span_craft_attests_every_evaluated_byte() {
        // Precondition: filler objects after the newest DSS-related object
        // let the doc-ts span2 stop at dss_revision_end BEFORE the owning
        // revision's xref/trailer. The gate passes — and the grant is SOUND:
        // every object the /DSS evaluation dereferences is in the measured
        // id set, so its offset is <= newest < dss_end == br_end and its
        // bytes sit inside the hashed spans (the only excluded range is the
        // /Contents gap inside the doc-ts object itself). The uncovered
        // filler/xref/trailer bytes feed no evidence evaluation; the xref
        // chain is attested by the final covering signature. Regression pin:
        // a gate change to revision-end semantics flips this honest-but-
        // unusual document to Invalid (dss_revision_end no longer == br_end).
        let (bytes, anchors, br_end, rev_xref, newest_dss) = span_craft_fixture();
        assert!(
            br_end < rev_xref,
            "span2 must stop before the revision xref"
        );
        let (doc, ts_br_end) = doc_and_ts_br_end(&bytes);
        assert_eq!(ts_br_end, br_end);
        assert_eq!(dss_revision_end(&doc, &bytes), Some(br_end));
        assert!(newest_dss < br_end);
        let engine = verify_engine(anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&bytes).unwrap();
        eprintln!(
            "PROBE-A br_end={br_end} dss_end={:?} rev_xref={rev_xref} newest_dss={newest_dss} -> {:?}",
            dss_revision_end(&doc, &bytes),
            report.achieved_profile
        );
        assert!(report.valid, "attested evidence must validate: {report:?}");
        assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineLta));
    }

    #[test]
    fn non_covering_doc_timestamp_confers_lt_not_lta() {
        // A VALID DocTimeStamp that does NOT cover the final /DSS keeps its
        // DocumentTimestamp check but must not confer B-LTA: fresh-at-clock
        // evidence plus a non-covering DTS classifies BaselineLt.
        let signer = test_ca("nc-signer");
        let signer2 = test_ca("nc-signer-two");
        let tsa = tsa_ca();
        let b1 = append_sig_revision(&base_input(), &signer, "nc-a", Some(&tsa), AT_UNIX);
        // DocTimeStamp BEFORE the /DSS revision: it cannot cover it.
        let b2 = append_doc_ts_revision(&b1, &tsa, AT_UNIX);
        // Evidence fresh at the VERIFY clock, so ValidationMaterial passes
        // without any archival time.
        let crl = build_crl(
            &signer,
            AT_UNIX - 60,
            Some(VERIFY_SECS + 3600),
            None,
            vec![],
        );
        let b3 = append_dss_revision(
            &b2,
            vec![signer.cert_der.clone(), tsa.cert_der.clone()],
            vec![crl],
        );
        let b4 = append_sig_revision(&b3, &signer2, "nc-b", None, 0);
        let anchors = vec![signer.cert_der, signer2.cert_der, tsa.cert_der];
        let engine = verify_engine(anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&b4).unwrap();
        assert!(report.valid, "fresh evidence must validate: {report:?}");
        let dts = report
            .checks
            .iter()
            .find(|c| c.kind == VerifyCheckKind::DocumentTimestamp)
            .unwrap();
        assert_eq!(dts.status, VerifyCheckStatus::Pass);
        assert_eq!(
            report.achieved_profile,
            Some(PadesProfile::BaselineLt),
            "a non-covering DocTimeStamp confers no archival rung"
        );
    }

    /// Probe B1 (dormant staging, activation by a LATER catalog /DSS key):
    /// /DSS objects sit in pre-timestamp revisions (covered by the doc-ts)
    /// but unnamed by the catalog; a post-timestamp revision's catalog
    /// update activates them. The gate must FAIL: the final trailer /Root
    /// object is itself in the measured id set, and the activating catalog
    /// instance lives past the doc-ts ByteRange end, so dss_revision_end
    /// exceeds br_end and the verification clock applies.
    #[test]
    fn probe_b1_late_catalog_activation_misses_archival_time() {
        let signer = test_ca("dorm-signer");
        let signer2 = test_ca("dorm-signer-two");
        let tsa = tsa_ca();
        let b1 = append_sig_revision(&base_input(), &signer, "dorm-a", Some(&tsa), AT_UNIX);
        let state = pdf::reparse_revision(&b1, &SealResourceLimits::default()).unwrap();
        let crl = build_crl(&signer, AT_UNIX - 60, Some(AT_UNIX + 3600), None, vec![]);
        let material = profile::DssMaterial {
            certs_der: vec![signer.cert_der.clone(), tsa.cert_der.clone()],
            ocsps_der: Vec::new(),
            crls_der: vec![crl],
        };
        let (dss_objs, dss_num) = profile::build_dss_objects(&material, state.max_obj + 1).unwrap();
        // Dormant staging: material objects only, no catalog /DSS key.
        let (b2, _) = emit_revision(&b1, &state, &dss_objs, None);
        let b3 = append_doc_ts_revision(&b2, &tsa, AT_UNIX);
        // Activation: a post-timestamp catalog update naming the staged DSS.
        let state4 = pdf::reparse_revision(&b3, &SealResourceLimits::default()).unwrap();
        let cat_body = catalog_body(&state4, Some(dss_num));
        let (b4, written4) = emit_revision(&b3, &state4, &[(state4.root.0, cat_body)], None);
        let cat_offset = written4[0].1;
        let b5 = append_sig_revision(&b4, &signer2, "dorm-b", None, 0);
        let anchors = vec![signer.cert_der, signer2.cert_der, tsa.cert_der];
        let (doc, ts_br_end) = doc_and_ts_br_end(&b5);
        let dss_end = dss_revision_end(&doc, &b5).unwrap();
        eprintln!(
            "PROBE-B1 ts_br_end={ts_br_end} dss_end={dss_end} activating_catalog@{cat_offset}"
        );
        assert!(cat_offset >= ts_br_end);
        assert!(
            dss_end > ts_br_end,
            "gate must measure the activating catalog"
        );
        let engine = verify_engine(anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&b5).unwrap();
        eprintln!("PROBE-B1 outcome -> {:?}", report.achieved_profile);
        assert!(!report.valid, "stale unattested evidence must not launder");
        assert_eq!(report.achieved_profile, None);
        let vm = report
            .checks
            .iter()
            .find(|c| c.kind == VerifyCheckKind::ValidationMaterial)
            .unwrap();
        assert_eq!(
            (vm.status, vm.finding),
            (
                VerifyCheckStatus::Fail,
                Some(VerifyFindingCode::ValidationMaterialInvalid)
            )
        );
    }

    /// Probe B2 (dormant staging, activation by trailer /Root switch): the
    /// staged bytes include a dormant ALTERNATE catalog C2 carrying the /DSS
    /// key; a post-timestamp revision only switches the trailer /Root to C2.
    /// The gate passes (every measured id resolves to a pre-timestamp
    /// offset) — and the grant is SOUND: the timestamp attests C2 and every
    /// /DSS object the evaluation reads; only the switching trailer is
    /// unattested by the doc-ts, and it is attested by the final covering
    /// signature. Regression pin: precondition dormant-staging; documents
    /// that the offset gate measures object identity, not activation time.
    #[test]
    fn probe_b2_root_switch_attests_staged_catalog_and_evidence() {
        let signer = test_ca("switch-signer");
        let signer2 = test_ca("switch-signer-two");
        let tsa = tsa_ca();
        let b1 = append_sig_revision(&base_input(), &signer, "switch-a", Some(&tsa), AT_UNIX);
        let state = pdf::reparse_revision(&b1, &SealResourceLimits::default()).unwrap();
        let m = state.max_obj;
        let crl = build_crl(&signer, AT_UNIX - 60, Some(AT_UNIX + 3600), None, vec![]);
        let material = profile::DssMaterial {
            certs_der: vec![signer.cert_der.clone(), tsa.cert_der.clone()],
            ocsps_der: Vec::new(),
            crls_der: vec![crl],
        };
        let (mut dss_objs, dss_num) = profile::build_dss_objects(&material, m + 1).unwrap();
        let c2_num = dss_num + 1;
        dss_objs.push((c2_num, catalog_body(&state, Some(dss_num))));
        // Dormant staging: C2 present in bytes, trailer /Root unchanged.
        let (b2, written2) = emit_revision(&b1, &state, &dss_objs, None);
        let c2_offset = written2.iter().find(|w| w.0 == c2_num).unwrap().1;
        let b3 = append_doc_ts_revision(&b2, &tsa, AT_UNIX);
        // Activation: trailer /Root switch only (one filler object carries
        // the revision; the doc-ts does not cover this revision).
        let state4 = pdf::reparse_revision(&b3, &SealResourceLimits::default()).unwrap();
        let filler = state4.max_obj + 1;
        let (b4, _) = emit_revision(
            &b3,
            &state4,
            &[(filler, b"<< /Probe /RootSwitch >>".to_vec())],
            Some((c2_num, 0)),
        );
        let b5 = append_sig_revision(&b4, &signer2, "switch-b", None, 0);
        let anchors = vec![signer.cert_der, signer2.cert_der, tsa.cert_der];
        let (doc, ts_br_end) = doc_and_ts_br_end(&b5);
        let dss_end = dss_revision_end(&doc, &b5).unwrap();
        eprintln!("PROBE-B2 ts_br_end={ts_br_end} dss_end={dss_end} staged_catalog_c2@{c2_offset}");
        assert!(c2_offset < ts_br_end, "C2 is staged pre-timestamp");
        assert!(dss_end <= ts_br_end, "gate passes over staged objects");
        let engine = verify_engine(anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&b5).unwrap();
        eprintln!("PROBE-B2 outcome -> {:?}", report.achieved_profile);
        assert!(
            report.valid,
            "attested staged evidence must validate: {report:?}"
        );
        assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineLta));
    }

    /// Probe C (the sharpening found while building A/B): the /CRLs array
    /// item is a REFERENCE CHAIN — a covered bare-reference object whose
    /// target stream is planted in a POST-timestamp revision (a placeholder
    /// reserves the object number pre-timestamp). The evaluation path
    /// (dss_array -> Document::dereference) follows chains, so the verifier
    /// reads the planted CRL; but dss_revision_end collected only the direct
    /// reference, so the terminal stream escaped the measured offsets, the
    /// gate passed, and stale-at-clock evidence validated at the archival
    /// genTime. WITHOUT the dss_revision_end chain-resolution fix this test
    /// FAILS (the document verifies BaselineLta): the mutation pin for the
    /// laundering hole. WITH the fix the gate measures the planted stream's
    /// post-timestamp offset and the verification clock applies.
    #[test]
    fn probe_c_reference_chain_cannot_smuggle_unattested_evidence() {
        let signer = test_ca("chain-signer");
        let signer2 = test_ca("chain-signer-two");
        let tsa = tsa_ca();
        let b1 = append_sig_revision(&base_input(), &signer, "chain-a", Some(&tsa), AT_UNIX);
        let state = pdf::reparse_revision(&b1, &SealResourceLimits::default()).unwrap();
        let m = state.max_obj;
        let crl = build_crl(&signer, AT_UNIX - 60, Some(AT_UNIX + 3600), None, vec![]);
        let (c1, c2, dss_n, link, hole) = (m + 1, m + 2, m + 3, m + 4, m + 5);
        let dss_body =
            format!("<< /Type /DSS /Certs [{c1} 0 R {c2} 0 R] /CRLs [{link} 0 R] >>").into_bytes();
        let objs = vec![
            (c1, stream_body(&signer.cert_der)),
            (c2, stream_body(&tsa.cert_der)),
            (dss_n, dss_body),
            (link, format!("{hole} 0 R").into_bytes()),
            (hole, b"null".to_vec()),
            (state.root.0, catalog_body(&state, Some(dss_n))),
        ];
        let (b2, _) = emit_revision(&b1, &state, &objs, None);
        let b3 = append_doc_ts_revision(&b2, &tsa, AT_UNIX);
        // Plant the terminal CRL stream AFTER the timestamp, overwriting the
        // placeholder: the doc-ts attests "null", the evaluation reads this.
        let state4 = pdf::reparse_revision(&b3, &SealResourceLimits::default()).unwrap();
        let (b4, written4) = emit_revision(&b3, &state4, &[(hole, stream_body(&crl))], None);
        let planted_offset = written4[0].1;
        let b5 = append_sig_revision(&b4, &signer2, "chain-b", None, 0);
        let anchors = vec![signer.cert_der, signer2.cert_der, tsa.cert_der];
        let (doc, ts_br_end) = doc_and_ts_br_end(&b5);
        let dss_end = dss_revision_end(&doc, &b5).unwrap();
        eprintln!("PROBE-C ts_br_end={ts_br_end} dss_end={dss_end} planted_crl@{planted_offset}");
        assert!(
            planted_offset >= ts_br_end,
            "planted evidence is post-timestamp"
        );
        let engine = verify_engine(anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&b5).unwrap();
        eprintln!("PROBE-C outcome -> {:?}", report.achieved_profile);
        assert!(
            dss_end > ts_br_end,
            "chain-resolved gate must measure the planted stream"
        );
        assert!(
            !report.valid,
            "unattested planted evidence laundered to {:?}",
            report.achieved_profile
        );
        assert_eq!(report.achieved_profile, None);
        let vm = report
            .checks
            .iter()
            .find(|c| c.kind == VerifyCheckKind::ValidationMaterial)
            .unwrap();
        assert_eq!(
            (vm.status, vm.finding),
            (
                VerifyCheckStatus::Fail,
                Some(VerifyFindingCode::ValidationMaterialInvalid)
            )
        );
    }

    // --- bot-fix leg 3b pins: DSS stream decode, object cap, typeless ----

    // --- signature discovery, hex whitespace in /Contents -----------------

    /// zlib wrapper around one final DEFLATE stored block (no compressor
    /// dependency needed for the fixture).
    pub(crate) fn zlib_store(data: &[u8]) -> Vec<u8> {
        assert!(u16::try_from(data.len()).is_ok());
        let len = data.len() as u16;
        let mut out = vec![0x78u8, 0x01, 0x01];
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(data);
        let (mut a, mut b) = (1u32, 0u32);
        for &x in data {
            a = (a + u32::from(x)) % 65521;
            b = (b + a) % 65521;
        }
        out.extend_from_slice(&((b << 16) | a).to_be_bytes());
        out
    }

    /// Mirror of `dss_doc` whose CRL entry rides a /FlateDecode stream.
    pub(crate) fn dss_doc_flate_crl(certs: &[Vec<u8>], crl_stream_bytes: Vec<u8>) -> Document {
        let mut doc = Document::with_version("1.4");
        let mut dss = lopdf::Dictionary::new();
        dss.set("Type", Object::Name(b"DSS".to_vec()));
        if !certs.is_empty() {
            let refs: Vec<Object> = certs
                .iter()
                .map(|d| {
                    let s = Stream::new(lopdf::Dictionary::new(), d.clone());
                    Object::Reference(doc.add_object(Object::Stream(s)))
                })
                .collect();
            dss.set("Certs", Object::Array(refs));
        }
        let mut crl_dict = lopdf::Dictionary::new();
        crl_dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        let crl_ref = Object::Reference(
            doc.add_object(Object::Stream(Stream::new(crl_dict, crl_stream_bytes))),
        );
        dss.set("CRLs", Object::Array(vec![crl_ref]));
        let dss_id = doc.add_object(Object::Dictionary(dss));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("DSS", Object::Reference(dss_id));
        let cat_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(cat_id));
        doc
    }

    #[test]
    fn dss_flate_wrapped_crl_validates() {
        // Filtered DSS evidence must be decoded before parsing: a
        // FlateDecode-wrapped CRL covering the chain validates exactly like
        // its raw form.
        let ca = test_ca("flate-dss-ca");
        let crl = build_crl(&ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc_flate_crl(std::slice::from_ref(&ca.cert_der), zlib_store(&crl));
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert!(
            checks.passed(VerifyCheckKind::ValidationMaterial),
            "FlateDecode-wrapped CRL evidence must validate"
        );
    }

    #[test]
    fn dss_broken_filter_stream_is_malformed_never_skipped() {
        // A stream whose declared filter cannot decode is Malformed, which
        // fails ValidationMaterial — never a silent skip to AbsentAllowed.
        let ca = test_ca("flate-broken-ca");
        let doc = dss_doc_flate_crl(std::slice::from_ref(&ca.cert_der), b"not zlib".to_vec());
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn verify_enforces_max_pdf_objects() {
        // The seal side rejects over-cap object counts; the verify side
        // must enforce the same configured cap.
        let signer = test_ca("objcap-signer");
        let bytes = append_sig_revision(&base_input(), &signer, "objcap", None, 0);
        let limits = SealResourceLimits {
            max_pdf_objects: 2,
            ..SealResourceLimits::default()
        };
        let engine = engine::NativeSealEngine::new(
            SealConfig {
                trust_anchors_der: vec![signer.cert_der],
                timestamp_authorities: Vec::new(),
                fetch_policy: FetchPolicy::default(),
                resource_limits: limits,
            },
            Arc::new(NoopBackend),
            Arc::new(NoopFetcher),
            Arc::new(ClockMs(VERIFY_SECS * 1000)),
        )
        .unwrap();
        let err = engine.verify_sealed_pdf(&bytes).unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: InputInvalidCode::ObjectLimitExceeded
            }
        ));
    }

    /// Signature dictionary body with patchable /ByteRange and /Contents,
    /// /Type optional (the typeless interop shape). Mirrors pdf's
    /// sig_dict_body. Returns (body, byterange_patch_rel, contents_lt_rel).
    fn sig_body_shaped(capacity: usize, typed: bool) -> (Vec<u8>, usize, usize) {
        let mut body = Vec::with_capacity(capacity * 2 + 256);
        body.extend_from_slice(b"<< ");
        if typed {
            body.extend_from_slice(b"/Type /Sig ");
        }
        body.extend_from_slice(
            b"/Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0 ",
        );
        let br_rel = body.len();
        for i in 0..3 {
            body.extend_from_slice(b"00000000000000000000");
            if i < 2 {
                body.push(b' ');
            }
        }
        body.extend_from_slice(b"] /Contents <");
        let lt_rel = body.len() - 1;
        body.extend(std::iter::repeat_n(b'0', capacity * 2));
        body.extend_from_slice(b"> >>");
        (body, br_rel, lt_rel)
    }

    /// Write the CMS DER hex into the gap with spec-legal whitespace (two
    /// spaces every 16 bytes — an even count, so the digit total stays
    /// even); the rest of the gap stays zero padding.
    fn fill_contents_spaced(out: &mut [u8], lt: usize, gt: usize, der: &[u8]) {
        let mut hex = String::new();
        for (i, b) in der.iter().enumerate() {
            if i > 0 && i % 16 == 0 {
                hex.push_str("  ");
            }
            hex.push_str(&format!("{b:02x}"));
        }
        assert!(hex.len() < gt - lt, "token exceeds contents capacity");
        out[lt + 1..lt + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    }

    /// Hand-emit one signature revision anchored through the production
    /// field-registration shape (the verifier discovers signatures through
    /// /AcroForm /Fields → field /V — botfix7 P1). The fixed-up revision is
    /// signature-shaped from the base input: fresh sig-dict bytes (the
    /// caller's shape), a field binding that dict by /V, and the AcroForm
    /// registration + catalog link on this revision, so the collected
    /// ByteRange measures the full final document.
    pub(crate) fn crafted_sig_revision(
        name: &str,
        typed: bool,
        spaced_hex: bool,
    ) -> (Vec<u8>, TestCa) {
        let signer = test_ca(name);
        let input = base_input();
        let state = pdf::reparse_revision(&input, &SealResourceLimits::default()).unwrap();
        let capacity = 64 * 1024;
        let (body, br_rel, lt_rel) = sig_body_shaped(capacity, typed);
        let sig_num = state.max_obj + 1;
        let field_num = sig_num + 1;
        let field = format!("<< /FT /Sig /T ({name}) /V {sig_num} 0 R >>");
        let acroform = format!("<< /Fields [{field_num} 0 R] /SigFlags 3 >>");
        let pages = state
            .root_dict
            .get(b"Pages")
            .and_then(Object::as_reference)
            .unwrap();
        let catalog = format!(
            "<< /Type /Catalog /Pages {} {} R /AcroForm {} 0 R >>",
            pages.0,
            pages.1,
            state.max_obj + 3
        );
        let objs = vec![
            (sig_num, body),
            (field_num, field.into_bytes()),
            (state.max_obj + 3, acroform.into_bytes()),
            (state.root.0, catalog.into_bytes()),
        ];
        let (mut bytes, written) = emit_revision(&input, &state, &objs, None);
        let (_, _, body_start) = written.iter().find(|w| w.0 == sig_num).copied().unwrap();
        let lt = (body_start as usize) + lt_rel;
        let gt = lt + 1 + capacity * 2;
        let total = bytes.len() as u64;
        let br = [0, lt as u64, gt as u64 + 1, total - (gt as u64 + 1)];
        patch_br(&mut bytes, (body_start as usize) + br_rel, br);
        let digest = pdf::hash_byte_range(&bytes, br).unwrap();
        let (issuer, serial) = cms::issuer_and_serial(&signer.cert_der).unwrap();
        let attrs = vec![
            cms::attr_content_type_data(),
            cms::attr_message_digest(&digest),
            cms::attr_signing_cert_v2(&signer.cert_der, &issuer, &serial),
        ];
        let (wire, signing) = cms::assemble_signed_attrs(attrs);
        let sig = sign_p256(&signer.key, &signing);
        let material = cms::SignerMaterial {
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            signer_cert_der: &signer.cert_der,
            issuer_name_der: &issuer,
            serial_der: &serial,
            chain_ders: &[],
        };
        let cms_der = cms::build_signed_data(&material, &wire, &sig, &[]);
        if spaced_hex {
            fill_contents_spaced(&mut bytes, lt, gt, &cms_der);
        } else {
            fill_contents(&mut bytes, lt, gt, &cms_der);
        }
        (bytes, signer)
    }

    #[test]
    fn typeless_signature_dictionary_verifies() {
        // Interop: real-world signers omit the optional /Type on the
        // signature dictionary. The /ByteRange + /Contents shape must be
        // discovered and verified, not silently skipped into "no cades".
        let (bytes, signer) = crafted_sig_revision("typeless-sig", false, false);
        let engine = verify_engine(vec![signer.cert_der], VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&bytes).unwrap();
        assert!(
            report.valid,
            "typeless signature doc must verify: {report:?}"
        );
        assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineB));
    }

    #[test]
    fn orphan_malformed_sig_dict_does_not_block_reachable_pin() {
        // botfix7 P1: a REACHABLE malformed partial shape (no /Contents)
        // still errors — the gate binds reached dictionaries only. An
        // unreachable copy of the same shape beside it is not consulted.
        let mut doc = Document::with_version("1.4");
        let mut partial = lopdf::Dictionary::new();
        partial.set(
            "ByteRange",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(1),
                Object::Integer(2),
                Object::Integer(3),
            ]),
        );
        let reachable_id = doc.add_object(Object::Dictionary(partial.clone()));
        // The unreachable twin: identical shape, never named by any field.
        doc.add_object(Object::Dictionary(partial));
        let mut field = lopdf::Dictionary::new();
        field.set("FT", Object::Name(b"Sig".to_vec()));
        field.set("V", Object::Reference(reachable_id));
        let field_id = doc.add_object(Object::Dictionary(field));
        let mut af = lopdf::Dictionary::new();
        af.set("Fields", Object::Array(vec![Object::Reference(field_id)]));
        let af_id = doc.add_object(Object::Dictionary(af));
        let mut pages = lopdf::Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![]));
        pages.set("Count", Object::Integer(0));
        let pages_id = doc.add_object(Object::Dictionary(pages));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        catalog.set("AcroForm", Object::Reference(af_id));
        let cat_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(cat_id));
        assert!(
            collect_signatures(&doc).is_err(),
            "the reachable partial shape must still be judged malformed"
        );
    }
}
