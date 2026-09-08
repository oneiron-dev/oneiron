//! Verifier tests C: skew and freshness tests, DocTimeStamp covered-set tests, LTA fixture and revision-append helpers.

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]
    use std::sync::Arc;

    use der::{Decode, Encode};

    use super::super::super::{cms, engine, pdf, profile, tsp};
    use super::super::verify_revocation::TS_GEN_TIME_MAX_SKEW_SECS;
    use super::super::verify_sig_pipeline::{Checks, SigEntry, verify_doc_ts};
    use super::super::verify_tests_dss_b::tests::*;
    use super::super::verify_tests_fixtures_dss_a::tests::*;
    use super::super::verify_tests_lta_probes::tests::*;
    use super::super::*;
    use crate::api::{
        BackendError, BackendSignature, FetchError, FetchPolicy, FetchRequest, FetchResponse,
        PadesProfile, PdfSealEngine, SealBackend, SealClock, SealConfig, SealFetcher,
        SealResourceLimits, Sha256Digest, SignDigestRequest, SignatureAlgorithm, SigningIdentity,
        VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode,
    };

    #[test]
    fn validate_response_rejects_over_skew_gen_time() {
        // The seal-side response path applies the SAME clock bound as the
        // verify path: an over-skew token must be refused at validation so
        // TSA failover (or profile degradation) stays available, instead of
        // the seal embedding a token its own self-verify rejects.
        let tsa = tsa_ca();
        let imprint = [9u8; 32];
        let nonce = [7u8; 16];
        let anchors = anchors_of(&tsa);
        let wrap_granted = |token: &[u8]| {
            let mut body = cms::tlv(0x30, &cms::tlv(0x02, &[0]));
            body.extend_from_slice(token);
            cms::tlv(0x30, &body)
        };
        let over = mint_token_custom(
            &tsa,
            &imprint,
            AT_UNIX + TS_GEN_TIME_MAX_SKEW_SECS + 1,
            true,
            Some(nonce),
            false,
        );
        assert!(
            tsp::validate_response(
                &wrap_granted(&over),
                &imprint,
                &nonce,
                None,
                &anchors,
                AT_UNIX * 1000,
            )
            .is_err(),
            "over-skew genTime must fail the seal-side response path"
        );
        // Within skew passes: TSA and sealer clocks are not assumed
        // synchronized.
        let near = mint_token_custom(
            &tsa,
            &imprint,
            AT_UNIX + TS_GEN_TIME_MAX_SKEW_SECS - 1,
            true,
            Some(nonce),
            false,
        );
        assert!(
            tsp::validate_response(
                &wrap_granted(&near),
                &imprint,
                &nonce,
                None,
                &anchors,
                AT_UNIX * 1000,
            )
            .is_ok(),
            "within-skew genTime must pass the seal-side response path"
        );
    }

    #[test]
    fn future_dated_ts_token_is_rejected_within_skew_passes() {
        // genTime ahead of the verify clock past the documented skew anchors
        // the applicable time in the future: rejected, never clamped.
        let signer = test_ca("skew-signer");
        let tsa = tsa_ca();
        let input = base_input();
        let anchors = vec![signer.cert_der.clone(), tsa.cert_der.clone()];
        let future = append_sig_revision(
            &input,
            &signer,
            "skew-a",
            Some(&tsa),
            AT_UNIX + TS_GEN_TIME_MAX_SKEW_SECS + 1,
        );
        let engine = verify_engine(anchors, AT_UNIX);
        let report = engine.verify_sealed_pdf(&future).unwrap();
        assert!(!report.valid, "future-dated token must fail verification");
        let ts = report
            .checks
            .iter()
            .find(|c| c.kind == VerifyCheckKind::SignatureTimestamp)
            .unwrap();
        assert_eq!(
            (ts.status, ts.finding),
            (
                VerifyCheckStatus::Fail,
                Some(VerifyFindingCode::TimestampInvalid)
            )
        );
        // Within skew: TSA/verifier clocks are not assumed synchronized.
        let near = append_sig_revision(
            &input,
            &signer,
            "skew-b",
            Some(&tsa),
            AT_UNIX + TS_GEN_TIME_MAX_SKEW_SECS - 1,
        );
        let report = engine.verify_sealed_pdf(&near).unwrap();
        assert!(report.valid, "within-skew token must pass: {report:?}");
        assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineT));
    }

    #[test]
    fn future_dated_doc_timestamp_is_rejected() {
        // The DocTimeStamp genTime feeds archival evidence freshness; a
        // future-dated one must fail, not launder stale evidence.
        let signer = test_ca("dts-skew-signer");
        let tsa = tsa_ca();
        let input = base_input();
        let b1 = append_sig_revision(&input, &signer, "dts-skew", Some(&tsa), AT_UNIX);
        let b2 = append_doc_ts_revision(&b1, &tsa, AT_UNIX + TS_GEN_TIME_MAX_SKEW_SECS + 1);
        let engine = verify_engine(vec![signer.cert_der, tsa.cert_der], AT_UNIX);
        let report = engine.verify_sealed_pdf(&b2).unwrap();
        let dts = report
            .checks
            .iter()
            .find(|c| c.kind == VerifyCheckKind::DocumentTimestamp)
            .unwrap();
        assert_eq!(
            (dts.status, dts.finding),
            (
                VerifyCheckStatus::Fail,
                Some(VerifyFindingCode::DocumentTimestampInvalid)
            ),
            "future-dated DocTimeStamp must fail its check"
        );
        assert!(!report.valid);
    }

    #[test]
    fn dss_crl_issuer_key_usage_without_crl_sign_fails() {
        // Key verification is not authorization: a CRL signed by a cert
        // whose KeyUsage lacks cRLSign fails even though its signature
        // verifies against that cert's key.
        let issuer = ca_with_kus("no-crlsign", vec![rcgen::KeyUsagePurpose::DigitalSignature]);
        let crl = build_crl(&issuer, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc(std::slice::from_ref(&issuer.cert_der), &[crl], &[]);
        let covered = covered_of(&[&issuer.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
        // Control: the same shape with cRLSign asserted is accepted.
        let ok_issuer = ca_with_kus(
            "with-crlsign",
            vec![
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::CrlSign,
            ],
        );
        let crl = build_crl(
            &ok_issuer,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            None,
            vec![],
        );
        let doc = dss_doc(std::slice::from_ref(&ok_issuer.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ok_issuer.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert!(
            checks.passed(VerifyCheckKind::ValidationMaterial),
            "cRLSign-authorized CRL must pass"
        );
    }

    #[test]
    fn rejected_doc_ts_leaves_no_trace_in_covered() {
        // A DocTimeStamp whose ByteRange is malformed must not extend the
        // DSS binding set, even when its token would validate.
        let tsa = tsa_ca();
        let anchors = anchors_of(&tsa);
        let bytes = b"%PDF-fake-body-for-hash";
        let entry = SigEntry {
            is_doc_ts: true,
            byte_range: [4, 2, 10, 4], // s1 != 0: ByteRange check fails
            contents: {
                // Token over the (well-formed) span digest: it WOULD
                // validate — the rejection comes from the ByteRange alone.
                let mut spans = Vec::new();
                spans.extend_from_slice(&bytes[4..6]);
                spans.extend_from_slice(&bytes[10..14]);
                mint_token(&tsa, &cms::sha256(&spans), AT_UNIX)
            },
        };
        let mut checks = Checks::new();
        let mut covered: Vec<EmbeddedCert> = Vec::new();
        let got = verify_doc_ts(
            bytes,
            &entry,
            &anchors,
            &mut checks,
            false,
            &mut covered,
            AT_UNIX * 1000,
        );
        assert!(got.is_none(), "bad ByteRange rejects the DocTimeStamp");
        assert!(
            covered.is_empty(),
            "a rejected DocTimeStamp leaves its TSA chain out of the binding set"
        );
    }

    // --- archival-time /DSS coverage binding: end-to-end through ----------

    // --- verify_sealed_pdf (the gap that let the bypass through) ----------

    /// Verify clock for the regression: two hours after the seal/archival
    /// time so evidence fresh at AT_UNIX is stale by then.
    pub(crate) const VERIFY_SECS: u64 = AT_UNIX + 7200;

    /// A TSA identity: end entity with exactly one critical
    /// id-kp-timeStamping EKU (RFC 3161 §2.3).
    pub(crate) fn tsa_ca() -> TestCa {
        use p256::pkcs8::DecodePrivateKey;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-tsa".to_string());
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let eku = cms::tlv(
            0x30,
            &cms::oid_tlv(&der::asn1::ObjectIdentifier::new_unwrap(
                "1.3.6.1.5.5.7.3.8",
            )),
        );
        let mut ext = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 37], eku);
        ext.set_criticality(true);
        params.custom_extensions.push(ext);
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        TestCa {
            cert_der,
            cert,
            key,
            rcgen_params: params,
            rcgen_key: key_pair,
        }
    }

    fn alg_id(oid: der::asn1::ObjectIdentifier, with_null: bool) -> Vec<u8> {
        let mut body = cms::oid_tlv(&oid);
        if with_null {
            body.extend_from_slice(&[0x05, 0x00]);
        }
        cms::tlv(0x30, &body)
    }

    /// Mint a TimeStampToken ContentInfo over `imprint` (RFC 3161, detached
    /// signature shape with eContent TSTInfo), signed by `tsa`.
    pub(crate) fn mint_token(tsa: &TestCa, imprint: &Sha256Digest, gen_time: u64) -> Vec<u8> {
        mint_token_custom(tsa, imprint, gen_time, true, None, false)
    }

    /// `mint_token` with a shape switch: `with_content_type` drops the
    /// RFC 3161 §2.4.2 content-type signed attribute when false.
    pub(crate) fn mint_token_shaped(
        tsa: &TestCa,
        imprint: &Sha256Digest,
        gen_time: u64,
        with_content_type: bool,
    ) -> Vec<u8> {
        mint_token_custom(tsa, imprint, gen_time, with_content_type, None, false)
    }

    /// Full fixture switchboard: `nonce` populates TSTInfo.nonce (needed by
    /// the seal-side response path), `extra_digest_alg` adds a weak SHA-1
    /// entry to the SignedData digestAlgorithms SET.
    pub(crate) fn mint_token_custom(
        tsa: &TestCa,
        imprint: &Sha256Digest,
        gen_time: u64,
        with_content_type: bool,
        nonce: Option<[u8; 16]>,
        extra_digest_alg: bool,
    ) -> Vec<u8> {
        let tst = x509_tsp::TstInfo {
            version: x509_tsp::TspVersion::V1,
            policy: der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4.5"),
            message_imprint: x509_tsp::MessageImprint {
                hash_algorithm: spki::AlgorithmIdentifierOwned {
                    oid: cms::OID_SHA256,
                    parameters: Some(der::asn1::Null.into()),
                },
                hashed_message: der::asn1::OctetString::new(imprint.to_vec()).unwrap(),
            },
            serial_number: der::asn1::Int::new(&[0x2a]).unwrap(),
            gen_time: gt(gen_time),
            accuracy: None,
            ordering: false,
            nonce: nonce.map(|n| der::asn1::Int::new(&n).unwrap()),
            tsa: None,
            extensions: None,
        };
        let tst_der = tst.to_der().unwrap();
        let (issuer, serial) = cms::issuer_and_serial(&tsa.cert_der).unwrap();
        let ct_oid = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
        let mut ct_body = cms::oid_tlv(&cms::OID_ATTR_CONTENT_TYPE);
        ct_body.extend_from_slice(&cms::tlv(0x31, &cms::oid_tlv(&ct_oid)));
        let mut attrs = vec![
            cms::attr_message_digest(&cms::sha256(&tst_der)),
            cms::attr_signing_cert_v2(&tsa.cert_der, &issuer, &serial),
        ];
        if with_content_type {
            attrs.push(cms::tlv(0x30, &ct_body));
        }
        let (wire, signing) = cms::assemble_signed_attrs(attrs);
        let sig = sign_p256(&tsa.key, &signing);
        let mut si = cms::tlv(0x02, &[1]);
        let mut sid = issuer;
        sid.extend_from_slice(&serial);
        si.extend_from_slice(&cms::tlv(0x30, &sid));
        si.extend_from_slice(&alg_id(cms::OID_SHA256, true));
        si.extend_from_slice(&wire);
        si.extend_from_slice(&alg_id(cms::OID_ECDSA_SHA256, false));
        si.extend_from_slice(&cms::tlv(0x04, &sig));
        let signer_info = cms::tlv(0x30, &si);
        // SignedData version 3: RFC 5652 5.1 mandates v3 whenever
        // eContentType is not id-data, so every compliant RFC 3161 token
        // (eContentType id-ct-TSTInfo) is exactly v3.
        let mut sd = cms::tlv(0x02, &[3]);
        // DER SET OF sorting: the SHA-1 AlgorithmIdentifier (30 09 ...)
        // encodes before SHA-256 (30 0D ...), so the weak entry lands first.
        let digest_algs = if extra_digest_alg {
            let sha1 = der::asn1::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
            let mut both = alg_id(sha1, true);
            both.extend_from_slice(&alg_id(cms::OID_SHA256, true));
            both
        } else {
            alg_id(cms::OID_SHA256, true)
        };
        sd.extend_from_slice(&cms::tlv(0x31, &digest_algs));
        let mut eci = cms::oid_tlv(&ct_oid);
        eci.extend_from_slice(&cms::tlv(0xA0, &cms::tlv(0x04, &tst_der)));
        sd.extend_from_slice(&cms::tlv(0x30, &eci));
        sd.extend_from_slice(&cms::tlv(0xA0, &tsa.cert_der));
        sd.extend_from_slice(&cms::tlv(0x31, &signer_info));
        let sd = cms::tlv(0x30, &sd);
        let mut ci = cms::oid_tlv(&cms::OID_SIGNED_DATA);
        ci.extend_from_slice(&cms::tlv(0xA0, &sd));
        cms::tlv(0x30, &ci)
    }

    /// Append one CAdES signature revision signed by `ca`; with `tsa`, embed
    /// a signature timestamp minted at `gen_time` (B-T).
    pub(crate) fn append_sig_revision(
        bytes: &[u8],
        ca: &TestCa,
        op: &str,
        tsa: Option<&TestCa>,
        gen_time: u64,
    ) -> Vec<u8> {
        let state = pdf::reparse_revision(bytes, &SealResourceLimits::default()).unwrap();
        let kind = pdf::RevisionKind::Signature {
            field_name: pdf::field_name_for(op),
            date_str: pdf::pdf_date(AT_UNIX * 1000),
        };
        let mut draft = pdf::append_revision(bytes, &state, &kind, 64 * 1024).unwrap();
        let br = draft.byte_range.unwrap();
        let digest = pdf::hash_byte_range(&draft.bytes, br).unwrap();
        let (issuer, serial) = cms::issuer_and_serial(&ca.cert_der).unwrap();
        let attrs = vec![
            cms::attr_content_type_data(),
            cms::attr_message_digest(&digest),
            cms::attr_signing_cert_v2(&ca.cert_der, &issuer, &serial),
        ];
        let (wire, signing) = cms::assemble_signed_attrs(attrs);
        let sig = sign_p256(&ca.key, &signing);
        let unsigned: Vec<Vec<u8>> = tsa
            .map(|t| mint_token(t, &cms::sha256(&sig), gen_time))
            .into_iter()
            .map(|t| cms::attr_ts_token(&t))
            .collect();
        let material = cms::SignerMaterial {
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            signer_cert_der: &ca.cert_der,
            issuer_name_der: &issuer,
            serial_der: &serial,
            chain_ders: &[],
        };
        let cms_der = cms::build_signed_data(&material, &wire, &sig, &unsigned);
        pdf::patch_contents(&mut draft, &cms_der).unwrap();
        draft.bytes
    }

    /// Append an UNSIGNED /DSS revision (catalog update + global arrays).
    pub(crate) fn append_dss_revision(
        bytes: &[u8],
        certs: Vec<Vec<u8>>,
        crls: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let state = pdf::reparse_revision(bytes, &SealResourceLimits::default()).unwrap();
        let material = profile::DssMaterial {
            certs_der: certs,
            ocsps_der: Vec::new(),
            crls_der: crls,
        };
        let (objs, dss_num) = profile::build_dss_objects(&material, state.max_obj + 1).unwrap();
        let draft = pdf::append_revision(
            bytes,
            &state,
            &pdf::RevisionKind::Dss {
                material_objects: objs,
                dss_obj: dss_num,
            },
            0,
        )
        .unwrap();
        draft.bytes
    }

    /// Append a DocTimeStamp revision minted at `gen_time` (B-LTA shape).
    pub(crate) fn append_doc_ts_revision(bytes: &[u8], tsa: &TestCa, gen_time: u64) -> Vec<u8> {
        let state = pdf::reparse_revision(bytes, &SealResourceLimits::default()).unwrap();
        let mut draft = pdf::append_revision(
            bytes,
            &state,
            &pdf::RevisionKind::DocumentTimestamp,
            64 * 1024,
        )
        .unwrap();
        let br = draft.byte_range.unwrap();
        let imprint = pdf::hash_byte_range(&draft.bytes, br).unwrap();
        let token = mint_token(tsa, &imprint, gen_time);
        pdf::patch_contents(&mut draft, &token).unwrap();
        draft.bytes
    }

    pub(crate) struct NoopBackend;

    #[async_trait::async_trait]
    impl SealBackend for NoopBackend {
        fn signing_identity(&self) -> Result<SigningIdentity, BackendError> {
            Err(BackendError::Unavailable {
                retry_after_ms: None,
            })
        }

        async fn sign_digest(
            &self,
            _request: SignDigestRequest,
        ) -> Result<BackendSignature, BackendError> {
            Err(BackendError::Unavailable {
                retry_after_ms: None,
            })
        }
    }

    pub(crate) struct NoopFetcher;

    #[async_trait::async_trait]
    impl SealFetcher for NoopFetcher {
        async fn fetch(&self, _request: FetchRequest) -> Result<FetchResponse, FetchError> {
            Err(FetchError::Unavailable)
        }
    }

    pub(crate) struct ClockMs(pub(crate) u64);

    impl SealClock for ClockMs {
        fn unix_time_ms(&self) -> u64 {
            self.0
        }
    }

    pub(crate) fn verify_engine(
        anchors: Vec<Vec<u8>>,
        clock_secs: u64,
    ) -> engine::NativeSealEngine {
        engine::NativeSealEngine::new(
            SealConfig {
                trust_anchors_der: anchors,
                timestamp_authorities: Vec::new(),
                fetch_policy: FetchPolicy::default(),
                resource_limits: SealResourceLimits::default(),
            },
            Arc::new(NoopBackend),
            Arc::new(NoopFetcher),
            Arc::new(ClockMs(clock_secs * 1000)),
        )
        .unwrap()
    }

    /// A valid multi-signature archived document: CAdES sig A with a
    /// signature timestamp, a covered /DSS revision carrying a CRL fresh at
    /// AT_UNIX (stale at VERIFY_SECS), a DocTimeStamp covering that /DSS,
    /// and a second valid CAdES signature appended AFTER the DocTimeStamp.
    struct LtaFixture {
        bytes: Vec<u8>,
        anchors: Vec<Vec<u8>>,
        signer_cert: Vec<u8>,
        stale_later_crl: Vec<u8>,
    }

    fn lta_multisig() -> LtaFixture {
        let signer = test_ca("lta-signer");
        let signer2 = test_ca("lta-signer-two");
        let tsa = tsa_ca();
        let input = std::fs::read(format!(
            "{}/tests/fixtures/pdf-input/classic_1page.pdf",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let b1 = append_sig_revision(&input, &signer, "lta-a", Some(&tsa), AT_UNIX);
        let crl = build_crl(&signer, AT_UNIX - 60, Some(AT_UNIX + 3600), None, vec![]);
        let b2 = append_dss_revision(
            &b1,
            vec![signer.cert_der.clone(), tsa.cert_der.clone()],
            vec![crl.clone()],
        );
        let b3 = append_doc_ts_revision(&b2, &tsa, AT_UNIX);
        let b4 = append_sig_revision(&b3, &signer2, "lta-b", None, 0);
        LtaFixture {
            bytes: b4,
            anchors: vec![signer.cert_der.clone(), signer2.cert_der, tsa.cert_der],
            signer_cert: signer.cert_der,
            stale_later_crl: crl,
        }
    }

    #[test]
    fn covering_doc_timestamp_keeps_lta_at_later_verify_clock() {
        // The final /DSS IS covered by the DocTimeStamp: its genTime is the
        // archival applicable time, so evidence stale at the verify clock
        // but fresh then still validates and the profile is kept.
        let fx = lta_multisig();
        let engine = verify_engine(fx.anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&fx.bytes).unwrap();
        assert!(
            report.valid,
            "covering DocTimeStamp must keep the archived profile: {report:?}"
        );
        assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineLta));
    }

    #[test]
    fn uncovered_dss_evidence_cannot_launder_through_old_timestamp() {
        // Attack: an UNSIGNED /DSS incremental revision appended after every
        // signature, carrying evidence fresh at the old DocTimeStamp genTime
        // but stale at the verify clock. No DocTimeStamp covers this
        // revision, so its genTime must not feed freshness: the stale
        // evidence fails ValidationMaterial and the profile drops below
        // B-LT/LTA.
        let fx = lta_multisig();
        let attacked = append_dss_revision(
            &fx.bytes,
            vec![fx.signer_cert.clone()],
            vec![fx.stale_later_crl.clone()],
        );
        let engine = verify_engine(fx.anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&attacked).unwrap();
        assert_ne!(report.achieved_profile, Some(PadesProfile::BaselineLt));
        assert_ne!(report.achieved_profile, Some(PadesProfile::BaselineLta));
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
            ),
            "stale uncovered evidence must fail ValidationMaterial"
        );
    }

    // --- dss_revision_end adversarial probes: the re-checker's shapes -----

    // --- (A filler span-craft, B dormant activation) plus the reference ---

    // --- chain sharpening found while building them -----------------------

    /// Classic-table incremental revision emitter for hand-crafted layouts
    /// the writer machinery cannot express (mixed doc-ts + DSS revisions,
    /// dormant objects, placeholder overwrites, trailer /Root switches).
    /// Mirrors append_revision's table emission; /Info and /ID (both
    /// optional) are omitted. Returns (bytes, [(num, obj_offset, body_start)]).
    pub(crate) fn emit_revision(
        input: &[u8],
        state: &pdf::RevisionState,
        objs: &[(u32, Vec<u8>)],
        root: Option<lopdf::ObjectId>,
    ) -> (Vec<u8>, Vec<(u32, u64, u64)>) {
        assert_eq!(state.xref_style, pdf::XrefStyle::Table);
        let mut out = input.to_vec();
        let mut written: Vec<(u32, u64, u64)> = Vec::with_capacity(objs.len());
        for (num, body) in objs {
            let obj_offset = out.len() as u64;
            out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
            written.push((*num, obj_offset, out.len() as u64));
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        let max_used = written
            .iter()
            .map(|w| w.0)
            .max()
            .unwrap_or(0)
            .max(state.max_obj);
        let xref_offset = out.len() as u64;
        let mut sorted = written.clone();
        sorted.sort_by_key(|w| w.0);
        out.extend_from_slice(b"xref\n");
        let mut idx = 0;
        while idx < sorted.len() {
            let start = sorted[idx].0;
            let mut end = start;
            while idx + 1 < sorted.len() && sorted[idx + 1].0 == end + 1 {
                idx += 1;
                end = sorted[idx].0;
            }
            let count = end - start + 1;
            out.extend_from_slice(format!("{start} {count}\n").as_bytes());
            for w in &sorted[idx + 1 - count as usize..=idx] {
                out.extend_from_slice(format!("{:010} 00000 n\r\n", w.1).as_bytes());
            }
            idx += 1;
        }
        let (rn, rg) = root.unwrap_or(state.root);
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Prev {} /Root {rn} {rg} R >>\n",
                max_used + 1,
                state.prev_startxref
            )
            .as_bytes(),
        );
        out.extend_from_slice(format!("startxref\n{xref_offset}\n%%EOF").as_bytes());
        (out, written)
    }

    /// /ByteRange placeholder digits, mirroring pdf's BYTERANGE_DIGITS.
    const BR_DIGITS: usize = 20;

    /// DocTimeStamp dictionary body with patchable /ByteRange and /Contents
    /// (mirrors pdf's sig_dict_body for the timestamp kind). Returns
    /// (body, byterange_patch_rel, contents_lt_rel).
    pub(crate) fn doc_ts_body(capacity: usize) -> (Vec<u8>, usize, usize) {
        let mut body = Vec::with_capacity(capacity * 2 + 256);
        body.extend_from_slice(
            b"<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 /ByteRange [0 ",
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

    /// Patch the three trailing /ByteRange fields (l1 s2 l2) at `pos`.
    pub(crate) fn patch_br(out: &mut [u8], pos: usize, br: [u64; 4]) {
        for (i, v) in br[1..4].iter().enumerate() {
            let at = pos + i * (BR_DIGITS + 1);
            let field = format!("{v:0BR_DIGITS$}");
            out[at..at + BR_DIGITS].copy_from_slice(field.as_bytes());
        }
    }

    /// Write the token DER hex into the /Contents gap (zero padding stays).
    pub(crate) fn fill_contents(out: &mut [u8], lt: usize, gt: usize, der: &[u8]) {
        let hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
        assert!(hex.len() < gt - lt, "token exceeds contents capacity");
        out[lt + 1..lt + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    }

    /// Stream object body, mirroring profile's stream_obj.
    pub(crate) fn stream_body(data: &[u8]) -> Vec<u8> {
        let mut body = format!("<< /Length {} >>\nstream\n", data.len()).into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(b"\nendstream");
        body
    }
}
