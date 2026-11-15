//! An unrelated certificate carried in a CMS certificate bag is on no
//! selected certification path. It must not need DSS revocation coverage
//! of its own, for the signer bag or for a document-timestamp token bag.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron_seal::{
    FetchPolicy, NativeSealEngine, PadesProfile, PdfSealEngine, SealConfig, SealRequest,
    TsaEndpoint, VerifyCheckKind, VerifyCheckStatus, VerifyReport, VerifyVerdict,
};

#[path = "support/mod.rs"]
mod support;

use support::{
    FixedClock, FixtureBackend, FixtureFetcher, TEST_TIME_MS, TestIdentity, p256_identity,
    rsa_identity,
};

fn fixture_pdf(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/pdf-input/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).unwrap()
}

fn config_for(anchors: Vec<Vec<u8>>, with_tsa: bool) -> SealConfig {
    SealConfig {
        trust_anchors_der: anchors,
        timestamp_authorities: if with_tsa {
            vec![TsaEndpoint {
                url: url::Url::parse("https://tsa.example.test/").unwrap(),
                expected_policy_oid: None,
            }]
        } else {
            Vec::new()
        },
        fetch_policy: FetchPolicy::default(),
        resource_limits: support::grant_all_limits(),
    }
}

fn request(target: PadesProfile) -> SealRequest {
    SealRequest {
        operation_id: "covered-set".to_string(),
        target_profile: target,
    }
}

fn engine_with(
    id: TestIdentity,
    fetcher: Arc<dyn oneiron_seal::SealFetcher>,
    config: SealConfig,
) -> NativeSealEngine {
    NativeSealEngine::new(
        config,
        Arc::new(FixtureBackend::new(id)),
        fetcher,
        Arc::new(FixedClock(TEST_TIME_MS)),
    )
    .unwrap()
}

fn assert_passes_at(report: &VerifyReport, profile: PadesProfile) {
    assert_eq!(report.verdict(), VerifyVerdict::Passed, "{report:?}");
    assert_eq!(report.achieved_profile(), Some(profile), "{report:?}");
    let mut seen_material = false;
    for check in report
        .checks()
        .filter(|c| c.kind == VerifyCheckKind::ValidationMaterial)
    {
        seen_material = true;
        assert_eq!(
            check.status,
            VerifyCheckStatus::Pass,
            "validation material must pass: {report:?}"
        );
    }
    assert!(seen_material, "a DSS check must be present: {report:?}");
}

fn find(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("needle present")
}

/// The (tag, whole TLV length, header length) of the single-byte-tag TLV
/// at `offset`.
fn tlv_header(buf: &[u8], offset: usize) -> (u8, usize, usize) {
    let tag = buf[offset];
    assert!(tag & 0x1f != 0x1f, "single-byte tags only");
    let first = buf[offset + 1];
    if first < 0x80 {
        (tag, 2 + usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | usize::from(buf[offset + 2 + i]);
        }
        (tag, 2 + count + len, 2 + count)
    }
}

fn content_of(full: &[u8]) -> &[u8] {
    let (_, total, header) = tlv_header(full, 0);
    &full[header..total]
}

fn children(content: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < content.len() {
        let (_, total, _) = tlv_header(content, offset);
        out.push(&content[offset..offset + total]);
        offset += total;
    }
    assert_eq!(offset, content.len());
    out
}

/// `cms` with `extra` added to its SignedData certificate set, in DER
/// set order. The SignerInfo bytes are untouched, as a bag stuffing
/// a verifier receives from another signer would leave them.
fn add_certificate(cms: &[u8], extra: &[u8]) -> Vec<u8> {
    assert_eq!(cms[0], 0x30, "ContentInfo is a SEQUENCE");
    let content_info = children(content_of(cms));
    assert_eq!(content_info.len(), 2);
    assert_eq!(content_info[1][0], 0xa0, "explicit SignedData");
    let signed_data_outer = children(content_of(content_info[1]));
    assert_eq!(signed_data_outer.len(), 1);
    assert_eq!(signed_data_outer[0][0], 0x30, "SignedData SEQUENCE");
    let signed_data = children(content_of(signed_data_outer[0]));
    assert_eq!(
        signed_data[3][0], 0xa0,
        "certificates [0] is the fourth SignedData field"
    );
    let mut members = children(content_of(signed_data[3]));
    members.push(extra);
    members.sort_unstable();
    members.dedup();
    let mut certs_content = Vec::new();
    for member in members {
        certs_content.extend_from_slice(member);
    }
    let new_certs = support::tlv(0xa0, &certs_content);
    let mut signed_data_content = Vec::new();
    for (index, child) in signed_data.iter().enumerate() {
        if index == 3 {
            signed_data_content.extend_from_slice(&new_certs);
        } else {
            signed_data_content.extend_from_slice(child);
        }
    }
    let new_signed_data = support::tlv(0x30, &signed_data_content);
    let new_explicit = support::tlv(0xa0, &new_signed_data);
    let mut content_info_content = content_info[0].to_vec();
    content_info_content.extend_from_slice(&new_explicit);
    support::tlv(0x30, &content_info_content)
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("not a hex digit: {byte}"),
    }
}

/// `sealed` with `extra` added to the certificate bag of the CMS in the
/// `/Contents` gap of the signature dictionary identified by `marker`.
/// The rewritten DER reuses the same gap and zero padding, so every
/// ByteRange offset is unchanged.
fn inject_bag_certificate(sealed: &[u8], marker: &[u8], extra: &[u8]) -> Vec<u8> {
    let marker_at = find(sealed, marker);
    let contents_at = marker_at + find(&sealed[marker_at..], b"/Contents <");
    let hex_start = contents_at + b"/Contents <".len();
    let hex_end = hex_start
        + sealed[hex_start..]
            .iter()
            .position(|byte| *byte == b'>')
            .expect("contents gap ends");
    let hex = &sealed[hex_start..hex_end];
    assert!(hex.len() % 2 == 0, "hex gap holds whole bytes");
    let mut der = Vec::with_capacity(hex.len() / 2);
    for pair in hex.chunks_exact(2) {
        der.push((hex_value(pair[0]) << 4) | hex_value(pair[1]));
    }
    let (_, total, _) = tlv_header(&der, 0);
    der.truncate(total);
    let rewritten = add_certificate(&der, extra);
    assert!(
        rewritten.len() <= hex.len() / 2,
        "rewritten CMS fits the gap"
    );
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = sealed.to_vec();
    for (index, byte) in rewritten.iter().enumerate() {
        out[hex_start + 2 * index] = HEX[usize::from(byte >> 4)];
        out[hex_start + 2 * index + 1] = HEX[usize::from(byte & 0x0f)];
    }
    for slot in &mut out[hex_start + 2 * rewritten.len()..hex_end] {
        *slot = b'0';
    }
    out
}

#[tokio::test]
async fn unrelated_signer_bag_certificate_does_not_change_b_lt_result() {
    // A B-LT document is sealed for a root-issued leaf: the DSS carries
    // the leaf and the root's fresh CRL. Sealing is only the fixture: the
    // unrelated certificate is then stuffed into the signer CMS bag, in
    // the unsigned /Contents gap, exactly as another signer's CMS could
    // already carry it.
    let root = support::ca_with_kus(
        "root-crlsign",
        vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ],
    );
    let leaf = support::leaf_identity_with_crl_dp(
        &root,
        "signer-leaf",
        "https://crl.example.test/root.crl",
    );
    let tsa = p256_identity(true);
    let crl = support::signed_crl_der(&root, "20260730070000Z", "20260730090000Z");
    let anchors = vec![root.cert_der.clone(), tsa.cert_der.clone()];
    let mut fetcher = FixtureFetcher::with_tsa(tsa);
    fetcher.responses.insert(
        "https://crl.example.test/root.crl".to_string(),
        oneiron_seal::FetchResponse {
            body: support::shared_bytes(&crl),
            content_type: None,
        },
    );
    let engine = engine_with(leaf, Arc::new(fetcher), config_for(anchors, true));
    let out = engine
        .seal_pdf(
            &fixture_pdf("classic_1page.pdf"),
            &request(PadesProfile::BaselineLt),
        )
        .await
        .unwrap();
    assert_eq!(out.achieved_profile, PadesProfile::BaselineLt);
    let sealed = out.bytes.to_vec();
    let control = engine.verify_sealed_pdf(&sealed).unwrap();
    assert_passes_at(&control, PadesProfile::BaselineLt);

    let unrelated = p256_identity(false).cert_der;
    let stuffed = inject_bag_certificate(&sealed, b"/ETSI.CAdES.detached", &unrelated);
    let report = engine.verify_sealed_pdf(&stuffed).unwrap();
    assert_passes_at(&report, PadesProfile::BaselineLt);
}

#[tokio::test]
async fn unrelated_timestamp_bag_certificate_does_not_change_b_lta_result() {
    // The same stuffing in a document timestamp token: its bag carries an
    // unrelated certificate beside the TSA certificate. The token's
    // selected TSA path is unchanged, so the archival result must be too.
    let signer = rsa_identity(false);
    let tsa = p256_identity(true);
    let anchors = vec![signer.cert_der.clone(), tsa.cert_der.clone()];
    let fetcher = Arc::new(FixtureFetcher::with_tsa(tsa));
    let engine = engine_with(signer, fetcher, config_for(anchors, true));
    let out = engine
        .seal_pdf(
            &fixture_pdf("classic_1page.pdf"),
            &request(PadesProfile::BaselineLta),
        )
        .await
        .unwrap();
    assert_eq!(out.achieved_profile, PadesProfile::BaselineLta);
    let sealed = out.bytes.to_vec();
    let control = engine.verify_sealed_pdf(&sealed).unwrap();
    assert_passes_at(&control, PadesProfile::BaselineLta);

    let unrelated = p256_identity(false).cert_der;
    let stuffed = inject_bag_certificate(&sealed, b"/ETSI.RFC3161", &unrelated);
    let report = engine.verify_sealed_pdf(&stuffed).unwrap();
    assert_passes_at(&report, PadesProfile::BaselineLta);
}
