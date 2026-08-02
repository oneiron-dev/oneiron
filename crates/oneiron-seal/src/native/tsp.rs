//! RFC 3161 timestamp requests and token validation (§7.4, §7.6).

use der::Decode;
use x509_tsp::{TspVersion, TstInfo};

use crate::api::Sha256Digest;
use crate::error::{FatalCode, SealError, SealStage};

use super::cms::{self, DerReader, OID_ATTR_MESSAGE_DIGEST, OID_ATTR_SIGNING_CERT_V2, OID_SHA256};

pub(crate) const OID_TST_INFO: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x04";

fn ts_err() -> SealError {
    SealError::Fatal {
        stage: SealStage::Timestamp,
        code: FatalCode::CmsEncodingFailed,
    }
}

fn sha256_alg_id() -> Vec<u8> {
    let mut body = cms::oid_tlv(&OID_SHA256);
    body.extend_from_slice(&[0x05, 0x00]);
    cms::tlv(0x30, &body)
}

/// Build a DER TimeStampReq: SHA-256 imprint, nonzero 128-bit nonce,
/// `certReq = TRUE`.
pub(crate) fn build_request(
    imprint: &Sha256Digest,
    nonce: &[u8; 16],
) -> Result<Vec<u8>, SealError> {
    if nonce.iter().all(|b| *b == 0) {
        return Err(ts_err());
    }
    let mut body = cms::tlv(0x02, &[1]); // version v1
    let mut mi = sha256_alg_id();
    mi.extend_from_slice(&cms::tlv(0x04, imprint));
    body.extend_from_slice(&cms::tlv(0x30, &mi));
    body.extend_from_slice(&cms::tlv(0x02, &nonce_int_body(nonce)));
    body.extend_from_slice(&cms::tlv(0x01, &[0xFF])); // certReq TRUE
    Ok(cms::tlv(0x30, &body))
}

/// Parsed + policy-checked timestamp response.
pub(crate) struct ValidatedToken {
    pub content_info_der: Vec<u8>,
    pub tsa_chain_ders: Vec<Vec<u8>>,
}

/// Extract the TimeStampToken ContentInfo DER from a TimeStampResp, requiring
/// status `granted` (0) or `grantedWithMods` (1) with a present token.
fn extract_token(resp_der: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut top = DerReader::new(resp_der);
    let resp = top.expect(0x30)?;
    if !top.is_done() {
        return Err(ts_err());
    }
    let mut r = DerReader::new(resp.content);
    let status = r.expect(0x30)?;
    let status_code = DerReader::new(status.content).expect(0x02)?;
    if status_code.content.len() != 1 || status_code.content[0] > 1 {
        return Err(ts_err()); // not granted / grantedWithMods
    }
    if r.is_done() {
        return Err(ts_err()); // granted but token absent
    }
    Ok(r.expect(0x30)?.full.to_vec())
}

/// Nonce as a DER INTEGER body: minimal-length two's complement — strip
/// redundant leading zero octets while the next octet's high bit is clear,
/// then sign-pad a set high bit.
fn nonce_int_body(nonce: &[u8; 16]) -> Vec<u8> {
    let mut be = nonce.to_vec();
    while be.len() > 1 && be[0] == 0 && be[1] & 0x80 == 0 {
        be.remove(0);
    }
    if be[0] & 0x80 != 0 {
        be.insert(0, 0);
    }
    be
}

/// Extract the message-digest signed attribute value from a token signer.
fn token_message_digest(signer: &cms::ParsedSignerInfo) -> Result<Sha256Digest, SealError> {
    let mut found = None;
    for attr in &signer.signed_attrs {
        let (oid, value) = cms::parse_attribute(attr)?;
        if oid == OID_ATTR_MESSAGE_DIGEST.as_bytes() {
            if found.is_some() || value.tag != 0x04 || value.content.len() != 32 {
                return Err(ts_err());
            }
            let mut d = [0u8; 32];
            d.copy_from_slice(value.content);
            found = Some(d);
        }
    }
    found.ok_or_else(ts_err)
}

/// RFC 3161 §2.4.2: the token's signedAttrs MUST include a content-type
/// attribute (exactly once) whose value is id-ct-TSTInfo.
fn token_content_type_check(signer: &cms::ParsedSignerInfo) -> Result<(), SealError> {
    let mut seen = false;
    for attr in &signer.signed_attrs {
        let (oid, value) = cms::parse_attribute(attr)?;
        if oid == cms::OID_ATTR_CONTENT_TYPE.as_bytes() {
            if seen || value.tag != 0x06 || value.content != OID_TST_INFO {
                return Err(ts_err());
            }
            seen = true;
        }
    }
    if seen { Ok(()) } else { Err(ts_err()) }
}

/// Signer-certificate binding inside the token's signingCertificateV2 attr.
fn token_ess_check(signer: &cms::ParsedSignerInfo, tsa_cert_der: &[u8]) -> Result<(), SealError> {
    let (issuer, serial) = cms::issuer_and_serial(tsa_cert_der)?;
    for attr in &signer.signed_attrs {
        let (oid, _) = cms::parse_attribute(attr)?;
        if oid == OID_ATTR_SIGNING_CERT_V2.as_bytes() {
            return cms::check_ess_binding(attr, tsa_cert_der, &issuer, &serial);
        }
    }
    Err(ts_err())
}

/// Validation profile for pkix-chain: RFC 5280 path validation at the
/// applicable (timestamp or verification) time, no extra policy OIDs.
pub(crate) struct SealProfile;

impl pkix_chain::Profile for SealProfile {
    fn id(&self) -> &'static str {
        "oneiron.seal.pades-baseline"
    }

    fn version(&self) -> &'static str {
        "v1"
    }

    fn policy(&self, now_unix: u64) -> pkix_chain::ValidationPolicy {
        pkix_chain::ValidationPolicy::new(now_unix)
    }

    fn policy_oids(&self) -> &[der::asn1::ObjectIdentifier] {
        &[]
    }
}

fn parse_certs(ders: &[Vec<u8>]) -> Result<Vec<x509_cert::Certificate>, SealError> {
    ders.iter()
        .map(|d| x509_cert::Certificate::from_der(d).map_err(|_| ts_err()))
        .collect()
}

/// Validate a TimeStampResp against the request's imprint/nonce/policy and
/// the configured trust anchors (§7.4 step 5). `clock_ms` is the seal clock:
/// the same genTime skew bound the verifier applies is enforced here, so an
/// over-skew response is refused BEFORE it can be returned as validated —
/// the caller's TSA failover (or profile degradation) stays available
/// instead of the seal embedding a token its own self-verification would
/// reject.
pub(crate) fn validate_response(
    resp_der: &[u8],
    expected_imprint: &Sha256Digest,
    nonce: &[u8; 16],
    expected_policy_oid: Option<&str>,
    anchors: &[pkix_chain::TrustAnchor],
    clock_ms: u64,
) -> Result<ValidatedToken, SealError> {
    let token_ci = extract_token(resp_der)?;
    let parsed = cms::parse_cms(&token_ci)?;
    if parsed.econtent_oid != OID_TST_INFO {
        return Err(ts_err());
    }
    check_digest_algs(&parsed)?;
    let econtent = parsed.econtent.clone().ok_or_else(ts_err)?;
    let tst = TstInfo::from_der(&econtent).map_err(|_| ts_err())?;
    check_tst_fields(&tst, expected_imprint, nonce, expected_policy_oid)?;
    let signer = &parsed.signer;
    if !cms::is_sha256_oid(&signer.digest_alg_oid) {
        return Err(ts_err());
    }
    token_content_type_check(signer)?;
    if token_message_digest(signer)? != cms::sha256(&econtent) {
        return Err(ts_err());
    }
    let tsa_idx = find_bound_cert(&parsed.certificates, signer)?;
    let tsa_cert_der = &parsed.certificates[tsa_idx];
    let tsa_alg = cms::cert_signature_algorithm(tsa_cert_der)?;
    if !cms::sig_alg_permitted(tsa_alg, &signer.signature_alg_oid) {
        return Err(ts_err());
    }
    let signing_input = cms::signed_attrs_signature_input(signer);
    cms::verify_signature_value(tsa_alg, tsa_cert_der, &signing_input, &signer.signature)?;
    let chain_ders: Vec<Vec<u8>> = std::iter::once(tsa_cert_der.clone())
        .chain(
            parsed
                .certificates
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != tsa_idx)
                .map(|(_, c)| c.clone()),
        )
        .collect();
    let gen_time_unix = generalized_time_unix(&tst);
    // The verify path rejects a genTime ahead of the clock past the
    // documented skew (never clamps); the seal path must refuse the same
    // token here or the artifact fails its own mandatory self-verification.
    if super::verify::gen_time_beyond_skew(gen_time_unix, clock_ms) {
        return Err(ts_err());
    }
    validate_tsa_chain(&chain_ders, anchors, gen_time_unix)?;
    Ok(ValidatedToken {
        content_info_der: token_ci,
        tsa_chain_ders: chain_ders,
    })
}

fn check_tst_fields(
    tst: &TstInfo,
    expected_imprint: &Sha256Digest,
    nonce: &[u8; 16],
    expected_policy_oid: Option<&str>,
) -> Result<(), SealError> {
    if tst.version != TspVersion::V1 {
        return Err(ts_err());
    }
    if tst.message_imprint.hash_algorithm.oid != OID_SHA256 {
        return Err(ts_err());
    }
    if tst.message_imprint.hashed_message.as_bytes() != expected_imprint {
        return Err(ts_err());
    }
    let token_nonce = tst.nonce.as_ref().ok_or_else(ts_err)?;
    if token_nonce.as_bytes() != nonce_int_body(nonce).as_slice() {
        return Err(ts_err());
    }
    if let Some(expected) = expected_policy_oid {
        let expected_oid = der::asn1::ObjectIdentifier::new(expected).map_err(|_| ts_err())?;
        if tst.policy != expected_oid {
            return Err(ts_err());
        }
    }
    Ok(())
}

fn generalized_time_unix(tst: &TstInfo) -> u64 {
    tst.gen_time.to_unix_duration().as_secs()
}

/// SignedData digestAlgorithms surface (mirrors the CAdES envelope gate in
/// verify.rs): exactly one algorithm, SHA-256. Checked on both tsp paths so
/// a weak declared digest cannot hide behind a checked SignerInfo field.
fn check_digest_algs(parsed: &cms::ParsedCms) -> Result<(), SealError> {
    if parsed.digest_algs.len() != 1 || !cms::is_sha256_oid(&parsed.digest_algs[0]) {
        return Err(ts_err());
    }
    Ok(())
}

/// Locate the CMS certificate whose ESS binding matches the token signer.
fn find_bound_cert(certs: &[Vec<u8>], signer: &cms::ParsedSignerInfo) -> Result<usize, SealError> {
    for (i, cert) in certs.iter().enumerate() {
        if token_ess_check(signer, cert).is_ok() {
            return Ok(i);
        }
    }
    Err(ts_err())
}

/// Token signature against the TSA cert, then path validation with the
/// critical-and-sole timestamping EKU rule (pkix-chain verify_time_stamper).
fn validate_tsa_chain(
    chain_ders: &[Vec<u8>],
    anchors: &[pkix_chain::TrustAnchor],
    at_unix: u64,
) -> Result<(), SealError> {
    let chain = parse_certs(chain_ders)?;
    pkix_chain::verify_time_stamper(
        &chain,
        anchors,
        &SealProfile,
        at_unix,
        &pkix_chain::DefaultVerifier,
        &pkix_chain::NoRevocation,
        &pkix_chain::NoAiaFetcher,
    )
    .map_err(|_| SealError::Fatal {
        stage: SealStage::Timestamp,
        code: FatalCode::CertificatePathInvalid,
    })?;
    Ok(())
}

/// Verify-time token validation (§7.7): imprint match, token signature,
/// signer-cert binding, TSA path, critical-and-sole timestamping EKU. The
/// request nonce/policy checks are seal-time only. Returns the token's
/// genTime as unix seconds for applicable-time path validation plus the
/// validated TSA chain DERs so the DSS binding can require the profile
/// material to speak about this chain (§7.5 step 3).
pub(crate) fn validate_token_for_verify(
    token_der: &[u8],
    expected_imprint: &Sha256Digest,
    anchors: &[pkix_chain::TrustAnchor],
) -> Result<(u64, Vec<Vec<u8>>), SealError> {
    let parsed = cms::parse_cms(token_der)?;
    if parsed.econtent_oid != OID_TST_INFO {
        return Err(ts_err());
    }
    check_digest_algs(&parsed)?;
    let econtent = parsed.econtent.clone().ok_or_else(ts_err)?;
    let tst = TstInfo::from_der(&econtent).map_err(|_| ts_err())?;
    // TSTInfo version enforced on BOTH tsp paths (the seal-time path gets it
    // via check_tst_fields): only v1 tokens exist under RFC 3161. NOTE: with
    // x509-tsp 0.1 the Enumerated decode rejects unknown versions first —
    // this check is the explicit posture if the crate ever grows variants.
    if tst.version != TspVersion::V1 {
        return Err(ts_err());
    }
    if tst.message_imprint.hash_algorithm.oid != OID_SHA256 {
        return Err(ts_err());
    }
    if tst.message_imprint.hashed_message.as_bytes() != expected_imprint {
        return Err(ts_err());
    }
    let signer = &parsed.signer;
    if !cms::is_sha256_oid(&signer.digest_alg_oid) {
        return Err(ts_err());
    }
    token_content_type_check(signer)?;
    if token_message_digest(signer)? != cms::sha256(&econtent) {
        return Err(ts_err());
    }
    let idx = find_bound_cert(&parsed.certificates, signer)?;
    let cert_der = &parsed.certificates[idx];
    let alg = cms::cert_signature_algorithm(cert_der)?;
    if !cms::sig_alg_permitted(alg, &signer.signature_alg_oid) {
        return Err(ts_err());
    }
    let input = cms::signed_attrs_signature_input(signer);
    cms::verify_signature_value(alg, cert_der, &input, &signer.signature)?;
    let chain_ders: Vec<Vec<u8>> = std::iter::once(cert_der.clone())
        .chain(
            parsed
                .certificates
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != idx)
                .map(|(_, c)| c.clone()),
        )
        .collect();
    let gen_time_unix = generalized_time_unix(&tst);
    validate_tsa_chain(&chain_ders, anchors, gen_time_unix)?;
    Ok((gen_time_unix, chain_ders))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn request_sets_sha256_certreq_and_nonzero_nonce() {
        use der::Decode;
        let imprint = [3u8; 32];
        let nonce = [7u8; 16];
        let der = build_request(&imprint, &nonce).expect("request");
        let req = x509_tsp::TimeStampReq::from_der(&der).expect("parse");
        assert_eq!(req.message_imprint.hash_algorithm.oid, OID_SHA256);
        assert_eq!(req.message_imprint.hashed_message.as_bytes(), &imprint);
        assert!(req.cert_req, "certReq must be true");
        let got = req.nonce.expect("nonce present");
        assert!(got.as_bytes().iter().any(|b| *b != 0), "nonzero nonce");
        let mut expect_nonce = nonce.to_vec();
        if expect_nonce[0] & 0x80 != 0 {
            expect_nonce.insert(0, 0);
        }
        assert_eq!(got.as_bytes(), expect_nonce.as_slice());
    }

    #[test]
    fn all_zero_nonce_is_rejected() {
        assert!(build_request(&[3u8; 32], &[0u8; 16]).is_err());
    }

    #[test]
    fn nonce_integer_body_is_minimal_twos_complement() {
        // Redundant leading zero stripped when the next MSB is clear.
        let mut n = [0u8; 16];
        n[1] = 0x7F;
        let body = nonce_int_body(&n);
        assert_eq!(body[0], 0x7F, "leading 0x00 before a clear MSB is dropped");
        assert_eq!(body.len(), 15);
        // 0x00FF: the leading zero is SIGNIFICANT (next MSB set) and must be
        // kept exactly once — 00 FF, never 00 00 FF.
        let mut n = [0u8; 16];
        n[1] = 0xFF;
        let body = nonce_int_body(&n);
        assert_eq!(&body[..2], &[0x00, 0xFF]);
        assert_eq!(body.len(), 16);
        // High bit set on the first octet: one sign pad.
        let mut n = [0x80u8; 16];
        n[0] = 0xFF;
        let body = nonce_int_body(&n);
        assert_eq!(&body[..2], &[0x00, 0xFF]);
        assert_eq!(body.len(), 17);
        // Multiple redundant zeros collapse.
        let mut n = [0u8; 16];
        n[3] = 0x01;
        let body = nonce_int_body(&n);
        assert_eq!(body[0], 0x01);
        assert_eq!(body.len(), 13);
    }

    #[test]
    fn granted_status_without_token_fails() {
        // TimeStampResp { status granted, no token }.
        let status = cms::tlv(0x30, &cms::tlv(0x02, &[0]));
        let resp = cms::tlv(0x30, &status);
        assert!(extract_token(&resp).is_err());
    }

    #[test]
    fn non_granted_status_fails() {
        // status = rejection(2), with a dummy token present.
        let status = cms::tlv(0x30, &cms::tlv(0x02, &[2]));
        let mut body = status;
        body.extend_from_slice(&cms::tlv(0x30, &[0x05, 0x00]));
        let resp = cms::tlv(0x30, &body);
        assert!(extract_token(&resp).is_err());
    }
}
