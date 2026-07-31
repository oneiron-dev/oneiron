//! RFC 3161 timestamp requests and token validation (§7.4, §7.6).

use der::Decode;
use x509_tsp::{TspVersion, TstInfo};

use crate::api::Sha256Digest;
use crate::error::{FatalCode, SealError, SealStage};

use super::cms::{
    self, DerReader, OID_ATTR_MESSAGE_DIGEST, OID_ATTR_SIGNING_CERT_V2, OID_SHA256,
};

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
    let mut nonce_be = nonce.to_vec();
    if nonce_be[0] & 0x80 != 0 {
        nonce_be.insert(0, 0);
    }
    body.extend_from_slice(&cms::tlv(0x02, &nonce_be));
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

/// Nonce as a DER INTEGER body (big-endian, sign-padded).
fn nonce_int_body(nonce: &[u8; 16]) -> Vec<u8> {
    let mut be = nonce.to_vec();
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

/// Signer-certificate binding inside the token's signingCertificateV2 attr.
fn token_ess_check(
    signer: &cms::ParsedSignerInfo,
    tsa_cert_der: &[u8],
) -> Result<(), SealError> {
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
/// the configured trust anchors (§7.4 step 5).
pub(crate) fn validate_response(
    resp_der: &[u8],
    expected_imprint: &Sha256Digest,
    nonce: &[u8; 16],
    expected_policy_oid: Option<&str>,
    anchors: &[pkix_chain::TrustAnchor],
) -> Result<ValidatedToken, SealError> {
    let token_ci = extract_token(resp_der)?;
    let parsed = cms::parse_cms(&token_ci)?;
    if parsed.econtent_oid != OID_TST_INFO {
        return Err(ts_err());
    }
    let econtent = parsed.econtent.clone().ok_or_else(ts_err)?;
    let tst = TstInfo::from_der(&econtent).map_err(|_| ts_err())?;
    check_tst_fields(&tst, expected_imprint, nonce, expected_policy_oid)?;
    let signer = &parsed.signer;
    if signer.digest_alg_oid != cms::sha256_oid_bytes() {
        return Err(ts_err());
    }
    if token_message_digest(signer)? != cms::sha256(&econtent) {
        return Err(ts_err());
    }
    let tsa_idx = find_bound_cert(&parsed.certificates, signer)?;
    let tsa_cert_der = &parsed.certificates[tsa_idx];
    let tsa_alg = cms::cert_signature_algorithm(tsa_cert_der)?;
    if !cms::sig_alg_oid_matches(tsa_alg, &signer.signature_alg_oid) {
        return Err(ts_err());
    }
    let signing_input = cms::signed_attrs_signature_input(signer);
    cms::verify_signature_value(tsa_alg, tsa_cert_der, &signing_input, &signer.signature)?;
    let chain_ders: Vec<Vec<u8>> = std::iter::once(tsa_cert_der.clone())
        .chain(parsed.certificates.iter().enumerate().filter_map(|(i, c)| {
            (i != tsa_idx).then(|| c.clone())
        }))
        .collect();
    let gen_time_unix = generalized_time_unix(&tst)?;
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

fn generalized_time_unix(tst: &TstInfo) -> Result<u64, SealError> {
    let dur = tst.gen_time.to_unix_duration();
    Ok(u64::try_from(dur.as_secs()).map_err(|_| ts_err())?)
}

/// Locate the CMS certificate whose ESS binding matches the token signer.
fn find_bound_cert(
    certs: &[Vec<u8>],
    signer: &cms::ParsedSignerInfo,
) -> Result<usize, SealError> {
    for (i, cert) in certs.iter().enumerate() {
        if token_ess_check(signer, cert).is_ok() {
            return Ok(i);
        }
    }
    Err(ts_err())
}

/// Token signature against the TSA cert, then path validation with the
/// critical-and-sole timestamping EKU rule (pkix-chain verify_time_stamper).
fn validate_tsa_chain_at(
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

fn validate_tsa_chain(
    chain_ders: &[Vec<u8>],
    anchors: &[pkix_chain::TrustAnchor],
    at_unix: u64,
) -> Result<(), SealError> {
    validate_tsa_chain_at(chain_ders, anchors, at_unix)
}

/// Verify-time token validation (§7.7): imprint match, token signature,
/// signer-cert binding, TSA path, critical-and-sole timestamping EKU. The
/// request nonce/policy checks are seal-time only. Returns the token's
/// genTime as unix seconds for applicable-time path validation.
pub(crate) fn validate_token_for_verify(
    token_der: &[u8],
    expected_imprint: &Sha256Digest,
    anchors: &[pkix_chain::TrustAnchor],
) -> Result<u64, SealError> {
    let parsed = cms::parse_cms(token_der)?;
    if parsed.econtent_oid != OID_TST_INFO {
        return Err(ts_err());
    }
    let econtent = parsed.econtent.clone().ok_or_else(ts_err)?;
    let tst = TstInfo::from_der(&econtent).map_err(|_| ts_err())?;
    if tst.message_imprint.hash_algorithm.oid != OID_SHA256 {
        return Err(ts_err());
    }
    if tst.message_imprint.hashed_message.as_bytes() != expected_imprint {
        return Err(ts_err());
    }
    let signer = &parsed.signer;
    if signer.digest_alg_oid != cms::sha256_oid_bytes() {
        return Err(ts_err());
    }
    if token_message_digest(signer)? != cms::sha256(&econtent) {
        return Err(ts_err());
    }
    let idx = find_bound_cert(&parsed.certificates, signer)?;
    let cert_der = &parsed.certificates[idx];
    let alg = cms::cert_signature_algorithm(cert_der)?;
    if !cms::sig_alg_oid_matches(alg, &signer.signature_alg_oid) {
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
                .filter_map(|(i, c)| (i != idx).then(|| c.clone())),
        )
        .collect();
    let gen_time_unix = generalized_time_unix(&tst)?;
    validate_tsa_chain(&chain_ders, anchors, gen_time_unix)?;
    Ok(gen_time_unix)
}
