//! Shared test support: ephemeral identities, fixture backend/fetcher/clock,
//! and a functional fixture TSA. Keys are generated fresh per test run; no
//! key material is persisted anywhere.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use oneiron_seal::{
    BackendSignature, FetchError, FetchRequest, FetchResponse, SealBackend, SealClock, SealFetcher,
    SignDigestRequest, SignatureAlgorithm, SigningIdentity,
};

// ---------------------------------------------------------------------------
// Minimal DER writer (mirrors the production encoding for fixture assembly)
// ---------------------------------------------------------------------------

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&len_bytes(content.len()));
    out.extend_from_slice(content);
    out
}

pub(crate) fn len_bytes(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let be = len.to_be_bytes();
    let start = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let significant = &be[start..];
    let mut out = vec![0x80 | significant.len() as u8];
    out.extend_from_slice(significant);
    out
}

pub(crate) fn oid_tlv(oid_content: &[u8]) -> Vec<u8> {
    tlv(0x06, oid_content)
}

pub(crate) const OID_SHA256: &[u8] = b"\x60\x86\x48\x01\x65\x03\x04\x02\x01";
pub(crate) const OID_DATA: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01";
pub(crate) const OID_SIGNED_DATA: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02";
pub(crate) const OID_TST_INFO: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x04";
pub(crate) const OID_ATTR_CONTENT_TYPE: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x03";
pub(crate) const OID_ATTR_MESSAGE_DIGEST: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04";
pub(crate) const OID_ATTR_SIGNING_CERT_V2: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x2f";
pub(crate) const OID_SHA256_WITH_RSA: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b";
pub(crate) const OID_ECDSA_SHA256: &[u8] = b"\x2a\x86\x48\xce\x3d\x04\x03\x02";

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

pub(crate) fn alg_id(oid_content: &[u8], with_null: bool) -> Vec<u8> {
    let mut body = oid_tlv(oid_content);
    if with_null {
        body.extend_from_slice(&[0x05, 0x00]);
    }
    tlv(0x30, &body)
}

pub(crate) fn attribute(oid_content: &[u8], value_der: &[u8]) -> Vec<u8> {
    let mut body = oid_tlv(oid_content);
    body.extend_from_slice(&tlv(0x31, value_der));
    tlv(0x30, &body)
}

/// signingCertificateV2 fixture attribute (full-cert SHA-256, DEFAULT hash
/// algorithm omitted, issuerSerial present) — mirrors the production rule.
pub(crate) fn ess_attr(cert_der: &[u8], issuer_name_der: &[u8], serial_der: &[u8]) -> Vec<u8> {
    let cert_hash = tlv(0x04, &sha256(cert_der));
    let gn = tlv(0xA4, issuer_name_der);
    let mut is_body = tlv(0x30, &gn);
    is_body.extend_from_slice(serial_der);
    let issuer_serial = tlv(0x30, &is_body);
    let mut ess_body = cert_hash;
    ess_body.extend_from_slice(&issuer_serial);
    let ess = tlv(0x30, &ess_body);
    let certs_seq = tlv(0x30, &ess);
    let sc = tlv(0x30, &certs_seq);
    attribute(OID_ATTR_SIGNING_CERT_V2, &sc)
}

pub(crate) fn message_digest_attr(digest: &[u8; 32]) -> Vec<u8> {
    attribute(OID_ATTR_MESSAGE_DIGEST, &tlv(0x04, digest))
}

/// Issuer Name + serial TLVs straight out of a certificate's TBS.
pub(crate) fn issuer_and_serial(cert_der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Walk: Certificate SEQ { tbs SEQ { ... } }. Fields up to issuer:
    // version [0], serial INTEGER, signature AlgId, issuer Name.
    let ((_cf, cert_content), _cr) = read_tlv(cert_der, 0x30);
    let ((_tf, tbs_content), _tr) = read_tlv(cert_content, 0x30);
    let mut rest = tbs_content;
    let (_, r) = read_tlv(rest, 0xA0);
    rest = r;
    let (_serial, r) = read_tlv(rest, 0x02);
    let serial = &rest[..rest.len() - r.len()];
    rest = r;
    let (_alg, r) = read_tlv(rest, 0x30);
    rest = r;
    let (_iss, r) = read_tlv(rest, 0x30);
    let issuer = &rest[..rest.len() - r.len()];
    (issuer.to_vec(), serial.to_vec())
}

/// Read the TLV at the start of `buf` with an expected tag; returns
/// ((full_tlv, content), rest).
pub(crate) fn read_tlv(buf: &[u8], tag: u8) -> ((&[u8], &[u8]), &[u8]) {
    assert_eq!(buf[0], tag, "tag mismatch");
    let (len, hdr) = if buf[1] & 0x80 == 0 {
        (usize::from(buf[1]), 2)
    } else {
        let n = usize::from(buf[1] & 0x7F);
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(buf[2 + i]);
        }
        (len, 2 + n)
    };
    let end = hdr + len;
    ((&buf[..end], &buf[hdr..end]), &buf[end..])
}

// ---------------------------------------------------------------------------
// Ephemeral identities (generated per run; never persisted)
// ---------------------------------------------------------------------------

#[allow(clippy::large_enum_variant)]
pub(crate) enum TestKey {
    P256(p256::ecdsa::SigningKey),
    Rsa(Box<rsa::RsaPrivateKey>),
}

pub(crate) struct TestIdentity {
    pub(crate) algorithm: SignatureAlgorithm,
    pub(crate) cert_der: Vec<u8>,
    pub(crate) key: TestKey,
}

pub(crate) fn self_signed_cert(key_pair: &rcgen::KeyPair, is_tsa: bool) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        if is_tsa { "test-tsa" } else { "test-signer" },
    );
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    if is_tsa {
        // Exactly one critical id-kp-timeStamping EKU (RFC 3161 §2.3).
        let eku = tlv(
            0x30,
            &oid_tlv(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08]),
        );
        let mut ext = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 37], eku);
        ext.set_criticality(true);
        params.custom_extensions.push(ext);
    }
    let cert = params.self_signed(key_pair).unwrap();
    cert.der().to_vec()
}

pub(crate) fn p256_identity(is_tsa: bool) -> TestIdentity {
    use p256::pkcs8::DecodePrivateKey;

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert_der = self_signed_cert(&key_pair, is_tsa);
    let sk = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
    TestIdentity {
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        cert_der,
        key: TestKey::P256(sk),
    }
}

pub(crate) fn rsa_identity(is_tsa: bool) -> TestIdentity {
    use rsa::pkcs8::EncodePrivateKey;

    let mut rng = rsa::rand_core::OsRng;
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pkcs8 = private.to_pkcs8_der().unwrap();
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
        &rcgen::PKCS_RSA_SHA256,
    )
    .unwrap();
    let cert_der = self_signed_cert(&key_pair, is_tsa);
    TestIdentity {
        algorithm: SignatureAlgorithm::RsaPkcs1v15Sha256,
        cert_der,
        key: TestKey::Rsa(Box::new(private)),
    }
}

pub(crate) fn sign_prehash(key: &TestKey, digest: &[u8; 32]) -> BackendSignature {
    match key {
        TestKey::P256(sk) => {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let sig: p256::ecdsa::Signature = sk.sign_prehash(digest).unwrap();
            BackendSignature::EcdsaP256Der {
                bytes: sig.to_der().as_bytes().to_vec(),
            }
        }
        TestKey::Rsa(sk) => {
            let scheme = rsa::Pkcs1v15Sign::new::<sha2::Sha256>();
            let bytes = sk.sign(scheme, digest).unwrap();
            BackendSignature::RsaPkcs1v15 { bytes }
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture backend / fetcher / clock
// ---------------------------------------------------------------------------

/// Fixture signing backend. Records every request for operation-ID
/// assertions; signs prehash digests with the ephemeral key.
pub(crate) struct FixtureBackend {
    pub(crate) identity: SigningIdentity,
    pub(crate) key: TestKey,
    pub(crate) requests: Mutex<Vec<SignDigestRequest>>,
    pub(crate) raw_p1363: std::sync::atomic::AtomicBool,
}

impl FixtureBackend {
    pub(crate) fn new(id: TestIdentity) -> Self {
        Self {
            identity: SigningIdentity {
                algorithm: id.algorithm,
                signer_certificate_der: id.cert_der.clone(),
                certificate_chain_der: Vec::new(),
            },
            key: id.key,
            requests: Mutex::new(Vec::new()),
            raw_p1363: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl SealBackend for FixtureBackend {
    fn signing_identity(&self) -> Result<SigningIdentity, oneiron_seal::BackendError> {
        Ok(self.identity.clone())
    }

    async fn sign_digest(
        &self,
        request: SignDigestRequest,
    ) -> Result<BackendSignature, oneiron_seal::BackendError> {
        self.requests.lock().unwrap().push(request.clone());
        if self.raw_p1363.load(std::sync::atomic::Ordering::SeqCst)
            && let TestKey::P256(sk) = &self.key
        {
            use p256::ecdsa::signature::hazmat::PrehashSigner;

            let sig: p256::ecdsa::Signature = sk.sign_prehash(&request.digest).unwrap();
            // Wrong wire form on purpose: raw P1363 r||s in the DER slot.
            return Ok(BackendSignature::EcdsaP256Der {
                bytes: sig.to_bytes().to_vec(),
            });
        }
        Ok(sign_prehash(&self.key, &request.digest))
    }
}

/// Fixture fetcher: static URL map plus a functional TSA that mints tokens
/// for any well-formed request.
pub(crate) struct FixtureFetcher {
    pub(crate) responses: HashMap<String, FetchResponse>,
    pub(crate) tsa: Option<TestIdentity>,
    pub(crate) calls: Mutex<Vec<String>>,
}

impl FixtureFetcher {
    pub(crate) fn offline() -> Self {
        Self {
            responses: HashMap::new(),
            tsa: None,
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn with_tsa(tsa: TestIdentity) -> Self {
        Self {
            responses: HashMap::new(),
            tsa: Some(tsa),
            calls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl SealFetcher for FixtureFetcher {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{:?}", request.purpose));
        if let Some(resp) = self.responses.get(request.url.as_str()) {
            return Ok(resp.clone());
        }
        if let Some(tsa) = &self.tsa
            && request.purpose == oneiron_seal::FetchPurpose::Timestamp
        {
            return tsa_response(tsa, &request.request_body)
                .map(|body| FetchResponse {
                    body,
                    content_type: Some("application/timestamp-reply".to_string()),
                })
                .ok_or(FetchError::InvalidResponse);
        }
        Err(FetchError::Unavailable)
    }
}

pub(crate) struct FixedClock(pub u64);

impl SealClock for FixedClock {
    fn unix_time_ms(&self) -> u64 {
        self.0
    }
}

/// 2026-07-30T08:00:00Z in unix ms.
pub(crate) const TEST_TIME_MS: u64 = 1_785_398_400_000;

// ---------------------------------------------------------------------------
// Functional fixture TSA: mints RFC 3161 tokens for well-formed requests
// ---------------------------------------------------------------------------

/// Build a granted TimeStampResp for `request_der` signed by the fixture TSA
/// identity. Returns None for malformed requests.
pub(crate) fn tsa_response(tsa: &TestIdentity, request_der: &[u8]) -> Option<Vec<u8>> {
    use der::{Decode, Encode};
    let req = x509_tsp::TimeStampReq::from_der(request_der).ok()?;
    if !req.cert_req {
        return None;
    }
    let gen_time = der::asn1::GeneralizedTime::from_unix_duration(
        std::time::Duration::from_millis(TEST_TIME_MS),
    )
    .ok()?;
    let serial = der::asn1::Int::new(&[0x01]).ok()?;
    let tst = x509_tsp::TstInfo {
        version: x509_tsp::TspVersion::V1,
        policy: der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4.5"),
        message_imprint: req.message_imprint.clone(),
        serial_number: serial,
        gen_time,
        accuracy: None,
        ordering: false,
        nonce: req.nonce,
        tsa: None,
        extensions: None,
    };
    let tst_der = tst.to_der().ok()?;
    let token = build_token_cms(tsa, &tst_der);
    // TimeStampResp: SEQ { PKIStatusInfo{granted}, token }
    let status = tlv(0x30, &tlv(0x02, &[0]));
    let mut body = status;
    body.extend_from_slice(&token);
    Some(tlv(0x30, &body))
}

/// Assemble the token ContentInfo: SignedData with eContentType
/// id-ct-TSTInfo, TSA cert embedded, and the PAdES-style signed attributes.
pub(crate) fn build_token_cms(tsa: &TestIdentity, tst_der: &[u8]) -> Vec<u8> {
    let (issuer, serial) = issuer_and_serial(&tsa.cert_der);
    let mut attrs = vec![
        attribute(OID_ATTR_CONTENT_TYPE, &oid_tlv(OID_TST_INFO)),
        message_digest_attr(&sha256(tst_der)),
        ess_attr(&tsa.cert_der, &issuer, &serial),
    ];
    attrs.sort();
    let mut attr_content = Vec::new();
    for a in &attrs {
        attr_content.extend_from_slice(a);
    }
    let signing_input = tlv(0x31, &attr_content);
    let digest = sha256(&signing_input);
    let signature = match sign_prehash(&tsa.key, &digest) {
        BackendSignature::RsaPkcs1v15 { bytes } => bytes,
        BackendSignature::EcdsaP256Der { bytes } => bytes,
    };
    let sig_alg_oid = match tsa.algorithm {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => OID_SHA256_WITH_RSA,
        SignatureAlgorithm::EcdsaP256Sha256 => OID_ECDSA_SHA256,
    };
    let sig_alg_with_null = matches!(tsa.algorithm, SignatureAlgorithm::RsaPkcs1v15Sha256);

    let mut si = tlv(0x02, &[1]);
    let mut sid_body = issuer;
    sid_body.extend_from_slice(&serial);
    si.extend_from_slice(&tlv(0x30, &sid_body));
    si.extend_from_slice(&alg_id(OID_SHA256, true));
    si.extend_from_slice(&tlv(0xA0, &attr_content));
    si.extend_from_slice(&alg_id(sig_alg_oid, sig_alg_with_null));
    si.extend_from_slice(&tlv(0x04, &signature));
    let signer_info = tlv(0x30, &si);

    let mut sd = tlv(0x02, &[3]);
    sd.extend_from_slice(&tlv(0x31, &alg_id(OID_SHA256, true)));
    let mut eci = oid_tlv(OID_TST_INFO);
    eci.extend_from_slice(&tlv(0xA0, &tlv(0x04, tst_der)));
    sd.extend_from_slice(&tlv(0x30, &eci));
    sd.extend_from_slice(&tlv(0xA0, &tsa.cert_der));
    sd.extend_from_slice(&tlv(0x31, &signer_info));
    let signed_data = tlv(0x30, &sd);

    let mut ci = oid_tlv(OID_SIGNED_DATA);
    ci.extend_from_slice(&tlv(0xA0, &signed_data));
    tlv(0x30, &ci)
}
