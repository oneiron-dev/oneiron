//! Profile assembly tests: operation ids, error mapping, DSS bounds, CRL freshness and gather rows.

#![allow(clippy::unwrap_used)]
use super::*;

use crate::api::{BackendError, FetchPolicy};

use std::sync::Arc;

use der::{Decode, Encode};

use super::super::cms;
use crate::api::{
    FetchRequest, SealBackend, SealConfig, SealFetcher, SignDigestRequest, SignatureAlgorithm,
    SigningIdentity,
};
use crate::error::SealError;

#[test]
fn key_bound_issuer_ignores_position_and_binds_by_key() {
    let root = crl_ca();
    let inter = child_crl_ca(&root, "inter", None);
    let leaf = leaf_with_crl_dp(&inter, "leaf", "https://crl.example.test/i.crl");
    // A deliberately shuffled set: the issuer is found by key, never by
    // the next slot.
    let shuffled = vec![inter.cert_der.clone(), leaf.clone()];
    assert_eq!(
        key_bound_issuer(&leaf, &shuffled, &[]),
        Some(inter.cert_der.as_slice())
    );
    // Anchor-omitted tip: resolves to the anchor, not to itself or a
    // positional neighbor.
    assert_eq!(
        key_bound_issuer(
            &inter.cert_der,
            &shuffled,
            std::slice::from_ref(&root.cert_der)
        ),
        Some(root.cert_der.as_slice())
    );
    // A self-signed tip still resolves to itself.
    assert_eq!(
        key_bound_issuer(&root.cert_der, std::slice::from_ref(&root.cert_der), &[]),
        Some(root.cert_der.as_slice())
    );
    // Issuer unknown (not in the chain, not an anchor): None — never a
    // positional guess.
    assert_eq!(
        key_bound_issuer(&leaf, std::slice::from_ref(&leaf), &[]),
        None
    );
}

#[test]
fn dss_uses_global_arrays_and_omits_vri() {
    let material = DssMaterial {
        certs_der: vec![vec![0x30, 0x03, 0x02, 0x01, 0x01]],
        ocsps_der: vec![vec![0x30, 0x00]],
        crls_der: vec![vec![0x30, 0x00]],
    };
    let (objs, dss_num) = build_dss_objects(&material, 10).unwrap();
    let dss = objs
        .iter()
        .find(|(n, _)| *n == dss_num)
        .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
        .unwrap();
    assert!(dss.contains("/Type /DSS"));
    assert!(dss.contains("/Certs [10 0 R]"));
    assert!(dss.contains("/OCSPs [11 0 R]"));
    assert!(dss.contains("/CRLs [12 0 R]"));
    assert!(!dss.contains("/VRI"), "VRI is not emitted in v1");
    // Stream objects carry exact lengths.
    let cert_obj = &objs.iter().find(|(n, _)| *n == 10).unwrap().1;
    assert!(cert_obj.starts_with(b"<< /Length 5 >>\nstream\n"));
}

#[test]
fn build_dss_objects_checked_at_object_number_boundary() {
    // P2-1: object numbers are allocated with checked arithmetic — at
    // the u32 boundary the assembler must fail clean, never panic
    // (debug) or wrap (release).
    let material = DssMaterial {
        certs_der: vec![vec![0x30, 0x00]],
        ocsps_der: Vec::new(),
        crls_der: Vec::new(),
    };
    let err = build_dss_objects(&material, u32::MAX).unwrap_err();
    assert!(matches!(
        err,
        SealError::InputInvalid {
            code: crate::error::InputInvalidCode::ObjectLimitExceeded
        }
    ));
    // Just inside the space still works: cert at MAX-2, DSS dict at
    // MAX-1 (allocation mirrors pdf's next_obj: a number without a
    // successor fails conservatively).
    let (objs, dss_num) = build_dss_objects(&material, u32::MAX - 2).unwrap();
    assert_eq!(dss_num, u32::MAX - 1);
    assert_eq!(objs.len(), 2);
}

// --- fetch_valid_crl seal-side rows (§7.5 step 3 freshness) -----------

/// 2026-07-30T08:00:00Z — matches the verify-side applicable time.
const CRL_NOW_SECS: u64 = 1_785_398_400;

struct StaticFetcher(Vec<u8>);

#[async_trait::async_trait]
impl SealFetcher for StaticFetcher {
    async fn fetch(
        &self,
        _request: FetchRequest,
    ) -> Result<crate::api::FetchResponse, crate::api::FetchError> {
        Ok(crate::api::FetchResponse {
            body: self.0.clone(),
            content_type: None,
        })
    }
}

struct NoopBackend;

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
    ) -> Result<crate::api::BackendSignature, BackendError> {
        Err(BackendError::Unavailable {
            retry_after_ms: None,
        })
    }
}

struct CrlCa {
    cert_der: Vec<u8>,
    key: p256::ecdsa::SigningKey,
    subject: x509_cert::name::Name,
    rcgen_params: rcgen::CertificateParams,
    rcgen_key: rcgen::KeyPair,
}

fn crl_ca_params(cn: &str) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn.to_string());
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
}

fn crl_ca_from(params: rcgen::CertificateParams, key_pair: rcgen::KeyPair, der: Vec<u8>) -> CrlCa {
    use p256::pkcs8::DecodePrivateKey;
    let parsed = x509_cert::Certificate::from_der(&der).unwrap();
    CrlCa {
        cert_der: der,
        key: p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap(),
        subject: parsed.tbs_certificate.subject,
        rcgen_params: params,
        rcgen_key: key_pair,
    }
}

fn crl_ca() -> CrlCa {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = crl_ca_params("crl-ca");
    let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();
    crl_ca_from(params, key_pair, cert_der)
}

/// A child CA issued by `parent` (fresh key pair), optionally carrying
/// one CRL DP URL.
fn child_crl_ca(parent: &CrlCa, cn: &str, dp: Option<&str>) -> CrlCa {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = crl_ca_params(cn);
    if let Some(url) = dp {
        params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
            uris: vec![url.to_string()],
        }];
    }
    let issuer = rcgen::Issuer::from_params(&parent.rcgen_params, &parent.rcgen_key);
    let cert_der = params.signed_by(&key_pair, &issuer).unwrap().der().to_vec();
    crl_ca_from(params, key_pair, cert_der)
}

/// A non-CA leaf issued by `issuer_ca` carrying one CRL DP URL.
fn leaf_with_crl_dp(issuer_ca: &CrlCa, cn: &str, url: &str) -> Vec<u8> {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn.to_string());
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    // rcgen 0.14 skips the extension block unless a CA flag demands it;
    // ExplicitNoCa writes basicConstraints CA:FALSE plus the CRL DP.
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
        uris: vec![url.to_string()],
    }];
    let issuer = rcgen::Issuer::from_params(&issuer_ca.rcgen_params, &issuer_ca.rcgen_key);
    params.signed_by(&key_pair, &issuer).unwrap().der().to_vec()
}

fn x509_time(secs: u64) -> x509_cert::time::Time {
    x509_cert::time::Time::GeneralTime(
        der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(secs))
            .unwrap(),
    )
}

fn signed_crl(ca: &CrlCa, this: u64, next: Option<u64>) -> Vec<u8> {
    signed_crl_ext(ca, this, next, Vec::new())
}

fn signed_crl_ext(
    ca: &CrlCa,
    this: u64,
    next: Option<u64>,
    crl_extensions: Vec<x509_cert::ext::Extension>,
) -> Vec<u8> {
    use der::Encode;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::Digest;
    let alg = spki::AlgorithmIdentifierOwned {
        oid: cms::OID_ECDSA_SHA256,
        parameters: None,
    };
    let tbs = x509_cert::crl::TbsCertList {
        version: x509_cert::Version::V2,
        signature: alg.clone(),
        issuer: ca.subject.clone(),
        this_update: x509_time(this),
        next_update: next.map(x509_time),
        revoked_certificates: None,
        crl_extensions: if crl_extensions.is_empty() {
            None
        } else {
            Some(crl_extensions)
        },
    };
    let tbs_der = tbs.to_der().unwrap();
    let digest = sha2::Sha256::digest(&tbs_der);
    let sig: p256::ecdsa::Signature = ca.key.sign_prehash(&digest).unwrap();
    x509_cert::crl::CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: alg,
        signature: der::asn1::BitString::from_bytes(sig.to_der().as_bytes()).unwrap(),
    }
    .to_der()
    .unwrap()
}

fn crl_ctx<'a>(
    config: &'a SealConfig,
    backend: &'a Arc<dyn SealBackend>,
    fetcher: &'a Arc<dyn SealFetcher>,
) -> SealContext<'a> {
    SealContext {
        config,
        backend,
        fetcher,
        clock_ms: CRL_NOW_SECS * 1000,
    }
}

#[tokio::test]
async fn fetch_valid_crl_rejects_stale_next_update() {
    let ca = crl_ca();
    let crl = signed_crl(&ca, CRL_NOW_SECS - 7200, Some(CRL_NOW_SECS - 60));
    let config = SealConfig {
        trust_anchors_der: Vec::new(),
        timestamp_authorities: Vec::new(),
        fetch_policy: FetchPolicy::default(),
        resource_limits: crate::api::SealResourceLimits::default(),
    };
    let backend: Arc<dyn SealBackend> = Arc::new(NoopBackend);
    let fetcher: Arc<dyn SealFetcher> = Arc::new(StaticFetcher(crl));
    let ctx = crl_ctx(&config, &backend, &fetcher);
    let url = url::Url::parse("https://crl.example.test/ca.crl").unwrap();
    assert!(fetch_valid_crl(&ctx, &ca.cert_der, url).await.is_none());
}

#[tokio::test]
async fn fetch_valid_crl_rejects_delta_and_idp_scoped_crls() {
    // The seal side mirrors the verify-side complete-scope posture: a
    // delta or IDP-scoped CRL gathered here would fail the embedded
    // self-verify, so it is refused at fetch time instead.
    for ext in [
        x509_cert::ext::Extension {
            extn_id: der::asn1::ObjectIdentifier::new_unwrap("2.5.29.46"),
            critical: false,
            extn_value: der::asn1::OctetString::new(
                der::asn1::Int::new(&[1]).unwrap().to_der().unwrap(),
            )
            .unwrap(),
        },
        x509_cert::ext::Extension {
            extn_id: der::asn1::ObjectIdentifier::new_unwrap("2.5.29.28"),
            critical: false,
            extn_value: der::asn1::OctetString::new(vec![0x30, 0x00]).unwrap(),
        },
    ] {
        let ca = crl_ca();
        let crl = signed_crl_ext(
            &ca,
            CRL_NOW_SECS - 3600,
            Some(CRL_NOW_SECS + 3600),
            vec![ext],
        );
        let config = SealConfig {
            trust_anchors_der: Vec::new(),
            timestamp_authorities: Vec::new(),
            fetch_policy: FetchPolicy::default(),
            resource_limits: crate::api::SealResourceLimits::default(),
        };
        let backend: Arc<dyn SealBackend> = Arc::new(NoopBackend);
        let fetcher: Arc<dyn SealFetcher> = Arc::new(StaticFetcher(crl));
        let ctx = crl_ctx(&config, &backend, &fetcher);
        let url = url::Url::parse("https://crl.example.test/ca.crl").unwrap();
        assert!(
            fetch_valid_crl(&ctx, &ca.cert_der, url).await.is_none(),
            "scoped CRL must not be gathered as complete evidence"
        );
    }
}

// --- gather_validation_material issuer key-binding rows ----------------

struct MapFetcher(std::collections::HashMap<String, Vec<u8>>);

#[async_trait::async_trait]
impl SealFetcher for MapFetcher {
    async fn fetch(
        &self,
        request: FetchRequest,
    ) -> Result<crate::api::FetchResponse, crate::api::FetchError> {
        self.0
            .get(request.url.as_str())
            .cloned()
            .map(|body| crate::api::FetchResponse {
                body,
                content_type: None,
            })
            .ok_or(crate::api::FetchError::Unavailable)
    }
}

fn gather_config(anchors: Vec<Vec<u8>>) -> SealConfig {
    SealConfig {
        trust_anchors_der: anchors,
        timestamp_authorities: Vec::new(),
        fetch_policy: FetchPolicy::default(),
        resource_limits: crate::api::SealResourceLimits::default(),
    }
}

fn p256_identity_for(cert_der: Vec<u8>, chain_der: Vec<Vec<u8>>) -> SigningIdentity {
    SigningIdentity {
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        signer_certificate_der: cert_der,
        certificate_chain_der: chain_der,
    }
}

/// A CA-legal intermediate (keyCertSign present so path validation
/// accepts it) issued by `parent`, optionally carrying one CRL DP URL.
fn child_path_ca(parent: &CrlCa, cn: &str, dp: Option<&str>) -> CrlCa {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn.to_string());
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    if let Some(url) = dp {
        params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
            uris: vec![url.to_string()],
        }];
    }
    let issuer = rcgen::Issuer::from_params(&parent.rcgen_params, &parent.rcgen_key);
    let cert_der = params.signed_by(&key_pair, &issuer).unwrap().der().to_vec();
    crl_ca_from(params, key_pair, cert_der)
}

#[tokio::test]
async fn gather_chain_cert_without_crl_dp_degrades_not_zero_evidence_lt() {
    // The intermediate advertises no CRL DP: it counts UNCOVERED, so the
    // gather fails closed (the assembler degrades to B-T with
    // ValidationMaterialUnavailable) instead of self-reporting B-LT on
    // material that says nothing about one chain certificate.
    let root = crl_ca();
    let inter = child_path_ca(&root, "inter-no-dp", None);
    let leaf = leaf_with_crl_dp(&inter, "leaf", "https://crl.example.test/i.crl");
    let inter_crl = signed_crl(&inter, CRL_NOW_SECS - 3600, Some(CRL_NOW_SECS + 3600));
    let mut map = std::collections::HashMap::new();
    map.insert("https://crl.example.test/i.crl".to_string(), inter_crl);
    let config = gather_config(vec![root.cert_der.clone()]);
    let backend: Arc<dyn SealBackend> = Arc::new(NoopBackend);
    let fetcher: Arc<dyn SealFetcher> = Arc::new(MapFetcher(map));
    let ctx = crl_ctx(&config, &backend, &fetcher);
    let identity = p256_identity_for(leaf, vec![inter.cert_der.clone()]);
    let material = gather_validation_material(&ctx, &identity, None).await;
    assert!(
        material.is_none(),
        "a non-anchor chain cert with no CRL DP must degrade the gather"
    );
    // Control: with the intermediate's DP advertised and served, the
    // same chain gathers fully.
    let inter_dp = child_path_ca(&root, "inter-dp", Some("https://crl.example.test/r.crl"));
    let leaf2 = leaf_with_crl_dp(&inter_dp, "leaf", "https://crl.example.test/i.crl");
    let root_crl = signed_crl(&root, CRL_NOW_SECS - 3600, Some(CRL_NOW_SECS + 3600));
    let inter_crl2 = signed_crl(&inter_dp, CRL_NOW_SECS - 3600, Some(CRL_NOW_SECS + 3600));
    let mut map = std::collections::HashMap::new();
    map.insert("https://crl.example.test/i.crl".to_string(), inter_crl2);
    map.insert("https://crl.example.test/r.crl".to_string(), root_crl);
    let fetcher: Arc<dyn SealFetcher> = Arc::new(MapFetcher(map));
    let ctx = crl_ctx(&config, &backend, &fetcher);
    let identity = p256_identity_for(leaf2, vec![inter_dp.cert_der.clone()]);
    let material = gather_validation_material(&ctx, &identity, None).await;
    assert_eq!(
        material.map(|m| m.crls_der.len()),
        Some(2),
        "fully advertised chains still gather every CRL"
    );
}
