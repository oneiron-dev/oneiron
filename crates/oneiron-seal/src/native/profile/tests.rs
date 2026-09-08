//! Profile assembly tests: operation ids, error mapping, DSS bounds, CRL freshness and gather rows.

#![allow(clippy::unwrap_used)]
use super::*;

use crate::api::{BackendError, BackendRejectCode, FetchPolicy};

use std::sync::Arc;

use der::{Decode, Encode};

use super::super::{cms, tsp};
use crate::api::{
    FetchRequest, SealBackend, SealConfig, SealFetcher, SignDigestRequest, SignatureAlgorithm,
    SigningIdentity,
};
use crate::error::{FatalCode, RetryableCode, SealError, SealStage};

#[test]
fn sub_operation_id_stable_and_phase_capacity_distinct() {
    let sha = [1u8; 32];
    let a = sub_operation_id("op", &sha, "sign", 65536);
    assert_eq!(a, sub_operation_id("op", &sha, "sign", 65536));
    assert_ne!(a, sub_operation_id("op", &sha, "sign", 131072));
    assert_ne!(a, sub_operation_id("op", &sha, "doc-ts", 65536));
    assert_ne!(a, sub_operation_id("op", &[2u8; 32], "sign", 65536));
    assert!(a.starts_with("op:"));
}

#[test]
fn sub_operation_id_at_max_caller_id_still_fits_backend_bound() {
    // The reserve budget is honest: a caller id at the validation
    // boundary plus the largest real suffix stays inside 256 bytes.
    let sha = [7u8; 32];
    let max_caller = crate::api::MAX_OPERATION_ID_BYTES - crate::api::OPERATION_ID_SUFFIX_RESERVE;
    let id = "x".repeat(max_caller);
    for capacity in CAPACITY_LADDER {
        let derived = sub_operation_id(&id, &sha, "sign", capacity);
        assert!(
            derived.len() <= crate::api::MAX_OPERATION_ID_BYTES,
            "derived id overflows the backend bound: {}",
            derived.len()
        );
    }
}

#[test]
fn backend_error_mapping_matches_taxonomy() {
    let unavailable = map_backend_error(BackendError::Unavailable {
        retry_after_ms: Some(5),
    });
    assert!(matches!(
        unavailable,
        SealError::BackendUnavailable {
            retry_after_ms: Some(5)
        }
    ));
    assert!(unavailable.is_retryable());
    let limited = map_backend_error(BackendError::RateLimited {
        retry_after_ms: None,
    });
    assert!(matches!(
        limited,
        SealError::Retryable {
            stage: SealStage::BackendSign,
            code: RetryableCode::TemporaryBackendFailure,
            ..
        }
    ));
    let rejected = map_backend_error(BackendError::Rejected {
        code: BackendRejectCode::Unauthorized,
    });
    assert!(matches!(
        rejected,
        SealError::Fatal {
            stage: SealStage::BackendSign,
            code: FatalCode::BackendRejected,
        }
    ));
    assert!(!rejected.is_retryable());
}

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

#[test]
fn near_boundary_trailer_size_dss_revision_fails_clean() {
    // P2-1 end-to-end: a crafted trailer /Size lets the signature
    // revision succeed, then B-LT DSS assembly must yield
    // ObjectLimitExceeded — no panic, no wrap.
    let bytes = std::fs::read(format!(
        "{}/tests/fixtures/pdf-input/classic_1page.pdf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let patched = text.replace("/Size 4 ", "/Size 4294967294 ");
    assert_ne!(patched, text, "trailer /Size must be patched");
    let config = SealConfig {
        trust_anchors_der: Vec::new(),
        timestamp_authorities: Vec::new(),
        fetch_policy: FetchPolicy::default(),
        resource_limits: crate::api::SealResourceLimits::default(),
    };
    let backend: Arc<dyn SealBackend> = Arc::new(NoopBackend);
    let fetcher: Arc<dyn SealFetcher> = Arc::new(StaticFetcher(Vec::new()));
    let ctx = crl_ctx(&config, &backend, &fetcher);
    let material = DssMaterial {
        certs_der: vec![vec![0x30, 0x00], vec![0x30, 0x00]],
        ocsps_der: Vec::new(),
        crls_der: vec![vec![0x30, 0x00]],
    };
    let err = append_dss(patched.as_bytes(), &ctx, &material).unwrap_err();
    assert!(matches!(
        err,
        SealError::InputInvalid {
            code: crate::error::InputInvalidCode::ObjectLimitExceeded
        }
    ));
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

/// A CA whose KeyUsage omits cRLSign: its key CAN sign a CRL, but the
/// certificate does not authorize that use.
fn crl_ca_without_crl_sign() -> CrlCa {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = crl_ca_params("crl-ca-unauthorized");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
    ];
    let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();
    crl_ca_from(params, key_pair, cert_der)
}

/// A CA with no KeyUsage extension at all (unconstrained key, RFC 5280
/// §4.2.1.3 posture).
fn crl_ca_no_key_usage() -> CrlCa {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = crl_ca_params("crl-ca-no-ku");
    params.key_usages = Vec::new();
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
async fn fetch_valid_crl_accepts_fresh_crl() {
    let ca = crl_ca();
    let crl = signed_crl(&ca, CRL_NOW_SECS - 3600, Some(CRL_NOW_SECS + 3600));
    let config = SealConfig {
        trust_anchors_der: Vec::new(),
        timestamp_authorities: Vec::new(),
        fetch_policy: FetchPolicy::default(),
        resource_limits: crate::api::SealResourceLimits::default(),
    };
    let backend: Arc<dyn SealBackend> = Arc::new(NoopBackend);
    let fetcher: Arc<dyn SealFetcher> = Arc::new(StaticFetcher(crl.clone()));
    let ctx = crl_ctx(&config, &backend, &fetcher);
    let url = url::Url::parse("https://crl.example.test/ca.crl").unwrap();
    let got = fetch_valid_crl(&ctx, &ca.cert_der, url).await;
    assert_eq!(got, Some(crl));
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
async fn fetch_valid_crl_rejects_issuer_without_crl_sign() {
    // Seal-side mirror of the verify-side issuer KeyUsage gate: a CRL
    // whose issuer KU omits cRLSign would fail the mandatory
    // self-verify if embedded, so it is refused at fetch time — the
    // gather degrades to B-T instead of poisoning the artifact.
    let url = url::Url::parse("https://crl.example.test/ca.crl").unwrap();
    let fresh = |ca: &CrlCa| signed_crl(ca, CRL_NOW_SECS - 3600, Some(CRL_NOW_SECS + 3600));
    let mk_parts = |crl: Vec<u8>| {
        let config = SealConfig {
            trust_anchors_der: Vec::new(),
            timestamp_authorities: Vec::new(),
            fetch_policy: FetchPolicy::default(),
            resource_limits: crate::api::SealResourceLimits::default(),
        };
        let backend: Arc<dyn SealBackend> = Arc::new(NoopBackend);
        let fetcher: Arc<dyn SealFetcher> = Arc::new(StaticFetcher(crl));
        (config, backend, fetcher)
    };
    let unauthorized = crl_ca_without_crl_sign();
    let (config, backend, fetcher) = mk_parts(fresh(&unauthorized));
    let ctx = crl_ctx(&config, &backend, &fetcher);
    assert!(
        fetch_valid_crl(&ctx, &unauthorized.cert_der, url.clone())
            .await
            .is_none(),
        "issuer KU without cRLSign must be refused at fetch time"
    );
    // Controls: the gate rejects unauthorized USE, not CRLs in general —
    // an asserting KU or an absent KU both pass with the same fresh CRL.
    let asserting = crl_ca();
    let (config, backend, fetcher) = mk_parts(fresh(&asserting));
    let ctx = crl_ctx(&config, &backend, &fetcher);
    assert!(
        fetch_valid_crl(&ctx, &asserting.cert_der, url.clone())
            .await
            .is_some(),
        "issuer KU asserting cRLSign passes"
    );
    let unconstrained = crl_ca_no_key_usage();
    let (config, backend, fetcher) = mk_parts(fresh(&unconstrained));
    let ctx = crl_ctx(&config, &backend, &fetcher);
    assert!(
        fetch_valid_crl(&ctx, &unconstrained.cert_der, url)
            .await
            .is_some(),
        "absent KeyUsage follows the RFC 5280 §4.2.1.3 posture and passes"
    );
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

#[tokio::test]
async fn gather_shuffled_tsa_chain_still_binds_issuers_by_key() {
    // CMS SET OF order is arbitrary: the TSA chain arrives as
    // [intermediate, tsa-leaf]. Positional issuer picks would verify
    // each CRL against the wrong cert and falsely degrade to B-T.
    let signer = crl_ca();
    let root = crl_ca();
    let inter = child_crl_ca(
        &root,
        "tsa-inter",
        Some("https://crl.example.test/root.crl"),
    );
    let tsa_leaf = leaf_with_crl_dp(&inter, "tsa-leaf", "https://crl.example.test/inter.crl");
    let root_crl = signed_crl(&root, CRL_NOW_SECS - 3600, Some(CRL_NOW_SECS + 3600));
    let inter_crl = signed_crl(&inter, CRL_NOW_SECS - 3600, Some(CRL_NOW_SECS + 3600));
    let mut map = std::collections::HashMap::new();
    map.insert("https://crl.example.test/root.crl".to_string(), root_crl);
    map.insert("https://crl.example.test/inter.crl".to_string(), inter_crl);
    let config = gather_config(vec![signer.cert_der.clone(), root.cert_der.clone()]);
    let backend: Arc<dyn SealBackend> = Arc::new(NoopBackend);
    let fetcher: Arc<dyn SealFetcher> = Arc::new(MapFetcher(map));
    let ctx = crl_ctx(&config, &backend, &fetcher);
    let identity = p256_identity_for(signer.cert_der.clone(), Vec::new());
    let token = tsp::ValidatedToken {
        content_info_der: Vec::new(),
        tsa_chain_ders: vec![inter.cert_der.clone(), tsa_leaf],
    };
    let material = gather_validation_material(&ctx, &identity, Some(&token)).await;
    assert_eq!(
        material.map(|m| m.crls_der.len()),
        Some(2),
        "both TSA-chain CRLs must gather despite the shuffled set"
    );
}

#[tokio::test]
async fn gather_anchor_omitted_tip_resolves_issuer_to_anchor() {
    // The signer leaf's issuer is the trust anchor and is NOT embedded
    // in the chain; the CRL must be fetched against the anchor's key.
    let root = crl_ca();
    let leaf = leaf_with_crl_dp(&root, "signer-leaf", "https://crl.example.test/root.crl");
    let root_crl = signed_crl(&root, CRL_NOW_SECS - 3600, Some(CRL_NOW_SECS + 3600));
    let mut map = std::collections::HashMap::new();
    map.insert("https://crl.example.test/root.crl".to_string(), root_crl);
    let config = gather_config(vec![root.cert_der.clone()]);
    let backend: Arc<dyn SealBackend> = Arc::new(NoopBackend);
    let fetcher: Arc<dyn SealFetcher> = Arc::new(MapFetcher(map));
    let ctx = crl_ctx(&config, &backend, &fetcher);
    let identity = p256_identity_for(leaf, Vec::new());
    let material = gather_validation_material(&ctx, &identity, None).await;
    assert_eq!(
        material.map(|m| m.crls_der.len()),
        Some(1),
        "anchor-omitted tip must gather its CRL against the anchor"
    );
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
