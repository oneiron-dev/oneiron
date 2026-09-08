//! Trust entry: VerifyCtx, the KeyUsage turnstile, chain validation, anchor loading, verify_document and profile classify.

use lopdf::{Document, LoadOptions};

use crate::api::{
    PadesProfile, SealConfig, VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode, VerifyReport,
};
use crate::error::{InputInvalidCode, SealError};

use super::super::cms;
use super::verify_dss_core::{EmbeddedCert, dss_revision_end, verify_dss};
use super::verify_sig_pipeline::{Checks, collect_signatures, verify_cades_sig, verify_doc_ts};

pub(crate) struct VerifyCtx<'a> {
    pub config: &'a SealConfig,
    pub clock_ms: u64,
}

pub(super) fn malformed_input() -> SealError {
    SealError::InputInvalid {
        code: InputInvalidCode::MalformedXref,
    }
}

fn cert_path_err() -> SealError {
    SealError::Fatal {
        stage: crate::error::SealStage::Verification,
        code: crate::error::FatalCode::CertificatePathInvalid,
    }
}

/// The ONE KeyUsage turnstile every KU gate in this crate rides.
///
/// Three call sites (signer leaf, CRL issuer, OCSP delegate) must each stay
/// fail-CLOSED on a malformed extension, so they share one body rather than
/// three hand-rolled walks that can drift apart:
/// - extensions absent, or no KeyUsage among them ⇒ `true`. RFC 5280
///   §4.2.1.3: an absent KeyUsage leaves the key unconstrained.
/// - KeyUsage PRESENT but its DER does not decode ⇒ `false`. A usage
///   restriction we cannot read is not a restriction we may ignore.
/// - KeyUsage present and readable ⇒ whatever `permits` says about it.
///
/// The matching extension decides: the walk returns on the first KeyUsage
/// OID rather than continuing, so a second (non-DER-legal) copy cannot
/// launder a verdict the first one already refused.
pub(super) fn key_usage_permits(
    cert: &x509_cert::Certificate,
    permits: impl Fn(&x509_cert::ext::pkix::KeyUsage) -> bool,
) -> bool {
    use const_oid::AssociatedOid;
    use der::Decode;
    use x509_cert::ext::pkix::KeyUsage;
    let Some(exts) = &cert.tbs_certificate.extensions else {
        return true;
    };
    for ext in exts {
        if ext.extn_id == KeyUsage::OID {
            let Ok(ku) = KeyUsage::from_der(ext.extn_value.as_bytes()) else {
                return false;
            };
            return permits(&ku);
        }
    }
    true
}

/// Signer-leaf key-usage gate: when the leaf carries a KeyUsage extension it
/// must permit signing — `digitalSignature` or `contentCommitment`
/// (nonRepudiation). Any other class (e.g. keyEncipherment-only) cannot act
/// as a signing identity. An ABSENT KeyUsage follows RFC 5280 §4.2.1.3 (the
/// key is unconstrained) and passes; this mirrors the vendored pkix-chain
/// TSA profile's treatment of a missing extension. The TSA chain does not
/// ride this gate: tsp.rs keeps it on the vendored `verify_time_stamper`
/// profile, which enforces the RFC 3161 signing-only shape.
pub(super) fn enforce_signer_leaf_key_usage(
    leaf: &x509_cert::Certificate,
) -> Result<(), SealError> {
    if key_usage_permits(leaf, |ku| ku.digital_signature() || ku.non_repudiation()) {
        Ok(())
    } else {
        Err(cert_path_err())
    }
}

/// CRL-issuer key-usage gate: when the issuer certificate carries a KeyUsage
/// extension it must assert `cRLSign` — a key verified to have signed a CRL
/// is not enough; the certificate must also AUTHORIZE that use. An ABSENT
/// KeyUsage follows the same documented RFC 5280 §4.2.1.3 posture as the
/// signer-leaf gate (unconstrained key, passes). Shared with the seal-side
/// CRL gather (profile.rs fetch_valid_crl): material that would fail this
/// gate at verify time is refused at fetch time, so an unauthorized-issuer
/// CRL degrades the profile instead of poisoning the sealed artifact.
pub(crate) fn issuer_permits_crl_sign(cert: &x509_cert::Certificate) -> bool {
    key_usage_permits(cert, x509_cert::ext::pkix::KeyUsage::crl_sign)
}

/// RFC 5280 path validation against configured trust anchors at the
/// applicable time, plus the signer-leaf key-usage gate. Shared by the
/// assembler (B-LT chain pre-check) and the verifier.
pub(crate) fn validate_chain(
    chain_ders: &[Vec<u8>],
    anchors: &[pkix_chain::TrustAnchor],
    at_unix: u64,
) -> Result<(), SealError> {
    use der::Decode;
    let chain: Vec<x509_cert::Certificate> = chain_ders
        .iter()
        .map(|d| x509_cert::Certificate::from_der(d))
        .collect::<Result<_, _>>()
        .map_err(|_| cert_path_err())?;
    pkix_chain::verify_chain(
        &chain,
        anchors,
        &pkix_chain::ValidationPolicy::new(at_unix),
        &pkix_chain::DefaultVerifier,
        &pkix_chain::NoRevocation,
        &pkix_chain::NoAiaFetcher,
    )
    .map_err(|_| cert_path_err())?;
    if let Some(leaf) = chain.first() {
        enforce_signer_leaf_key_usage(leaf)?;
    }
    Ok(())
}

pub(super) fn anchors(config: &SealConfig) -> Vec<pkix_chain::TrustAnchor> {
    use der::Decode;
    config
        .trust_anchors_der
        .iter()
        .filter_map(|d| x509_cert::Certificate::from_der(d).ok())
        .map(pkix_chain::TrustAnchor::from_cert)
        .collect()
}

/// Full document verification and profile classification (§7.7).
pub(crate) fn verify_document(
    bytes: &[u8],
    ctx: &VerifyCtx<'_>,
) -> Result<VerifyReport, SealError> {
    let limits = &ctx.config.resource_limits;
    let evidence_sha256 = cms::sha256(bytes);
    if bytes.is_empty() {
        return Err(SealError::InputInvalid {
            code: InputInvalidCode::Empty,
        });
    }
    if bytes.len() > limits.max_input_bytes {
        return Err(SealError::InputInvalid {
            code: InputInvalidCode::TooLarge,
        });
    }
    if !bytes.starts_with(b"%PDF-") {
        return Err(SealError::InputInvalid {
            code: InputInvalidCode::NotPdf,
        });
    }
    let options = LoadOptions {
        strict: true,
        max_decompressed_size: Some(limits.max_input_bytes),
        ..LoadOptions::default()
    };
    let doc = Document::load_mem_with_options(bytes, options).map_err(|_| malformed_input())?;
    // Byte/decompress limits ride the loader; the object-count cap does
    // not — enforce it here exactly as the seal side does.
    if doc.objects.len() > limits.max_pdf_objects {
        return Err(SealError::InputInvalid {
            code: InputInvalidCode::ObjectLimitExceeded,
        });
    }
    let mut checks = Checks::new();
    // Legal revision chain and final EOF: the strict parse plus an EOF tail
    // (an optional single trailing EOL is tolerated for interoperability).
    let eof_ok = bytes
        .strip_suffix(b"\n")
        .or_else(|| bytes.strip_suffix(b"\r\n"))
        .unwrap_or(bytes)
        .ends_with(b"%%EOF");
    checks.record(
        VerifyCheckKind::PdfRevision,
        eof_ok,
        VerifyFindingCode::InvalidPdfRevision,
    );
    let anchors = anchors(ctx.config);
    let anchor_certs: Vec<EmbeddedCert> = ctx
        .config
        .trust_anchors_der
        .iter()
        .filter_map(|d| EmbeddedCert::from_der(d))
        .collect();
    let sigs = collect_signatures(&doc)?;
    let last_idx = sigs.len().saturating_sub(1);
    let mut saw_cades = false;
    // Certificates of the CMS signer/TSA chains this report covers; the DSS
    // binding requires the validation material to speak about them.
    let mut covered: Vec<EmbeddedCert> = Vec::new();
    // genTime of the most recent VALIDATED DocTimeStamp whose ByteRange
    // provably covers the final /DSS revision: the archival applicable time
    // for DSS evidence freshness (§7.6 step 3 — the DocTimeStamp covers the
    // DSS revision and attests the material as of that moment). A validated
    // DocTimeStamp that does NOT cover the /DSS attests nothing about the
    // evidence, so its genTime must not feed freshness; with no covering
    // DocTimeStamp the verify clock applies and stale evidence fails.
    let dss_end = dss_revision_end(&doc, bytes);
    let mut archival_time: Option<u64> = None;
    // Set when a VALIDATED DocTimeStamp provably covers the final /DSS
    // revision (br_end >= dss_end — the archival_time condition). The LTA
    // rung requires it: a validated DocTimeStamp that does NOT cover the
    // /DSS keeps its DocumentTimestamp check for the report but confers no
    // archival profile.
    let mut covering_dts_valid = false;
    for (i, e) in sigs.iter().enumerate() {
        if e.is_doc_ts {
            if let Some(gen_time) = verify_doc_ts(
                bytes,
                e,
                &anchors,
                &mut checks,
                i == last_idx,
                &mut covered,
                ctx.clock_ms,
            ) {
                let br_end = e.byte_range[2].saturating_add(e.byte_range[3]);
                if dss_end.is_some_and(|end| br_end >= end) {
                    archival_time = Some(gen_time);
                    covering_dts_valid = true;
                }
            }
        } else {
            saw_cades = true;
            verify_cades_sig(bytes, e, ctx, &anchors, &mut checks, &mut covered);
        }
    }
    if !saw_cades {
        checks.absent(VerifyCheckKind::SignatureTimestamp);
    }
    verify_dss(
        &doc,
        &anchor_certs,
        &covered,
        archival_time.unwrap_or(ctx.clock_ms / 1000),
        limits.max_input_bytes,
        &mut checks,
    );
    let valid = saw_cades
        && eof_ok
        && !checks
            .list
            .iter()
            .any(|c| c.status == VerifyCheckStatus::Fail);
    let achieved = classify(&checks, valid, covering_dts_valid);
    Ok(VerifyReport {
        valid,
        achieved_profile: achieved,
        evidence_sha256,
        checks: checks.list,
    })
}

/// Highest achieved baseline profile from the check outcomes. The archival
/// rung requires a VALIDATED DocTimeStamp that provably covers the final
/// /DSS revision: `lt` already implies a present, valid DSS, so a
/// non-covering (or absent) DocTimeStamp tops out at B-LT even when its
/// DocumentTimestamp check passes.
pub(super) fn classify(
    checks: &Checks,
    valid: bool,
    covering_dts_valid: bool,
) -> Option<PadesProfile> {
    if !valid {
        return None;
    }
    let t = checks.passed(VerifyCheckKind::SignatureTimestamp);
    let lt = t && checks.passed(VerifyCheckKind::ValidationMaterial);
    let lta = lt && checks.passed(VerifyCheckKind::DocumentTimestamp) && covering_dts_valid;
    if lta {
        Some(PadesProfile::BaselineLta)
    } else if lt {
        Some(PadesProfile::BaselineLt)
    } else if t {
        Some(PadesProfile::BaselineT)
    } else {
        Some(PadesProfile::BaselineB)
    }
}
