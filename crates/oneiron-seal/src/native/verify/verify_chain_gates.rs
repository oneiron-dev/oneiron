//! Trust entry: VerifyCtx, the KeyUsage turnstile, chain validation, anchor loading, verify_document and profile classify.

use lopdf::{Document, LoadOptions};

use crate::api::{
    Modifications, SealConfig, VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode, VerifyReport,
};
use crate::error::{InputInvalidCode, SealError};

use super::super::{cms, pdf};
use super::evidence_time::{
    archival_coverage, material_validation_time, provisional_material_time, signer_validation_time,
};
use super::verify_dss_core::{EmbeddedCert, dss_revision_end, verify_dss};
use super::verify_report_build::{classify_signature, signature_report};
use super::verify_revisions;
use super::verify_sig_pipeline::{Checks, collect_signatures, evaluate_envelope};

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

/// Only a missing path/anchor is unresolved trust. A constructed path that
/// violates a certificate constraint has conclusively failed validation.
pub(crate) fn pkix_path_status(error: &pkix_chain::Error) -> VerifyCheckStatus {
    match error {
        pkix_chain::Error::Path(pkix_chain::pkix_path::Error::NoTrustedPath)
        | pkix_chain::Error::PathBuild(pkix_chain::pkix_path_builder::Error::NoPathFound)
        | pkix_chain::Error::Aia(_)
        | pkix_chain::Error::AiaDepthExceeded => VerifyCheckStatus::NotRun,
        _ => VerifyCheckStatus::Fail,
    }
}

/// RFC 5280 path validation against configured trust anchors at the
/// applicable time, plus the signer-leaf key-usage gate. The typed status is
/// shared by seal-side refusal and verify's distinct trust axis.
pub(crate) fn signer_path_status(
    chain_ders: &[Vec<u8>],
    anchors: &[pkix_chain::TrustAnchor],
    at_unix: u64,
) -> VerifyCheckStatus {
    use der::Decode;
    let Ok(chain) = chain_ders
        .iter()
        .map(|d| x509_cert::Certificate::from_der(d))
        .collect::<Result<Vec<_>, _>>()
    else {
        return VerifyCheckStatus::Fail;
    };
    // This violation is provable without a root. Check it before path
    // construction so an absent CMS root cannot turn bad KeyUsage into unknown.
    if chain
        .first()
        .is_none_or(|leaf| enforce_signer_leaf_key_usage(leaf).is_err())
    {
        return VerifyCheckStatus::Fail;
    }
    match pkix_chain::verify_chain(
        &chain,
        anchors,
        &pkix_chain::ValidationPolicy::new(at_unix),
        &pkix_chain::DefaultVerifier,
        &pkix_chain::NoRevocation,
        &pkix_chain::NoAiaFetcher,
    ) {
        Ok(_) => VerifyCheckStatus::Pass,
        Err(error) => pkix_path_status(&error),
    }
}

pub(crate) fn validate_chain(
    chain_ders: &[Vec<u8>],
    anchors: &[pkix_chain::TrustAnchor],
    at_unix: u64,
) -> Result<(), SealError> {
    if signer_path_status(chain_ders, anchors, at_unix) == VerifyCheckStatus::Pass {
        Ok(())
    } else {
        Err(cert_path_err())
    }
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

/// Retry only the reason for a failed DSS check: if fully parsed material
/// validates with crypto-valid embedded chains treated as PROVISIONAL roots,
/// root availability is NotRun. No provisional result grants trust or profile.
fn classify_missing_material_root(
    doc: &Document,
    covered: &[EmbeddedCert],
    at: u64,
    max_stream_bytes: usize,
    checks: &mut Checks,
) {
    let unresolved = checks.list.iter().any(|c| {
        c.status == VerifyCheckStatus::NotRun
            && matches!(
                c.kind,
                VerifyCheckKind::TimestampCertificatePath | VerifyCheckKind::CertificatePath
            )
    });
    if !unresolved
        || !checks.list.iter().any(|c| {
            c.kind == VerifyCheckKind::ValidationMaterial && c.status == VerifyCheckStatus::Fail
        })
    {
        return;
    }
    let provisional: Vec<_> = covered
        .iter()
        .filter_map(|c| EmbeddedCert::from_der(&c.der))
        .collect();
    let mut probe = Checks::new();
    verify_dss(doc, &provisional, covered, at, max_stream_bytes, &mut probe);
    if probe.passed(VerifyCheckKind::ValidationMaterial)
        && let Some(check) = checks
            .list
            .iter_mut()
            .find(|c| c.kind == VerifyCheckKind::ValidationMaterial)
    {
        check.status = VerifyCheckStatus::NotRun;
        check.finding = Some(VerifyFindingCode::TrustRootUnavailable);
    }
}

/// Full document verification and profile classification (§7.7).
pub(crate) fn verify_document(
    bytes: &[u8],
    ctx: &VerifyCtx<'_>,
) -> Result<VerifyReport, SealError> {
    let limits = &ctx.config.resource_limits;
    let artifact_sha256 = cms::sha256(bytes);
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
    // The refuse-to-seal gate and output verifier share this object/security
    // scan. An output may have signatures; neither path accepts active content.
    checks.record(
        VerifyCheckKind::PdfRevision,
        pdf::analyze_security(&doc, false).is_ok(),
        VerifyFindingCode::InvalidPdfRevision,
    );
    // The same structural xref/EOF analysis used by prepared admission
    // accepts up to four final CR/LF bytes. Do not keep a competing
    // single-newline predicate on the verify side.
    let revision_ends = pdf::revision_ends(bytes, &doc, limits);
    checks.record(
        VerifyCheckKind::PdfRevision,
        revision_ends.is_some(),
        VerifyFindingCode::InvalidPdfRevision,
    );
    let anchors = anchors(ctx.config);
    let anchor_certs: Vec<EmbeddedCert> = ctx
        .config
        .trust_anchors_der
        .iter()
        .filter_map(|d| EmbeddedCert::from_der(d))
        .collect();
    // Stage 1: bind every envelope to the already-proven xref chain and
    // validate its CMS/TSP integrity. No signer path or profile is decided
    // until all trusted time proofs are available.
    let sigs = collect_signatures(&doc)?;
    let envelopes: Vec<_> = sigs
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            evaluate_envelope(
                bytes,
                entry,
                index,
                revision_ends.as_deref(),
                ctx,
                &anchors,
                index + 1 == sigs.len(),
            )
        })
        .collect();
    let dss_end = dss_revision_end(&doc, bytes);
    let mut covered = Vec::new();
    for envelope in &envelopes {
        covered.extend(
            envelope
                .covered
                .iter()
                .filter_map(|cert| EmbeddedCert::from_der(&cert.der)),
        );
    }
    verify_dss(
        &doc,
        &anchor_certs,
        &covered,
        material_validation_time(&envelopes, dss_end, ctx.clock_ms / 1000),
        limits.max_input_bytes,
        &mut checks,
    );
    let trust_pending = envelopes.iter().flat_map(|e| e.checks.iter()).any(|c| {
        c.kind == VerifyCheckKind::TimestampCertificatePath && c.status == VerifyCheckStatus::NotRun
    });
    if trust_pending {
        // Include the typed pending check solely as a reason for the probe.
        checks.not_run(VerifyCheckKind::TimestampCertificatePath);
        classify_missing_material_root(
            &doc,
            &covered,
            provisional_material_time(&envelopes, dss_end, None, ctx.clock_ms / 1000),
            limits.max_input_bytes,
            &mut checks,
        );
        checks
            .list
            .retain(|c| c.kind != VerifyCheckKind::TimestampCertificatePath);
    }

    // Stage 2: resolve TWO independent obligations for each signer. The
    // earliest eligible proof fixes signer validation time; a possibly newer
    // document timestamp can separately attest the effective DSS.
    let mut envelopes = envelopes;
    let mut profiles = Vec::with_capacity(envelopes.len());
    for index in 0..envelopes.len() {
        if envelopes[index].kind != crate::api::SignatureKind::Signature {
            profiles.push(None);
            continue;
        }
        let validation_time =
            signer_validation_time(&envelopes[index], &envelopes, ctx.clock_ms / 1000);
        let archival = archival_coverage(&envelopes[index], &envelopes, dss_end);
        if let Some(chain) = &envelopes[index].signer_chain {
            let mut path = Checks::new();
            path.record_status(
                VerifyCheckKind::CertificatePath,
                signer_path_status(chain, &anchors, validation_time.at),
                VerifyFindingCode::CertificatePathInvalid,
            );
            envelopes[index].checks.extend(path.list);
        }
        let mut material = Vec::new();
        material.extend(
            envelopes[index]
                .covered
                .iter()
                .filter_map(|cert| EmbeddedCert::from_der(&cert.der)),
        );
        if let Some(archive) = &archival
            && let Some(proof) = envelopes[archive.timestamp].time_proof.as_ref()
        {
            material.extend(
                proof
                    .tsa_chain_ders
                    .iter()
                    .filter_map(|der| EmbeddedCert::from_der(der)),
            );
        }
        let mut material_checks = Checks::new();
        verify_dss(
            &doc,
            &anchor_certs,
            &material,
            archival
                .as_ref()
                .map_or(ctx.clock_ms / 1000, |proof| proof.at),
            limits.max_input_bytes,
            &mut material_checks,
        );
        if envelopes[index].checks.iter().any(|c| {
            c.kind == VerifyCheckKind::TimestampCertificatePath
                && c.status == VerifyCheckStatus::NotRun
        }) {
            material_checks.not_run(VerifyCheckKind::TimestampCertificatePath);
            classify_missing_material_root(
                &doc,
                &material,
                provisional_material_time(
                    &envelopes,
                    dss_end,
                    Some(&envelopes[index]),
                    ctx.clock_ms / 1000,
                ),
                limits.max_input_bytes,
                &mut material_checks,
            );
            material_checks
                .list
                .retain(|c| c.kind != VerifyCheckKind::TimestampCertificatePath);
        }
        let dss_ok = material_checks.passed(VerifyCheckKind::ValidationMaterial);
        envelopes[index].checks.extend(material_checks.list);
        profiles.push(classify_signature(
            &envelopes[index],
            &validation_time,
            dss_ok,
            archival.as_ref(),
            dss_end,
        ));
    }

    // Stage 3: classify raw revision changes against the private evidence,
    // then project each final envelope into the public report exactly once.
    let facts = pdf::analyze_revision_facts(bytes, limits).ok();
    let (revisions, modifications, anomalies) = verify_revisions::classify(
        bytes,
        &envelopes,
        revision_ends.as_deref(),
        facts.as_ref(),
        limits,
    );
    match modifications {
        Modifications::Suspicious => checks.record(
            VerifyCheckKind::Modification,
            false,
            VerifyFindingCode::ModificationNotAllowed,
        ),
        Modifications::NotRun => checks.not_run(VerifyCheckKind::Modification),
        Modifications::Clean(_) => checks.record(
            VerifyCheckKind::Modification,
            true,
            VerifyFindingCode::ModificationNotAllowed,
        ),
    }
    let signatures = envelopes
        .into_iter()
        .zip(profiles)
        .map(|(evidence, profile)| signature_report(evidence, profile))
        .collect();
    Ok(VerifyReport {
        artifact_sha256,
        revisions,
        signatures,
        modifications,
        anomalies,
        checks: checks.list,
    })
}
