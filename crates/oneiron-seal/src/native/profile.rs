//! PAdES profile assembly: B-B / B-T / B-LT / B-LTA (§7.2, §7.4–§7.6).
//!
//! Missing timestamp or validation-material services produce the highest
//! valid lower profile plus a structured degradation warning; B-B is the
//! availability floor.

use std::sync::Arc;

use der::{Decode, Encode};
use rsa::rand_core::RngCore;

use crate::api::{
    FetchMethod, FetchPurpose, FetchRequest, PadesProfile, ProfileDegradeReason, SealBackend,
    SealConfig, SealFetcher, SealWarning, Sha256Digest, SignDigestRequest, SignatureAlgorithm,
    SigningIdentity,
};
use crate::error::{FatalCode, RetryableCode, SealError, SealStage};

use super::{cms, pdf, tsp, verify};

/// `/Contents` DER capacity ladder in bytes (§7.2 rule 5).
pub(crate) const CAPACITY_LADDER: [usize; 3] = [64 * 1024, 128 * 1024, 256 * 1024];

/// Everything the profile assembler needs, bundled to keep signatures small.
pub(crate) struct SealContext<'a> {
    pub config: &'a SealConfig,
    pub backend: &'a Arc<dyn SealBackend>,
    pub fetcher: &'a Arc<dyn SealFetcher>,
    pub clock_ms: u64,
}

/// Result of one seal operation at whatever profile was reachable.
pub(crate) struct AssemblyOutcome {
    pub bytes: Vec<u8>,
    pub achieved: PadesProfile,
    pub warnings: Vec<SealWarning>,
}

pub(crate) fn sub_operation_id(
    operation_id: &str,
    input_sha256: &Sha256Digest,
    phase: &str,
    capacity: usize,
) -> String {
    let mut hex = String::with_capacity(16);
    for b in &input_sha256[..8] {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("{operation_id}:{hex}:{phase}:{capacity}")
}

/// Map a backend failure into the seal error taxonomy (§6).
pub(crate) fn map_backend_error(err: crate::api::BackendError) -> SealError {
    use crate::api::BackendError as Be;
    match err {
        Be::Unavailable { retry_after_ms } => SealError::BackendUnavailable { retry_after_ms },
        Be::RateLimited { retry_after_ms } => SealError::Retryable {
            stage: SealStage::BackendSign,
            code: RetryableCode::TemporaryBackendFailure,
            retry_after_ms,
        },
        Be::Rejected { .. } | Be::MalformedSignature => SealError::Fatal {
            stage: SealStage::BackendSign,
            code: FatalCode::BackendRejected,
        },
    }
}

/// Request one prehashed signature from the backend and verify it against
/// the signer certificate before any embedding (§4 seam rules).
async fn request_signature(
    ctx: &SealContext<'_>,
    identity: &SigningIdentity,
    sub_op_id: String,
    signing_input: &[u8],
) -> Result<Vec<u8>, SealError> {
    let digest = cms::sha256(signing_input);
    let request = SignDigestRequest {
        operation_id: sub_op_id,
        digest_algorithm: crate::api::DigestAlgorithm::Sha256,
        digest,
    };
    let signed = ctx
        .backend
        .sign_digest(request)
        .await
        .map_err(map_backend_error)?;
    let bytes = match (identity.algorithm, signed) {
        (
            SignatureAlgorithm::RsaPkcs1v15Sha256,
            crate::api::BackendSignature::RsaPkcs1v15 { bytes },
        ) => bytes,
        (
            SignatureAlgorithm::EcdsaP256Sha256,
            crate::api::BackendSignature::EcdsaP256Der { bytes },
        ) => bytes,
        // Wrong variant for the identity algorithm: malformed backend output.
        _ => {
            return Err(SealError::Fatal {
                stage: SealStage::BackendSign,
                code: FatalCode::BackendRejected,
            });
        }
    };
    cms::verify_signature_value(
        identity.algorithm,
        &identity.signer_certificate_der,
        signing_input,
        &bytes,
    )
    .map_err(|_| SealError::Fatal {
        stage: SealStage::BackendSign,
        code: FatalCode::InvalidSigningIdentity,
    })?;
    Ok(bytes)
}

/// Ordered TSA failover (§5 rule 8, §7.4 step 3). Returns the first token
/// that passes every §7.4-step-5 check.
async fn fetch_timestamp_token(
    ctx: &SealContext<'_>,
    imprint: &Sha256Digest,
) -> Result<Option<tsp::ValidatedToken>, SealError> {
    let anchors = trust_anchors(ctx.config)?;
    for endpoint in &ctx.config.timestamp_authorities {
        let mut nonce = [0u8; 16];
        rsa::rand_core::OsRng.fill_bytes(&mut nonce);
        let req_der = tsp::build_request(imprint, &nonce)?;
        let response = ctx
            .fetcher
            .fetch(FetchRequest {
                purpose: FetchPurpose::Timestamp,
                url: endpoint.url.clone(),
                method: FetchMethod::Post,
                request_body: req_der,
                content_type: Some("application/timestamp-query".to_string()),
            })
            .await;
        let Ok(resp) = response else { continue };
        let validated = tsp::validate_response(
            &resp.body,
            imprint,
            &nonce,
            endpoint.expected_policy_oid.as_deref(),
            &anchors,
        );
        if let Ok(token) = validated {
            return Ok(Some(token));
        }
    }
    Ok(None)
}

fn trust_anchors(config: &SealConfig) -> Result<Vec<pkix_chain::TrustAnchor>, SealError> {
    config
        .trust_anchors_der
        .iter()
        .map(|der| {
            let cert = x509_cert::Certificate::from_der(der).map_err(|_| SealError::Fatal {
                stage: SealStage::InputValidation,
                code: FatalCode::InvalidConfiguration,
            })?;
            Ok(pkix_chain::TrustAnchor::from_cert(cert))
        })
        .collect()
}

/// DSS revision material: global `/Certs`, `/OCSPs`, `/CRLs` arrays; `/VRI`
/// is not emitted in v1 (§7.5 step 5).
pub(crate) struct DssMaterial {
    pub certs_der: Vec<Vec<u8>>,
    pub ocsps_der: Vec<Vec<u8>>,
    pub crls_der: Vec<Vec<u8>>,
}

/// Serialize DSS stream objects and the DSS dictionary (which is included in
/// the returned object list). Returns `(objects, dss_dict_obj_num)` with
/// object numbers starting at `first_num`.
pub(crate) fn build_dss_objects(
    material: &DssMaterial,
    first_num: u32,
) -> (Vec<(u32, Vec<u8>)>, u32) {
    let mut objs: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut next = first_num;
    let mut cert_refs = Vec::new();
    let mut ocsp_refs = Vec::new();
    let mut crl_refs = Vec::new();
    for cert in &material.certs_der {
        objs.push((next, stream_obj(cert)));
        cert_refs.push(format!("{next} 0 R"));
        next += 1;
    }
    for ocsp in &material.ocsps_der {
        objs.push((next, stream_obj(ocsp)));
        ocsp_refs.push(format!("{next} 0 R"));
        next += 1;
    }
    for crl in &material.crls_der {
        objs.push((next, stream_obj(crl)));
        crl_refs.push(format!("{next} 0 R"));
        next += 1;
    }
    let dss_num = next;
    let mut dss = b"<< /Type /DSS ".to_vec();
    if !cert_refs.is_empty() {
        dss.extend_from_slice(format!("/Certs [{}] ", cert_refs.join(" ")).as_bytes());
    }
    if !ocsp_refs.is_empty() {
        dss.extend_from_slice(format!("/OCSPs [{}] ", ocsp_refs.join(" ")).as_bytes());
    }
    if !crl_refs.is_empty() {
        dss.extend_from_slice(format!("/CRLs [{}] ", crl_refs.join(" ")).as_bytes());
    }
    dss.extend_from_slice(b">>");
    objs.push((dss_num, dss));
    (objs, dss_num)
}

fn stream_obj(data: &[u8]) -> Vec<u8> {
    let mut body = format!("<< /Length {} >>\nstream\n", data.len()).into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(b"\nendstream");
    body
}

struct SignedCandidate {
    draft: pdf::DraftRevision,
    token: Option<tsp::ValidatedToken>,
}

/// Build the signature revision at one capacity, returning `Ok(None)` when
/// the CMS does not fit and the caller must rebuild at the next capacity.
async fn try_capacity(
    ctx: &SealContext<'_>,
    prepared: &pdf::PreparedInput,
    operation_id: &str,
    input_sha: &Sha256Digest,
    identity: &SigningIdentity,
    target: PadesProfile,
    capacity: usize,
) -> Result<Option<SignedCandidate>, SealError> {
    let kind = pdf::RevisionKind::Signature {
        field_name: pdf::field_name_for(operation_id),
        date_str: pdf::pdf_date(ctx.clock_ms),
    };
    let mut draft = pdf::append_revision(&prepared.bytes, &prepared.state, &kind, capacity)?;
    let br = draft
        .byte_range
        .ok_or_else(|| SealError::Fatal {
            stage: SealStage::PdfIncrementalUpdate,
            code: FatalCode::PdfInvariantFailed,
        })?;
    let content_digest = pdf::hash_byte_range(&draft.bytes, br)?;
    let (issuer, serial) = cms::issuer_and_serial(&identity.signer_certificate_der)?;
    let attrs = vec![
        cms::attr_content_type_data(),
        cms::attr_message_digest(&content_digest),
        cms::attr_signing_cert_v2(&identity.signer_certificate_der, &issuer, &serial),
    ];
    let (wire, signing) = cms::assemble_signed_attrs(attrs);
    let sub_id = sub_operation_id(operation_id, input_sha, "sign", capacity);
    let signature = request_signature(ctx, identity, sub_id, &signing).await?;
    let mut unsigned = Vec::new();
    let mut token = None;
    if target >= PadesProfile::BaselineT {
        let imprint = cms::sha256(&signature);
        if let Some(t) = fetch_timestamp_token(ctx, &imprint).await? {
            unsigned.push(cms::attr_ts_token(&t.content_info_der));
            token = Some(t);
        }
    }
    let material = cms::SignerMaterial {
        algorithm: identity.algorithm,
        signer_cert_der: &identity.signer_certificate_der,
        issuer_name_der: &issuer,
        serial_der: &serial,
        chain_ders: &identity.certificate_chain_der,
    };
    let cms_der = cms::build_signed_data(&material, &wire, &signature, &unsigned);
    match pdf::patch_contents(&mut draft, &cms_der) {
        Ok(()) => Ok(Some(SignedCandidate { draft, token })),
        Err(SealError::Fatal {
            code: FatalCode::ContentsCapacityExceeded,
            ..
        }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// CRL distribution-point URIs of a certificate (http/https only).
fn crl_urls_for(cert_der: &[u8]) -> Vec<url::Url> {
    let Ok(cert) = x509_cert::Certificate::from_der(cert_der) else {
        return Vec::new();
    };
    let Some(exts) = &cert.tbs_certificate.extensions else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    use const_oid::AssociatedOid;
    for ext in exts {
        if ext.extn_id != x509_cert::ext::pkix::CrlDistributionPoints::OID {
            continue;
        }
        let Ok(dps) = x509_cert::ext::pkix::CrlDistributionPoints::from_der(
            ext.extn_value.as_bytes(),
        ) else {
            continue;
        };
        for dp in &dps.0 {
            let Some(names) = &dp.distribution_point else { continue };
            let x509_cert::ext::pkix::name::DistributionPointName::FullName(gns) = names
            else {
                continue;
            };
            for gn in gns {
                if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                    uri,
                ) = gn
                {
                    if let Ok(u) = url::Url::parse(uri.as_str()) {
                        if matches!(u.scheme(), "http" | "https") {
                            urls.push(u);
                        }
                    }
                }
            }
        }
    }
    urls
}

/// Fetch + minimally validate one CRL: parses, signature verifies against
/// the issuing certificate, and is fresh at the applicable time.
async fn fetch_valid_crl(
    ctx: &SealContext<'_>,
    issuer_cert_der: &[u8],
    url: url::Url,
) -> Option<Vec<u8>> {
    let resp = ctx
        .fetcher
        .fetch(FetchRequest {
            purpose: FetchPurpose::Crl,
            url,
            method: FetchMethod::Get,
            request_body: Vec::new(),
            content_type: None,
        })
        .await
        .ok()?;
    let crl = x509_cert::crl::CertificateList::from_der(&resp.body).ok()?;
    let alg = cms::cert_signature_algorithm(issuer_cert_der).ok()?;
    let tbs = crl.tbs_cert_list.to_der().ok()?;
    cms::verify_signature_value(alg, issuer_cert_der, &tbs, crl.signature.raw_bytes()).ok()?;
    let now_secs = ctx.clock_ms / 1000;
    let this_secs: u64 = match crl.tbs_cert_list.this_update {
        x509_cert::time::Time::UtcTime(t) => t.to_unix_duration().as_secs(),
        x509_cert::time::Time::GeneralTime(t) => t.to_unix_duration().as_secs(),
    };
    if now_secs < this_secs {
        return None; // not yet valid
    }
    Some(resp.body)
}

/// Gather complete validation material for B-LT (§7.5): signer + TSA chains
/// and a valid CRL for every non-anchor certificate that advertises one.
/// OCSP is preferred when reachable; v1 gathers CRLs through the guarded
/// fetcher and treats unreachable/missing material as degradation, never as
/// a seal failure.
async fn gather_validation_material(
    ctx: &SealContext<'_>,
    identity: &SigningIdentity,
    token: Option<&tsp::ValidatedToken>,
) -> Option<DssMaterial> {
    let mut certs_der = vec![identity.signer_certificate_der.clone()];
    certs_der.extend(identity.certificate_chain_der.iter().cloned());
    if let Some(t) = token {
        certs_der.extend(t.tsa_chain_ders.iter().cloned());
    }
    let anchors = trust_anchors(ctx.config).ok()?;
    // Chains must validate at the signing time before their material is
    // worth embedding.
    let signer_chain_ders: Vec<Vec<u8>> = std::iter::once(identity.signer_certificate_der.clone())
        .chain(identity.certificate_chain_der.iter().cloned())
        .collect();
    verify::validate_chain(&signer_chain_ders, &anchors, ctx.clock_ms / 1000).ok()?;
    let mut crls_der = Vec::new();
    let mut covered = 0usize;
    let mut need = 0usize;
    for (i, cert) in certs_der.iter().enumerate() {
        let urls = crl_urls_for(cert);
        if urls.is_empty() {
            continue;
        }
        need += 1;
        // The CRL issuer is the next cert in the chain when present.
        let issuer = certs_der.get(i + 1).unwrap_or(cert);
        for u in urls {
            if let Some(crl) = fetch_valid_crl(ctx, issuer, u).await {
                crls_der.push(crl);
                covered += 1;
                break;
            }
        }
    }
    if need > 0 && covered < need {
        return None;
    }
    if crls_der.is_empty() && need > 0 {
        return None;
    }
    Some(DssMaterial {
        certs_der,
        ocsps_der: Vec::new(),
        crls_der,
    })
}

fn degrade_warning(
    requested: PadesProfile,
    achieved: PadesProfile,
    reason: ProfileDegradeReason,
) -> SealWarning {
    SealWarning::ProfileDegraded {
        requested,
        achieved,
        reason,
    }
}

/// Append the DSS revision for B-LT. Returns updated bytes.
fn append_dss(
    bytes: &[u8],
    ctx: &SealContext<'_>,
    material: &DssMaterial,
) -> Result<Vec<u8>, SealError> {
    let state = pdf::reparse_revision(bytes, &ctx.config.resource_limits)?;
    let (objs, dss_num) = build_dss_objects(material, state.max_obj + 1);
    let kind = pdf::RevisionKind::Dss {
        material_objects: objs,
        dss_obj: dss_num,
    };
    let draft = pdf::append_revision(bytes, &state, &kind, 0)?;
    Ok(draft.bytes)
}

/// Append the DocTimeStamp revision for B-LTA (§7.6). `Ok(None)` means the
/// archival timestamp could not be produced; caller degrades to B-LT.
async fn append_doc_timestamp(
    bytes: &[u8],
    ctx: &SealContext<'_>,
    operation_id: &str,
    input_sha: &Sha256Digest,
) -> Result<Option<Vec<u8>>, SealError> {
    let _ = sub_operation_id(operation_id, input_sha, "doc-ts", 0);
    for capacity in CAPACITY_LADDER {
        let state = pdf::reparse_revision(bytes, &ctx.config.resource_limits)?;
        let mut draft =
            pdf::append_revision(bytes, &state, &pdf::RevisionKind::DocumentTimestamp, capacity)?;
        let br = draft.byte_range.ok_or_else(|| SealError::Fatal {
            stage: SealStage::DocumentTimestamp,
            code: FatalCode::PdfInvariantFailed,
        })?;
        let imprint = pdf::hash_byte_range(&draft.bytes, br)?;
        let Some(token) = fetch_timestamp_token(ctx, &imprint).await? else {
            return Ok(None);
        };
        match pdf::patch_contents(&mut draft, &token.content_info_der) {
            Ok(()) => return Ok(Some(draft.bytes)),
            Err(SealError::Fatal {
                code: FatalCode::ContentsCapacityExceeded,
                ..
            }) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(SealError::Fatal {
        stage: SealStage::DocumentTimestamp,
        code: FatalCode::ContentsCapacityExceeded,
    })
}

/// Full profile assembly (§7). Always produces at least B-B or an error;
/// higher profiles degrade with structured warnings.
pub(crate) async fn assemble(
    ctx: &SealContext<'_>,
    prepared: &pdf::PreparedInput,
    operation_id: &str,
    target: PadesProfile,
) -> Result<AssemblyOutcome, SealError> {
    let identity = ctx.backend.signing_identity().map_err(map_backend_error)?;
    let cert_alg = cms::cert_signature_algorithm(&identity.signer_certificate_der)?;
    if cert_alg != identity.algorithm {
        return Err(SealError::Fatal {
            stage: SealStage::BackendSign,
            code: FatalCode::InvalidSigningIdentity,
        });
    }
    let input_sha = cms::sha256(&prepared.bytes);
    let mut candidate = None;
    for capacity in CAPACITY_LADDER {
        candidate =
            try_capacity(ctx, prepared, operation_id, &input_sha, &identity, target, capacity)
                .await?;
        if candidate.is_some() {
            break;
        }
    }
    let SignedCandidate { draft, token } = candidate.ok_or(SealError::Fatal {
        stage: SealStage::PdfIncrementalUpdate,
        code: FatalCode::ContentsCapacityExceeded,
    })?;
    let mut warnings = Vec::new();
    let mut achieved = PadesProfile::BaselineB;
    if token.is_some() {
        achieved = PadesProfile::BaselineT;
    } else if target >= PadesProfile::BaselineT {
        warnings.push(degrade_warning(
            target,
            achieved,
            ProfileDegradeReason::TimestampUnavailable,
        ));
    }
    let mut bytes = draft.bytes;
    if target >= PadesProfile::BaselineLt && achieved == PadesProfile::BaselineT {
        match gather_validation_material(ctx, &identity, token.as_ref()).await {
            Some(material) => {
                bytes = append_dss(&bytes, ctx, &material)?;
                achieved = PadesProfile::BaselineLt;
            }
            None => warnings.push(degrade_warning(
                target,
                achieved,
                ProfileDegradeReason::ValidationMaterialUnavailable,
            )),
        }
    } else if target >= PadesProfile::BaselineLt {
        warnings.push(degrade_warning(
            target,
            achieved,
            ProfileDegradeReason::ValidationMaterialUnavailable,
        ));
    }
    if target == PadesProfile::BaselineLta && achieved == PadesProfile::BaselineLt {
        match append_doc_timestamp(&bytes, ctx, operation_id, &input_sha).await? {
            Some(b) => {
                bytes = b;
                achieved = PadesProfile::BaselineLta;
            }
            None => warnings.push(degrade_warning(
                target,
                achieved,
                ProfileDegradeReason::DocumentTimestampUnavailable,
            )),
        }
    } else if target == PadesProfile::BaselineLta {
        warnings.push(degrade_warning(
            target,
            achieved,
            ProfileDegradeReason::DocumentTimestampUnavailable,
        ));
    }
    let growth = bytes.len().saturating_sub(prepared.bytes.len());
    if growth > ctx.config.resource_limits.max_output_growth_bytes {
        return Err(SealError::Fatal {
            stage: SealStage::PdfIncrementalUpdate,
            code: FatalCode::PdfInvariantFailed,
        });
    }
    Ok(AssemblyOutcome {
        bytes,
        achieved,
        warnings,
    })
}
