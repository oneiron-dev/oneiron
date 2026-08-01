//! PAdES profile assembly: B-B / B-T / B-LT / B-LTA (§7.2, §7.4–§7.6).
//!
//! Missing timestamp or validation-material services produce the highest
//! valid lower profile plus a structured degradation warning; B-B is the
//! availability floor.

use std::sync::Arc;

use const_oid::AssociatedOid;
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
    let br = draft.byte_range.ok_or(SealError::Fatal {
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
    for ext in exts {
        if ext.extn_id != x509_cert::ext::pkix::CrlDistributionPoints::OID {
            continue;
        }
        let Ok(dps) =
            x509_cert::ext::pkix::CrlDistributionPoints::from_der(ext.extn_value.as_bytes())
        else {
            continue;
        };
        for dp in &dps.0 {
            let Some(names) = &dp.distribution_point else {
                continue;
            };
            let x509_cert::ext::pkix::name::DistributionPointName::FullName(gns) = names else {
                continue;
            };
            for gn in gns {
                if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) = gn
                    && let Ok(u) = url::Url::parse(uri.as_str())
                    && matches!(u.scheme(), "http" | "https")
                {
                    urls.push(u);
                }
            }
        }
    }
    urls
}

/// Fetch + minimally validate one CRL: parses, signature verifies against
/// the issuing certificate, and is fresh at the applicable time
/// (thisUpdate not in the future; a present nextUpdate not in the past).
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
    if !verify::evidence_fresh(
        crl.tbs_cert_list.this_update,
        crl.tbs_cert_list.next_update,
        now_secs,
    ) {
        return None; // not yet valid, or stale
    }
    Some(resp.body)
}

/// Issuer of `cert_der` bound by key (the r4 lesson, seal side): the chain
/// or trust-anchor certificate whose KEY verifies `cert_der`'s signature —
/// never the next positional slot. CMS certificate `SET OF` members are
/// unordered and DER-sorted on assembly, so `chain[i+1]` can be a sibling,
/// the certificate itself, or an unrelated cert. A self-signed tip resolves
/// to itself; an anchor-omitted tip resolves to the anchor. `None` when no
/// candidate's key signed the certificate: its CRL cannot be authenticated,
/// so the gather skips it and the material degrades.
fn key_bound_issuer<'a>(
    cert_der: &[u8],
    chain: &'a [Vec<u8>],
    anchors: &'a [Vec<u8>],
) -> Option<&'a [u8]> {
    let cert = verify::EmbeddedCert::from_der(cert_der)?;
    chain
        .iter()
        .chain(anchors.iter())
        .find(|cand_der| {
            verify::EmbeddedCert::from_der(cand_der)
                .is_some_and(|cand| verify::issued_by(&cert, &cand))
        })
        .map(Vec::as_slice)
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
    let empty_chain: &[Vec<u8>] = &[];
    let tsa_chain = token.map_or(empty_chain, |t| t.tsa_chain_ders.as_slice());
    let mut crls_der = Vec::new();
    let mut covered = 0usize;
    let mut need = 0usize;
    for chain in [signer_chain_ders.as_slice(), tsa_chain] {
        for cert in chain {
            let urls = crl_urls_for(cert);
            if urls.is_empty() {
                continue;
            }
            need += 1;
            // Issuer identity is bound by key, never by position: the CMS
            // SET OF order is arbitrary, so a positional pick can verify the
            // CRL against the wrong cert and falsely degrade.
            if let Some(issuer) = key_bound_issuer(cert, chain, &ctx.config.trust_anchors_der) {
                for u in urls {
                    if let Some(crl) = fetch_valid_crl(ctx, issuer, u).await {
                        crls_der.push(crl);
                        covered += 1;
                        break;
                    }
                }
            }
        }
    }
    if covered < need {
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
) -> Result<Option<Vec<u8>>, SealError> {
    for capacity in CAPACITY_LADDER {
        let state = pdf::reparse_revision(bytes, &ctx.config.resource_limits)?;
        let mut draft = pdf::append_revision(
            bytes,
            &state,
            &pdf::RevisionKind::DocumentTimestamp,
            capacity,
        )?;
        let br = draft.byte_range.ok_or(SealError::Fatal {
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
        candidate = try_capacity(
            ctx,
            prepared,
            operation_id,
            &input_sha,
            &identity,
            target,
            capacity,
        )
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
        match append_doc_timestamp(&bytes, ctx).await? {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::api::{BackendError, BackendRejectCode, FetchPolicy};

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
        let (objs, dss_num) = build_dss_objects(&material, 10);
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

    fn crl_ca_from(
        params: rcgen::CertificateParams,
        key_pair: rcgen::KeyPair,
        der: Vec<u8>,
    ) -> CrlCa {
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
            crl_extensions: None,
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
}
