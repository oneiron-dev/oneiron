//! B-LT validation material: working CRLs first, then OCSP for uncovered certificates.

use const_oid::AssociatedOid;
use der::{Decode, Encode};

use crate::api::{
    FetchError, FetchMethod, FetchPurpose, FetchRequest, SealConfig, SealResourceLimits,
    SigningIdentity,
};
use crate::error::{FatalCode, SealError, SealStage};
use crate::memory::{MemoryLedger, SealMemoryRefusal, SharedBytes};

use super::super::{cms, pdf, tsp, verify};
use super::DssMaterial;
use super::assembly::SealContext;

mod ocsp;

/// Invalid configured DER is absent material; resource refusals stay distinct
/// so each caller preserves its own bad-configuration behavior.
pub(super) fn trust_anchors(
    config: &SealConfig,
    limits: &SealResourceLimits,
) -> Result<Option<Vec<pkix_chain::TrustAnchor>>, SealMemoryRefusal> {
    limits
        .memory
        .admit::<pkix_chain::TrustAnchor>(config.trust_anchors_der.len())?;
    let mut anchors = Vec::with_capacity(config.trust_anchors_der.len());
    for der in &config.trust_anchors_der {
        let Ok(cert) = x509_cert::Certificate::from_der(der) else {
            return Ok(None);
        };
        anchors.push(pkix_chain::TrustAnchor::from_cert(cert));
    }
    Ok(Some(anchors))
}

/// CRL distribution-point URIs of a certificate (http/https only).
fn crl_urls_for(
    cert_der: &[u8],
    limits: &SealResourceLimits,
) -> Result<Vec<url::Url>, SealMemoryRefusal> {
    let Ok(cert) = x509_cert::Certificate::from_der(cert_der) else {
        return Ok(Vec::new());
    };
    let Some(exts) = &cert.tbs_certificate.extensions else {
        return Ok(Vec::new());
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
                    pdf::admitted::push(limits, &mut urls, u)?;
                }
            }
        }
    }
    Ok(urls)
}

/// Fetch + minimally validate one CRL (see [`crl_valid`]). The CRL keeps
/// the fetch's own admitted bytes. A fetch memory refused is the seal's own
/// resource error; any other failed fetch is no CRL from this URL.
pub(super) async fn fetch_valid_crl(
    ctx: &SealContext<'_>,
    issuer_cert_der: &[u8],
    url: url::Url,
) -> Result<Option<SharedBytes>, SealError> {
    let response = ctx
        .fetcher
        .fetch(FetchRequest {
            purpose: FetchPurpose::Crl,
            url,
            method: FetchMethod::Get,
            request_body: Vec::new(),
            content_type: None,
        })
        .await;
    let resp = match response {
        Ok(resp) => resp,
        Err(FetchError::Memory(refusal)) => {
            return Err(refusal.seal_error(SealStage::Revocation));
        }
        // Denied, unreachable, timed out or invalid: no CRL from here.
        Err(_) => return Ok(None),
    };
    let valid = crl_valid(ctx, issuer_cert_der, &resp.body)
        .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
    Ok(valid.map(|()| resp.body))
}

/// `Some` when `crl_der` is a valid CRL: it parses, its signature verifies
/// against the issuing certificate, and it is fresh at the applicable time
/// (thisUpdate not in the future; a present nextUpdate not in the past).
/// The issuer certificate must also AUTHORIZE CRL signing (the shared
/// verify-side cRLSign KeyUsage gate): an unauthorized-issuer CRL embedded
/// here would fail the mandatory self-verify, turning an expected B-LT
/// degradation into a VerifyFailed for the whole seal.
fn crl_valid(
    ctx: &SealContext<'_>,
    issuer_cert_der: &[u8],
    crl_der: &[u8],
) -> Result<Option<()>, SealMemoryRefusal> {
    let Ok(crl) = x509_cert::crl::CertificateList::from_der(crl_der) else {
        return Ok(None);
    };
    if !verify::crl_complete_scope(&crl) {
        return Ok(None); // delta / IDP-scoped CRL: not complete evidence
    }
    let Ok(alg) = cms::cert_signature_algorithm(issuer_cert_der) else {
        return Ok(None);
    };
    let Some(tbs_len) = crl
        .tbs_cert_list
        .encoded_len()
        .ok()
        .and_then(|len| usize::try_from(len).ok())
    else {
        return Ok(None);
    };
    let _tbs_held = ctx.limits.memory.hold(tbs_len)?;
    let Ok(tbs) = crl.tbs_cert_list.to_der() else {
        return Ok(None);
    };
    if cms::verify_signature_value(alg, issuer_cert_der, &tbs, crl.signature.raw_bytes()).is_err() {
        return Ok(None);
    }
    // Key verification alone is not authorization: when the issuer carries
    // a KeyUsage it must assert cRLSign (same gate the verifier applies to
    // embedded DSS CRLs).
    let Ok(issuer_cert) = x509_cert::Certificate::from_der(issuer_cert_der) else {
        return Ok(None);
    };
    if !verify::issuer_permits_crl_sign(&issuer_cert) {
        return Ok(None);
    }
    let now_secs = ctx.clock_ms / 1000;
    if !verify::evidence_fresh(
        crl.tbs_cert_list.this_update,
        crl.tbs_cert_list.next_update,
        now_secs,
    ) {
        return Ok(None); // not yet valid, or stale
    }
    Ok(Some(()))
}

/// Issuer of `cert_der` bound by key (the r4 lesson, seal side): the chain
/// or trust-anchor certificate whose KEY verifies `cert_der`'s signature —
/// never the next positional slot. CMS certificate `SET OF` members are
/// unordered and DER-sorted on assembly, so `chain[i+1]` can be a sibling,
/// the certificate itself, or an unrelated cert. A self-signed tip resolves
/// to itself; an anchor-omitted tip resolves to the anchor. `None` when no
/// candidate's key signed the certificate: its CRL cannot be authenticated,
/// so the gather skips it and the material degrades. Each certificate it
/// decodes is held on `memory` while it is read (FIX 12260).
///
/// # Errors
/// The ledger's refusal.
pub(super) fn key_bound_issuer<'a>(
    cert_der: &[u8],
    chain: &'a [Vec<u8>],
    anchors: &'a [Vec<u8>],
    memory: &MemoryLedger,
) -> Result<Option<&'a [u8]>, SealMemoryRefusal> {
    let Some(cert) = verify::EmbeddedCert::admitted(cert_der, memory)? else {
        return Ok(None);
    };
    for cand_der in chain.iter().chain(anchors.iter()) {
        if let Some(cand) = verify::EmbeddedCert::admitted(cand_der, memory)?
            && verify::issued_by(&cert, &cand, memory)?
        {
            return Ok(Some(cand_der.as_slice()));
        }
    }
    Ok(None)
}

/// Gather complete validation material for B-LT (§7.5): signer + TSA chains
/// and valid CRL or OCSP evidence for every NON-ANCHOR chain certificate. Certificates
/// whose DER is a configured trust anchor ride anchor trust and are exempt;
/// every other chain certificate counts toward `need`, including ones with
/// no advertised revocation URL or an unresolvable issuer — those count uncovered,
/// so the gather fails closed (degrade to B-T) instead of self-reporting
/// B-LT on zero-evidence material. Existing CRL attempts run first; only an
/// uncovered certificate tries OCSP. The guarded fetcher treats unreachable/missing
/// material as degradation (`Ok(None)`), never as a seal failure. A fetch
/// memory refused is the seal's own resource error, never degradation.
pub(super) async fn gather_validation_material(
    ctx: &SealContext<'_>,
    identity: &SigningIdentity,
    token: Option<&tsp::ValidatedToken>,
) -> Result<Option<DssMaterial>, SealError> {
    // The certificate copies below are the seal's own: the DSS's list and
    // the signer chain checked before it, reserved before they are made
    // (FIX 8452).
    let signer_chain_bytes: usize = std::iter::once(&identity.signer_certificate_der)
        .chain(&identity.certificate_chain_der)
        .map(Vec::len)
        .sum();
    let tsa_chain_bytes: usize = token.map_or(0, |t| t.tsa_chain_ders.iter().map(Vec::len).sum());
    ctx.limits
        .memory
        .admit::<u8>(
            signer_chain_bytes
                .saturating_mul(2)
                .saturating_add(tsa_chain_bytes),
        )
        .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
    let signer_chain_len = identity.certificate_chain_der.len().saturating_add(1);
    let certs_len = signer_chain_len.saturating_add(token.map_or(0, |t| t.tsa_chain_ders.len()));
    ctx.limits
        .memory
        .admit::<Vec<u8>>(certs_len)
        .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
    let mut certs_der = Vec::with_capacity(certs_len);
    certs_der.push(identity.signer_certificate_der.clone());
    certs_der.extend(identity.certificate_chain_der.iter().cloned());
    if let Some(t) = token {
        certs_der.extend(t.tsa_chain_ders.iter().cloned());
    }
    let Some(anchors) = trust_anchors(ctx.config, ctx.limits)
        .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?
    else {
        return Ok(None);
    };
    let memory = ctx
        .limits
        .memory
        .ledger()
        .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
    // Chains must validate at the signing time before their material is
    // worth embedding.
    memory
        .admit_len::<Vec<u8>>(signer_chain_len)
        .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
    let mut signer_chain_ders = Vec::with_capacity(signer_chain_len);
    signer_chain_ders.push(identity.signer_certificate_der.clone());
    signer_chain_ders.extend(identity.certificate_chain_der.iter().cloned());
    match verify::validate_chain(&signer_chain_ders, &anchors, ctx.clock_ms / 1000, &memory) {
        Ok(()) => {}
        Err(SealError::Fatal {
            code: FatalCode::CertificatePathInvalid,
            ..
        }) => return Ok(None),
        Err(error) => return Err(error),
    }
    let empty_chain: &[Vec<u8>] = &[];
    let tsa_chain = token.map_or(empty_chain, |t| t.tsa_chain_ders.as_slice());
    let mut crls_der = Vec::new();
    let mut ocsps_der = Vec::new();
    let mut covered = 0usize;
    let mut need = 0usize;
    for chain in [signer_chain_ders.as_slice(), tsa_chain] {
        for cert in chain {
            if ctx.config.trust_anchors_der.iter().any(|a| a == cert) {
                continue; // anchors ride anchor trust: no evidence owed
            }
            need += 1;
            let urls = crl_urls_for(cert, ctx.limits)
                .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
            // Issuer identity is bound by key, never by position: the CMS
            // SET OF order is arbitrary, so a positional pick can verify the
            // CRL against the wrong cert and falsely degrade.
            let issuer = key_bound_issuer(cert, chain, &ctx.config.trust_anchors_der, &memory)
                .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
            if let Some(issuer) = issuer {
                let mut crl_covered = false;
                for u in urls {
                    if let Some(crl) = fetch_valid_crl(ctx, issuer, u).await? {
                        pdf::admitted::push(ctx.limits, &mut crls_der, crl)
                            .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
                        covered += 1;
                        crl_covered = true;
                        break;
                    }
                }
                if !crl_covered
                    && let Some(ocsp) = ocsp::fetch_valid_ocsp(ctx, cert, issuer, &memory).await?
                {
                    if ocsps_der.is_empty() {
                        let slots = signer_chain_ders.len().saturating_add(tsa_chain.len());
                        memory
                            .admit_len::<SharedBytes>(slots)
                            .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
                        ocsps_der.reserve_exact(slots);
                    }
                    ocsps_der.push(ocsp);
                    covered += 1;
                }
            }
        }
    }
    if covered < need {
        return Ok(None);
    }
    Ok(Some(DssMaterial {
        certs_der,
        ocsps_der,
        crls_der,
    }))
}
