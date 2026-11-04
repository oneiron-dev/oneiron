//! B-LT validation-material gather: CRL DP discovery, key-bound issuer resolution, fetch+validate CRLs.

use const_oid::AssociatedOid;
use der::{Decode, Encode};

use crate::api::{
    FetchError, FetchMethod, FetchPurpose, FetchRequest, SealConfig, SigningIdentity,
};
use crate::error::{FatalCode, SealError, SealStage};
use crate::memory::{MemoryLedger, SealMemoryRefusal, SharedBytes};

use super::super::{cms, tsp, verify};
use super::DssMaterial;
use super::assembly::SealContext;

pub(super) fn trust_anchors(
    config: &SealConfig,
    memory: &MemoryLedger,
) -> Result<Vec<pkix_chain::TrustAnchor>, SealError> {
    memory
        .admit_len::<pkix_chain::TrustAnchor>(config.trust_anchors_der.len())
        .map_err(|refusal| refusal.seal_error(SealStage::InputValidation))?;
    memory
        .admit_len::<u8>(
            config
                .trust_anchors_der
                .iter()
                .map(Vec::len)
                .sum::<usize>()
                .saturating_add(
                    config
                        .trust_anchors_der
                        .len()
                        .saturating_mul(std::mem::size_of::<x509_cert::Certificate>()),
                ),
        )
        .map_err(|refusal| refusal.seal_error(SealStage::InputValidation))?;
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

/// CRL distribution-point URIs of a certificate (http/https only).
fn crl_urls_for(cert_der: &[u8], memory: &MemoryLedger) -> Result<Vec<url::Url>, SealError> {
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
                {
                    // The parsed URL (its string plus one slot) is admitted
                    // before the parse allocates; a refusal is the seal's
                    // resource error, while an unparsable URI stays skipped.
                    memory
                        .admit_len::<u8>(uri.as_str().len())
                        .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
                    memory
                        .admit_len::<url::Url>(1)
                        .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
                    if let Ok(u) = url::Url::parse(uri.as_str())
                        && matches!(u.scheme(), "http" | "https")
                    {
                        urls.push(u);
                    }
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
    let memory = ctx
        .limits
        .memory
        .ledger()
        .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
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
    Ok(crl_valid(ctx, issuer_cert_der, &resp.body, &memory)?.map(|()| resp.body))
}

/// `Some` when `crl_der` is a valid CRL: it parses, its signature verifies
/// against the issuing certificate, and it is fresh at the applicable time
/// (thisUpdate not in the future; a present nextUpdate not in the past).
/// The issuer certificate must also AUTHORIZE CRL signing (the shared
/// verify-side cRLSign KeyUsage gate): an unauthorized-issuer CRL embedded
/// here would fail the mandatory self-verify, turning an expected B-LT
/// degradation into a VerifyFailed for the whole seal.
/// `Ok(None)` is an invalid CRL, `Err` only a refused ledger: the
/// re-encoded TBS below is admitted before it is built.
fn crl_valid(
    ctx: &SealContext<'_>,
    issuer_cert_der: &[u8],
    crl_der: &[u8],
    memory: &MemoryLedger,
) -> Result<Option<()>, SealError> {
    let Ok(crl) = x509_cert::crl::CertificateList::from_der(crl_der) else {
        return Ok(None);
    };
    if !verify::crl_complete_scope(&crl) {
        return Ok(None); // delta / IDP-scoped CRL: not complete evidence
    }
    let Ok(alg) = cms::cert_signature_algorithm(issuer_cert_der) else {
        return Ok(None);
    };
    // The re-encoded TBS is most of the CRL, so the CRL length covers it.
    memory
        .admit_len::<u8>(crl_der.len())
        .map_err(|refusal| refusal.seal_error(SealStage::Revocation))?;
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
/// so the gather skips it and the material degrades.
pub(super) fn key_bound_issuer<'a>(
    cert_der: &[u8],
    chain: &'a [Vec<u8>],
    anchors: &'a [Vec<u8>],
    memory: &MemoryLedger,
) -> Result<Option<&'a [u8]>, SealMemoryRefusal> {
    let Some(cert) = verify::EmbeddedCert::from_der(cert_der, memory)? else {
        return Ok(None);
    };
    // Both parses are working copies dropped before this returns; their
    // admissions go back as each temporary drops, so a long chain does not
    // hold every candidate at once. The returned borrow is into `chain` or
    // `anchors`, never into a temporary.
    for cand_der in chain.iter().chain(anchors.iter()) {
        let Some(cand) = verify::EmbeddedCert::from_der(cand_der, memory)? else {
            continue;
        };
        if verify::issued_by(&cert, &cand) {
            memory.release(cert_der.len() as u64);
            memory.release(std::mem::size_of::<x509_cert::Certificate>() as u64);
            memory.release(cand_der.len() as u64);
            memory.release(std::mem::size_of::<x509_cert::Certificate>() as u64);
            return Ok(Some(cand_der.as_slice()));
        }
        memory.release(cand_der.len() as u64);
        memory.release(std::mem::size_of::<x509_cert::Certificate>() as u64);
    }
    memory.release(cert_der.len() as u64);
    memory.release(std::mem::size_of::<x509_cert::Certificate>() as u64);
    Ok(None)
}

/// Gather complete validation material for B-LT (§7.5): signer + TSA chains
/// and a valid CRL for every NON-ANCHOR chain certificate. Certificates
/// whose DER is a configured trust anchor ride anchor trust and are exempt;
/// every other chain certificate counts toward `need`, including ones with
/// no advertised CRL DP or an unresolvable issuer — those count uncovered,
/// so the gather fails closed (degrade to B-T) instead of self-reporting
/// B-LT on zero-evidence material. OCSP is preferred when reachable; v1
/// gathers CRLs through the guarded fetcher and treats unreachable/missing
/// material as degradation (`Ok(None)`), never as a seal failure. A fetch
/// memory refused is the seal's own resource error, never degradation.
pub(super) async fn gather_validation_material(
    ctx: &SealContext<'_>,
    identity: &SigningIdentity,
    token: Option<&tsp::ValidatedToken>,
) -> Result<Option<DssMaterial>, SealError> {
    let memory = ctx
        .limits
        .memory
        .ledger()
        .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
    // Both DER copies admitted before they are made: the DSS set and the
    // signer chain validated below live side by side, so both stay charged.
    let tsa_len: usize = token.map_or(0, |t| t.tsa_chain_ders.iter().map(Vec::len).sum());
    let tsa_count: usize = token.map_or(0, |t| t.tsa_chain_ders.len());
    let chain_len: usize = identity.certificate_chain_der.iter().map(Vec::len).sum();
    let certs_sum = identity
        .signer_certificate_der
        .len()
        .saturating_add(chain_len)
        .saturating_add(tsa_len);
    let certs_count = identity
        .certificate_chain_der
        .len()
        .saturating_add(tsa_count)
        .saturating_add(1);
    memory
        .admit_len::<u8>(certs_sum)
        .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
    memory
        .admit_len::<Vec<u8>>(certs_count)
        .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
    let mut certs_der = vec![identity.signer_certificate_der.clone()];
    certs_der.extend(identity.certificate_chain_der.iter().cloned());
    if let Some(t) = token {
        certs_der.extend(t.tsa_chain_ders.iter().cloned());
    }
    let anchors = match trust_anchors(ctx.config, &memory) {
        Ok(anchors) => anchors,
        // Unparsable anchors degrade; memory a parse was refused is the
        // seal's own resource error, never degradation.
        Err(err) if err.is_retryable() => return Err(err),
        Err(_) => return Ok(None),
    };
    // Chains must validate at the signing time before their material is
    // worth embedding.
    memory
        .admit_len::<u8>(
            identity
                .signer_certificate_der
                .len()
                .saturating_add(chain_len),
        )
        .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
    memory
        .admit_len::<Vec<u8>>(identity.certificate_chain_der.len().saturating_add(1))
        .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
    let signer_chain_ders: Vec<Vec<u8>> = std::iter::once(identity.signer_certificate_der.clone())
        .chain(identity.certificate_chain_der.iter().cloned())
        .collect();
    if verify::validate_chain(&signer_chain_ders, &anchors, ctx.clock_ms / 1000).is_err() {
        return Ok(None);
    }
    let empty_chain: &[Vec<u8>] = &[];
    let tsa_chain = token.map_or(empty_chain, |t| t.tsa_chain_ders.as_slice());
    let mut crls_der = Vec::new();
    let mut covered = 0usize;
    let mut need = 0usize;
    for chain in [signer_chain_ders.as_slice(), tsa_chain] {
        for cert in chain {
            if ctx.config.trust_anchors_der.iter().any(|a| a == cert) {
                continue; // anchors ride anchor trust: no evidence owed
            }
            need += 1;
            let urls = crl_urls_for(cert, &memory)?;
            if urls.is_empty() {
                continue; // no advertised CRL DP: uncovered by construction
            }
            // Issuer identity is bound by key, never by position: the CMS
            // SET OF order is arbitrary, so a positional pick can verify the
            // CRL against the wrong cert and falsely degrade.
            let issuer = key_bound_issuer(cert, chain, &ctx.config.trust_anchors_der, &memory)
                .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
            if let Some(issuer) = issuer {
                for u in urls {
                    if let Some(crl) = fetch_valid_crl(ctx, issuer, u).await? {
                        // The CRL body keeps its fetch lease; only the new
                        // slot is admitted here, never the bytes again.
                        memory
                            .admit_len::<SharedBytes>(1)
                            .map_err(|refusal| refusal.seal_error(SealStage::Dss))?;
                        crls_der.push(crl);
                        covered += 1;
                        break;
                    }
                }
            }
        }
    }
    if covered < need {
        return Ok(None);
    }
    Ok(Some(DssMaterial {
        certs_der,
        ocsps_der: Vec::new(),
        crls_der,
    }))
}
