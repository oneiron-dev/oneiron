//! CRL/OCSP evidence validators: issuer key-binding, freshness windows and clock-skew bounds.

use super::super::cms;
use super::verify_chain_gates::{issuer_permits_crl_sign, key_usage_permits};
use super::verify_dss_core::{EmbeddedCert, crl_signer_authorized, crl_signer_shadows};
use crate::memory::{LedgerHold, MemoryLedger, SealMemoryRefusal};

/// Seconds-since-epoch for an X.509 time choice.
fn time_secs(t: x509_cert::time::Time) -> u64 {
    match t {
        x509_cert::time::Time::UtcTime(t) => t.to_unix_duration().as_secs(),
        x509_cert::time::Time::GeneralTime(t) => t.to_unix_duration().as_secs(),
    }
}

/// Freshness window shared by CRL and OCSP evidence (§7.5 step 3): issued
/// at or before the applicable time, and a present nextUpdate not in the
/// past. Also used by the seal-side CRL fetcher.
pub(crate) fn evidence_fresh(
    this_update: x509_cert::time::Time,
    next_update: Option<x509_cert::time::Time>,
    at_unix: u64,
) -> bool {
    time_secs(this_update) <= at_unix && next_update.is_none_or(|n| at_unix <= time_secs(n))
}

/// Certificates whose subject is `issuer`, embedded DSS certs first, then
/// trust anchors. X.509 issuer identity is name+key: subject matching is
/// only the first sieve. Callers must confirm the candidate's KEY actually
/// signed the certificate the evidence speaks for (`issued_by`) — a
/// same-subject/different-key shadow must never authenticate evidence.
fn issuer_candidates<'a, 'n>(
    issuer: &'n x509_cert::name::Name,
    embedded: &'a [EmbeddedCert],
    anchors: &'a [EmbeddedCert],
) -> impl Iterator<Item = &'a EmbeddedCert> + 'n
where
    'a: 'n,
{
    embedded
        .iter()
        .chain(anchors.iter())
        .filter(|c| c.cert.tbs_certificate.subject == *issuer)
}

/// Is `cert` actually issued by `issuer`: issuer-name match AND `cert`'s
/// own signature verifies under `issuer`'s key with a consistent, allowed
/// algorithm. This binds issuer identity by key, defeating same-subject
/// fake-issuer shadowing.
pub(crate) fn issued_by(
    cert: &EmbeddedCert,
    issuer: &EmbeddedCert,
    memory: &MemoryLedger,
) -> Result<bool, SealMemoryRefusal> {
    use der::Encode;
    if cert.cert.tbs_certificate.issuer != issuer.cert.tbs_certificate.subject {
        return Ok(false);
    }
    let Ok(alg) = cms::cert_signature_algorithm(&issuer.der) else {
        return Ok(false);
    };
    let oid = cert.cert.signature_algorithm.oid.as_bytes();
    if !cms::sig_alg_permitted(alg, oid) {
        return Ok(false);
    }
    let Some(tbs_len) = cert
        .cert
        .tbs_certificate
        .encoded_len()
        .ok()
        .and_then(|len| usize::try_from(len).ok())
    else {
        return Ok(false);
    };
    let _tbs_held = memory.hold(tbs_len)?;
    let Ok(tbs) = cert.cert.tbs_certificate.to_der() else {
        return Ok(false);
    };
    Ok(
        cms::verify_signature_value(alg, &issuer.der, &tbs, cert.cert.signature.raw_bytes())
            .is_ok(),
    )
}

/// deltaCRLIndicator (2.5.29.46) and IssuingDistributionPoint (2.5.29.28).
const OID_EXT_DELTA_CRL_INDICATOR: &[u8] = b"\x55\x1d\x2e";

const OID_EXT_ISSUING_DISTRIBUTION_POINT: &[u8] = b"\x55\x1d\x1c";

/// Complete-scope posture (fail-closed): a CRL carrying deltaCRLIndicator
/// (changes since a base CRL) or IssuingDistributionPoint (subset coverage
/// of the issuer's namespace) is NOT complete revocation evidence and must
/// not count toward revocation coverage. Deliberate support for scoped CRLs
/// can be added later; until then both seal and verify reject them.
pub(crate) fn crl_complete_scope(crl: &x509_cert::crl::CertificateList) -> bool {
    crl.tbs_cert_list
        .crl_extensions
        .as_ref()
        .is_none_or(|exts| {
            !exts.iter().any(|e| {
                e.extn_id.as_bytes() == OID_EXT_DELTA_CRL_INDICATOR
                    || e.extn_id.as_bytes() == OID_EXT_ISSUING_DISTRIBUTION_POINT
            })
        })
}

/// One DSS CRL entry: parses, its signature verifies against an
/// embedded/anchored issuer cert with a consistent algorithm and cRLSign,
/// and, when it is about the report's covered chains, it has complete
/// scope, is fresh at the applicable time and lists no covered serial
/// (§7.5 step 3). The issuer is the first name-matched candidate whose KEY
/// verifies the CRL signature — a same-subject/different-key shadow can
/// only authenticate a CRL it truly signed, and the coverage rule counts
/// that CRL only for certificates that shadow actually issued
/// (`issued_by`). On success returns that key-bound issuer certificate;
/// otherwise why it is rejected (lead ruling F): unparseable, verified by
/// no claimed issuer's key, signed by an issuer without cRLSign, or listing
/// a covered certificate for an issuer it shadows is Unverifiable; a delta
/// or IDP-scoped CRL or one stale at `at_unix` is Unusable; one listing a
/// covered serial is Revoked.
///
/// A CRL is about the covered chains when its signer has revocation
/// authority over a covered non-anchor certificate: it issued it, or it
/// holds a key that certificate's own issuer certified (a separate
/// CRL-signing key, a rollover's link certificate; RFC 5280 §5.1.1.3,
/// §5.2.1). A same-subject CA another trust anchor vouches for is no shadow
/// (ruling Q2) but has no authority over another CA's certificates (RFC
/// 5280 §8): its CRL claims nothing about them.
/// What a CRL about nothing in the chains says (stale, scoped, a listing)
/// claims nothing about them (Engine call Q-C = A, 10 Nov 07:23; Q4): it is
/// returned unjudged, supplies no coverage, and still reaches the shadow
/// scan, so a shadow's stale CRL reads as possible tampering.
pub(super) fn crl_entry_valid<'a>(
    data: &[u8],
    embedded: &'a [EmbeddedCert],
    anchors: &'a [EmbeddedCert],
    covered: &[EmbeddedCert],
    at_unix: u64,
    memory: &MemoryLedger,
) -> Result<Result<&'a EmbeddedCert, EvidenceRejection>, SealMemoryRefusal> {
    use der::{Decode, Encode};
    let Ok(crl) = x509_cert::crl::CertificateList::from_der(data) else {
        return Ok(Err(EvidenceRejection::Unverifiable));
    };
    let Some(tbs_len) = crl
        .tbs_cert_list
        .encoded_len()
        .ok()
        .and_then(|len| usize::try_from(len).ok())
    else {
        return Ok(Err(EvidenceRejection::Unverifiable));
    };
    let _tbs_held = memory.hold(tbs_len)?;
    let Ok(tbs) = crl.tbs_cert_list.to_der() else {
        return Ok(Err(EvidenceRejection::Unverifiable));
    };
    let oid = crl.signature_algorithm.oid.as_bytes();
    let Some(issuer) =
        issuer_candidates(&crl.tbs_cert_list.issuer, embedded, anchors).find(|cand| {
            let Ok(alg) = cms::cert_signature_algorithm(&cand.der) else {
                return false;
            };
            cms::sig_alg_permitted(alg, oid)
                && cms::verify_signature_value(alg, &cand.der, &tbs, crl.signature.raw_bytes())
                    .is_ok()
        })
    else {
        return Ok(Err(EvidenceRejection::Unverifiable));
    };
    // Key verification alone is not authorization: the issuer certificate
    // must permit CRL signing (cRLSign) when it carries a KeyUsage.
    if !issuer_permits_crl_sign(&issuer.cert) {
        return Ok(Err(EvidenceRejection::Unverifiable));
    }
    // Relevance and listings: for each covered non-anchor certificate under
    // this CRL's issuer name, the signer has revocation authority over it,
    // is a shadow of its issuer, or is neither (a same-subject CA another
    // anchor vouches for). Authority makes the CRL about the chains, and
    // its listing of that certificate is a revocation; a shadow's listing is
    // forged material about it, Unverifiable, never a failure a third party
    // could append (lead ruling F). Any other listing, or a listing of a
    // certificate outside the covered chains, claims nothing about them.
    let revoked = crl
        .tbs_cert_list
        .revoked_certificates
        .as_deref()
        .unwrap_or_default();
    let mut about_chain = false;
    let mut revoked_listing = false;
    let mut forged_listing = false;
    for cert in covered {
        if cert.cert.tbs_certificate.issuer != crl.tbs_cert_list.issuer
            || anchors.iter().any(|anchor| anchor.der == cert.der)
        {
            continue;
        }
        let authorized = crl_signer_authorized(cert, issuer, embedded, anchors, memory)?;
        about_chain |= authorized;
        if revoked
            .iter()
            .any(|r| r.serial_number == cert.cert.tbs_certificate.serial_number)
        {
            if authorized {
                revoked_listing = true;
            } else if crl_signer_shadows(cert, issuer, embedded, anchors, covered, memory)? {
                forged_listing = true;
            }
        }
    }
    if !about_chain {
        return Ok(if forged_listing {
            Err(EvidenceRejection::Unverifiable)
        } else {
            Ok(issuer)
        });
    }
    // Authenticity first, then what the genuine CRL says: a forged delta,
    // scoped, stale or revoking CRL is Unverifiable, never a failure.
    if !crl_complete_scope(&crl) {
        return Ok(Err(EvidenceRejection::Unusable));
    }
    if !evidence_fresh(
        crl.tbs_cert_list.this_update,
        crl.tbs_cert_list.next_update,
        at_unix,
    ) {
        return Ok(Err(EvidenceRejection::Unusable));
    }
    if revoked_listing {
        return Ok(Err(EvidenceRejection::Revoked));
    }
    if forged_listing {
        return Ok(Err(EvidenceRejection::Unverifiable));
    }
    Ok(Ok(issuer))
}

/// id-sha1 (RFC 6960 default CertID hash) and id-kp-OCSPSigning.
const OID_SHA1_BYTES: &[u8] = b"\x2b\x0e\x03\x02\x1a";

const OID_OCSP_SIGNING: &[u8] = b"\x2b\x06\x01\x05\x05\x07\x03\x09";

/// Clock-skew tolerance for the OCSP producedAt sanity bound (seconds).
const OCSP_PRODUCED_AT_MAX_SKEW_SECS: u64 = 300;

/// Clock-skew tolerance for RFC 3161 token genTime sanity (seconds). A token
/// whose genTime lies further ahead of the verify clock than this anchors the
/// applicable time in the FUTURE, gaming every freshness window that consumes
/// it; such a token is rejected outright (never clamped — a clamped genTime
/// would still certify a signature the TSA had not seen at the clamp time).
/// Within-skew passes: TSA and verifier clocks are not assumed synchronized.
pub(super) const TS_GEN_TIME_MAX_SKEW_SECS: u64 = 300;

/// genTime ahead of the verify clock beyond the documented skew? Shared
/// with the seal-side response validation (tsp.rs validate_response): one
/// bound on both paths so a token the verifier would reject is never
/// returned as validated at seal time.
pub(crate) fn gen_time_beyond_skew(gen_time: u64, clock_ms: u64) -> bool {
    gen_time > (clock_ms / 1000).saturating_add(TS_GEN_TIME_MAX_SKEW_SECS)
}

/// Hash `data` with the CertID hash algorithm; only SHA-1 and SHA-256 are
/// recognized evidence-hash forms.
fn cert_id_hash(
    oid_bytes: &[u8],
    data: &[u8],
    memory: &MemoryLedger,
) -> Result<Option<(Vec<u8>, LedgerHold)>, SealMemoryRefusal> {
    if cms::is_sha256_oid(oid_bytes) {
        let hash = cms::sha256(data);
        let held = memory.hold(hash.len())?;
        return Ok(Some((hash.to_vec(), held)));
    }
    if oid_bytes == OID_SHA1_BYTES {
        use sha1::Digest;
        let hash = sha1::Sha1::digest(data);
        let held = memory.hold(hash.len())?;
        return Ok(Some((hash.to_vec(), held)));
    }
    Ok(None)
}

/// The cert a SingleResponse binds to: serial match against an embedded or
/// anchored cert, and the CertID issuer hashes recompute against that
/// cert's ACTUAL issuer — the name-matched candidate whose key signed the
/// target certificate (§7.5 step 3 certificate identity/serial). Serial and
/// issuer are bound TOGETHER: when several validation-set certs share a
/// serial (different issuers), each candidate is tried until one complete
/// binding (serial + actual issuer + both CertID hashes) holds. A
/// same-subject/different-key shadow fails `issued_by`, so its name+key
/// hashes can never authenticate the binding.
fn ocsp_cert_binding<'a>(
    cert_id: &x509_ocsp::CertId,
    embedded: &'a [EmbeddedCert],
    anchors: &'a [EmbeddedCert],
    memory: &MemoryLedger,
) -> Result<Option<(&'a EmbeddedCert, &'a EmbeddedCert)>, SealMemoryRefusal> {
    let oid = cert_id.hash_algorithm.oid.as_bytes();
    for target in embedded
        .iter()
        .chain(anchors.iter())
        .filter(|c| c.cert.tbs_certificate.serial_number == cert_id.serial_number)
    {
        let mut issuer = None;
        for candidate in issuer_candidates(&target.cert.tbs_certificate.issuer, embedded, anchors) {
            if issued_by(target, candidate, memory)? {
                issuer = Some(candidate);
                break;
            }
        }
        let Some(issuer) = issuer else {
            continue;
        };
        let name_matches = {
            use der::Encode;
            let subject = &issuer.cert.tbs_certificate.subject;
            let Some(subject_len) = subject
                .encoded_len()
                .ok()
                .and_then(|len| usize::try_from(len).ok())
            else {
                continue;
            };
            let _subject_held = memory.hold(subject_len)?;
            let Ok(subject_der) = subject.to_der() else {
                continue;
            };
            let Some(name_hash) = cert_id_hash(oid, &subject_der, memory)? else {
                continue;
            };
            name_hash.0 == cert_id.issuer_name_hash.as_bytes()
        };
        if !name_matches {
            continue;
        }
        let key_matches = {
            let key_bytes = issuer
                .cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let Some(key_hash) = cert_id_hash(oid, key_bytes, memory)? else {
                continue;
            };
            key_hash.0 == cert_id.issuer_key_hash.as_bytes()
        };
        if !key_matches {
            continue;
        }
        return Ok(Some((target, issuer)));
    }
    Ok(None)
}

/// RFC 6960 §2.6: the responder is the issuer itself, or a delegate
/// carrying the id-kp-OCSPSigning EKU whose certificate is actually issued
/// BY the issuer (delegation chains to the key-bound actual issuer, never
/// to a same-subject shadow). A delegate must additionally be TIME-VALID at
/// the applicable time: delegation rides a certificate, and an expired or
/// not-yet-valid delegate certificate authorizes nothing. A responder the
/// issuer did not delegate to, or whose key usage or EKU does not allow it,
/// is Unverifiable; a genuine delegate outside its validity is Unusable.
fn ocsp_responder_authorized(
    responder: &EmbeddedCert,
    issuer: &EmbeddedCert,
    at_unix: u64,
    memory: &MemoryLedger,
) -> Result<Result<(), EvidenceRejection>, SealMemoryRefusal> {
    use der::Decode;
    use x509_cert::ext::pkix::KeyUsage;
    if responder.der == issuer.der {
        return Ok(Ok(()));
    }
    let validity = &responder.cert.tbs_certificate.validity;
    let time_valid =
        time_secs(validity.not_before) <= at_unix && at_unix <= time_secs(validity.not_after);
    let has_eku = responder
        .cert
        .tbs_certificate
        .extensions
        .as_ref()
        .is_some_and(|exts| {
            exts.iter().any(|e| {
                e.extn_id.as_bytes() == b"\x55\x1d\x25"
                    && x509_cert::ext::pkix::ExtendedKeyUsage::from_der(e.extn_value.as_bytes())
                        .is_ok_and(|eku| eku.0.iter().any(|o| o.as_bytes() == OID_OCSP_SIGNING))
            })
        });
    // A PRESENT KeyUsage must permit signing — symmetric with the
    // signer-leaf / CRL-issuer gates, and fail-CLOSED on a KeyUsage whose
    // DER does not decode (botfix8 F2: the botfix-7 shape authorized a
    // delegate carrying a present-but-unreadable KeyUsage). An ABSENT
    // KeyUsage follows the documented RFC 5280 §4.2.1.3 posture (passes).
    let ku_permits_signing = key_usage_permits(&responder.cert, KeyUsage::digital_signature);
    if !(has_eku && ku_permits_signing && issued_by(responder, issuer, memory)?) {
        return Ok(Err(EvidenceRejection::Unverifiable));
    }
    Ok(if time_valid {
        Ok(())
    } else {
        Err(EvidenceRejection::Unusable)
    })
}

/// Does this candidate certificate match the BasicOCSPResponse responderID?
fn ocsp_responder_matches(rid: &x509_ocsp::ResponderId, cert: &x509_cert::Certificate) -> bool {
    match rid {
        x509_ocsp::ResponderId::ByName(name) => *name == cert.tbs_certificate.subject,
        x509_ocsp::ResponderId::ByKey(hash) => {
            use sha1::Digest;
            let key = cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            &sha1::Sha1::digest(key)[..] == hash.as_bytes()
        }
    }
}

/// Why presented revocation evidence is not used (lead ruling F,
/// SEAL-SHADOW-ETSI, 10 Nov 06:50; Engine reading 07:02).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceRejection {
    /// Forged or unverifiable: it does not parse, no key it claims verifies
    /// it, it binds to no validation-set certificate, or its signer is not
    /// authorized to sign it. Anyone holding the signed PDF can append it, so
    /// it is discarded and reported as possible tampering, never as a
    /// failure.
    Unverifiable,
    /// Genuine but not usable here: stale or future-dated at the applicable
    /// time, a delegate responder outside its validity, or a delta or
    /// IDP-scoped CRL.
    Unusable,
    /// Genuine, and says a validation-set certificate is revoked.
    Revoked,
}

/// An authenticated OCSP response: only `good` targets supply revocation
/// coverage; an authenticated `unknown` remains unresolved, not invalid, for
/// the certificate it names (`unknown_statuses`). What it says no to is in
/// `negative`, one claim per SingleResponse.
pub(crate) struct OcspEvidence<'a> {
    pub(crate) good_targets: Vec<&'a [u8]>,
    pub(crate) unknown_statuses: Vec<UnknownStatus<'a>>,
    pub(crate) negative: Vec<NegativeClaim<'a>>,
}

/// An authenticated `unknown` SingleResponse. Its CertID names a certificate
/// by issuer and serial number: `target` is the first certificate it bound
/// to, `issuer` the certificate whose key signed that target.
pub(crate) struct UnknownStatus<'a> {
    pub(crate) target: &'a EmbeddedCert,
    pub(crate) issuer: &'a EmbeddedCert,
}

/// What an authenticated SingleResponse says no to about the certificate
/// it binds: `revoked` (Revoked), or stale, signed by a delegate outside
/// its validity, or in a response produced after the applicable time
/// (Unusable). It counts only when its issuer and serial name a covered
/// non-anchor certificate (Engine call Q-C = A, 10 Nov 07:23); about any
/// other certificate it claims nothing (Q4).
pub(crate) struct NegativeClaim<'a> {
    pub(crate) target: &'a EmbeddedCert,
    pub(crate) issuer: &'a EmbeddedCert,
    pub(crate) rejection: EvidenceRejection,
}

/// One DSS OCSP entry: successful basic response whose signature verifies
/// under an authorized responder, with every SingleResponse bound to an
/// embedded/anchored cert serial. A `good` SingleResponse fresh at the
/// applicable time supplies coverage; an `unknown` is returned only after
/// the signature, every binding and authorization validate and its own
/// SingleResponse is fresh. The
/// response's own certificates are held on `memory` as responder
/// candidates (FIX 12260); memory refused is `Err`. A response that is not
/// authentic is rejected as Unverifiable (lead ruling F): unparseable,
/// unsuccessful, empty, without a responder, bound to no validation-set
/// certificate, signed by an unauthorized responder or not verifying. What
/// an authentic response says no to (produced after the applicable time,
/// stale, a delegate outside its validity, `revoked`) is returned as its
/// negative claims, for the caller to weigh against the covered chains.
pub(crate) fn ocsp_entry_valid<'a>(
    data: &[u8],
    embedded: &'a [EmbeddedCert],
    anchors: &'a [EmbeddedCert],
    at_unix: u64,
    memory: &MemoryLedger,
) -> Result<Result<OcspEvidence<'a>, EvidenceRejection>, SealMemoryRefusal> {
    use const_oid::AssociatedOid;
    use der::Decode;
    let Ok(resp) = x509_ocsp::OcspResponse::from_der(data) else {
        return Ok(Err(EvidenceRejection::Unverifiable));
    };
    if resp.response_status != x509_ocsp::OcspResponseStatus::Successful {
        return Ok(Err(EvidenceRejection::Unverifiable));
    }
    let Some(bytes) = &resp.response_bytes else {
        return Ok(Err(EvidenceRejection::Unverifiable));
    };
    if bytes.response_type != x509_ocsp::BasicOcspResponse::OID {
        return Ok(Err(EvidenceRejection::Unverifiable));
    }
    let Ok(basic) = x509_ocsp::BasicOcspResponse::from_der(bytes.response.as_bytes()) else {
        return Ok(Err(EvidenceRejection::Unverifiable));
    };
    if basic.tbs_response_data.responses.is_empty() {
        return Ok(Err(EvidenceRejection::Unverifiable));
    }
    // Candidate responder certs: response-embedded, then DSS, then anchors.
    let mut candidates: Vec<EmbeddedCert> = Vec::new();
    if let Some(certs) = &basic.certs {
        for c in certs {
            let Some(candidate) = EmbeddedCert::admitted_copy(c, memory)? else {
                return Ok(Err(EvidenceRejection::Unverifiable));
            };
            candidates.push(candidate);
        }
    }
    memory.admit_len::<&[u8]>(basic.tbs_response_data.responses.len())?;
    ocsp_basic_valid(&basic, &candidates, embedded, anchors, at_unix, memory)
}

/// The rest of [`ocsp_entry_valid`]: the responder among `candidates`, the
/// DSS certificates and the anchors, the response signature, each
/// SingleResponse's binding and the responder's authority over it, and
/// only then what the genuine response says: producedAt, freshness and
/// status. Judging authenticity first means a forged response is
/// Unverifiable whatever it claims: a forged `revoked`, stale or
/// future-dated response never fails the verdict (lead ruling F).
fn ocsp_basic_valid<'a>(
    basic: &x509_ocsp::BasicOcspResponse,
    candidates: &[EmbeddedCert],
    embedded: &'a [EmbeddedCert],
    anchors: &'a [EmbeddedCert],
    at_unix: u64,
    memory: &MemoryLedger,
) -> Result<Result<OcspEvidence<'a>, EvidenceRejection>, SealMemoryRefusal> {
    use der::Encode;
    let Some(responder) = candidates
        .iter()
        .find(|c| ocsp_responder_matches(&basic.tbs_response_data.responder_id, &c.cert))
        .or_else(|| {
            embedded
                .iter()
                .chain(anchors.iter())
                .find(|c| ocsp_responder_matches(&basic.tbs_response_data.responder_id, &c.cert))
        })
    else {
        return Ok(Err(EvidenceRejection::Unverifiable));
    };
    let Ok(alg) = cms::cert_signature_algorithm(&responder.der) else {
        return Ok(Err(EvidenceRejection::Unverifiable));
    };
    let oid = basic.signature_algorithm.oid.as_bytes();
    if !cms::sig_alg_permitted(alg, oid) {
        return Ok(Err(EvidenceRejection::Unverifiable));
    }
    let Some(tbs_len) = basic
        .tbs_response_data
        .encoded_len()
        .ok()
        .and_then(|len| usize::try_from(len).ok())
    else {
        return Ok(Err(EvidenceRejection::Unverifiable));
    };
    let tbs_held = memory.hold(tbs_len)?;
    let Ok(tbs) = basic.tbs_response_data.to_der() else {
        return Ok(Err(EvidenceRejection::Unverifiable));
    };
    if cms::verify_signature_value(alg, &responder.der, &tbs, basic.signature.raw_bytes()).is_err()
    {
        return Ok(Err(EvidenceRejection::Unverifiable));
    }
    drop(tbs);
    drop(tbs_held);
    let responses = &basic.tbs_response_data.responses;
    memory.admit_len::<(&EmbeddedCert, &EmbeddedCert, Result<(), EvidenceRejection>)>(
        responses.len(),
    )?;
    let mut bound = Vec::with_capacity(responses.len());
    for single in responses {
        let Some((target, issuer)) = ocsp_cert_binding(&single.cert_id, embedded, anchors, memory)?
        else {
            return Ok(Err(EvidenceRejection::Unverifiable));
        };
        let authority = ocsp_responder_authorized(responder, issuer, at_unix, memory)?;
        if authority == Err(EvidenceRejection::Unverifiable) {
            return Ok(Err(EvidenceRejection::Unverifiable));
        }
        bound.push((target, issuer, authority));
    }
    // producedAt sanity bound: RFC 6960 assigns producedAt no freshness
    // semantics, but a response claiming to be produced BEYOND the
    // applicable time (plus a documented clock-skew tolerance) is not
    // plausible evidence: every SingleResponse in it is Unusable.
    let produced_at = basic
        .tbs_response_data
        .produced_at
        .0
        .to_unix_duration()
        .as_secs();
    let produced_late = produced_at > at_unix.saturating_add(OCSP_PRODUCED_AT_MAX_SKEW_SECS);
    let mut targets: Vec<&[u8]> = Vec::with_capacity(responses.len());
    let mut unknown_statuses: Vec<UnknownStatus<'_>> = Vec::new();
    memory.admit_len::<NegativeClaim<'_>>(responses.len())?;
    let mut negative = Vec::with_capacity(responses.len());
    for (single, (target, issuer, authority)) in responses.iter().zip(bound) {
        let rejection = if produced_late {
            Some(EvidenceRejection::Unusable)
        } else if let Err(rejection) = authority {
            Some(rejection)
        } else if !evidence_fresh(
            x509_cert::time::Time::GeneralTime(single.this_update.0),
            single
                .next_update
                .map(|n| x509_cert::time::Time::GeneralTime(n.0)),
            at_unix,
        ) {
            Some(EvidenceRejection::Unusable)
        } else if matches!(single.cert_status, x509_ocsp::CertStatus::Revoked(_)) {
            Some(EvidenceRejection::Revoked)
        } else {
            None
        };
        if let Some(rejection) = rejection {
            negative.push(NegativeClaim {
                target,
                issuer,
                rejection,
            });
        } else if matches!(single.cert_status, x509_ocsp::CertStatus::Good(_)) {
            targets.push(target.der.as_slice());
        } else {
            unknown_statuses.push(UnknownStatus { target, issuer });
        }
    }
    Ok(Ok(OcspEvidence {
        good_targets: targets,
        unknown_statuses,
        negative,
    }))
}
