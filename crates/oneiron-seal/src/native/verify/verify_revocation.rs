//! CRL/OCSP evidence validators: issuer key-binding, freshness windows and clock-skew bounds.

use super::super::cms;
use super::verify_chain_gates::{issuer_permits_crl_sign, key_usage_permits};
use super::verify_dss_core::EmbeddedCert;

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
pub(crate) fn issued_by(cert: &EmbeddedCert, issuer: &EmbeddedCert) -> bool {
    use der::Encode;
    if cert.cert.tbs_certificate.issuer != issuer.cert.tbs_certificate.subject {
        return false;
    }
    let Ok(alg) = cms::cert_signature_algorithm(&issuer.der) else {
        return false;
    };
    let oid = cert.cert.signature_algorithm.oid.as_bytes();
    if !cms::sig_alg_permitted(alg, oid) {
        return false;
    }
    let Ok(tbs) = cert.cert.tbs_certificate.to_der() else {
        return false;
    };
    cms::verify_signature_value(alg, &issuer.der, &tbs, cert.cert.signature.raw_bytes()).is_ok()
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

/// One DSS CRL entry: parses, signature verifies against an
/// embedded/anchored issuer cert with a consistent algorithm, is fresh at
/// the applicable time, and lists no in-scope serial on its revoked list
/// (§7.5 step 3). In-scope means every cert in the validation set
/// (embedded, anchors, and the report's covered chains) issued by this
/// CRL's issuer; any listed serial invalidates the evidence. The issuer is
/// the first name-matched candidate whose KEY verifies the CRL signature —
/// a same-subject/different-key shadow can only authenticate a CRL it
/// truly signed, and the coverage rule below counts that CRL only for
/// certificates that shadow actually issued (`issued_by`). On success
/// returns that key-bound issuer certificate.
pub(super) fn crl_entry_valid<'a>(
    data: &[u8],
    embedded: &'a [EmbeddedCert],
    anchors: &'a [EmbeddedCert],
    covered: &[EmbeddedCert],
    at_unix: u64,
) -> Option<&'a EmbeddedCert> {
    use der::{Decode, Encode};
    let Ok(crl) = x509_cert::crl::CertificateList::from_der(data) else {
        return None;
    };
    if !crl_complete_scope(&crl) {
        return None;
    }
    let Ok(tbs) = crl.tbs_cert_list.to_der() else {
        return None;
    };
    let oid = crl.signature_algorithm.oid.as_bytes();
    let issuer = issuer_candidates(&crl.tbs_cert_list.issuer, embedded, anchors).find(|cand| {
        let Ok(alg) = cms::cert_signature_algorithm(&cand.der) else {
            return false;
        };
        cms::sig_alg_permitted(alg, oid)
            && cms::verify_signature_value(alg, &cand.der, &tbs, crl.signature.raw_bytes()).is_ok()
    })?;
    // Key verification alone is not authorization: the issuer certificate
    // must permit CRL signing (cRLSign) when it carries a KeyUsage.
    if !issuer_permits_crl_sign(&issuer.cert) {
        return None;
    }
    if !evidence_fresh(
        crl.tbs_cert_list.this_update,
        crl.tbs_cert_list.next_update,
        at_unix,
    ) {
        return None;
    }
    // Revocation evaluation: a validation-set certificate issued by this
    // CRL's issuer whose serial is on the revoked list makes the evidence
    // assert a revocation — it can never support validity. Name-matched
    // scoping is deliberate (fail-closed): a shadow issuer listing a real
    // serial still poisons its own CRL.
    if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
        let in_scope = embedded
            .iter()
            .chain(anchors.iter())
            .chain(covered.iter())
            .filter(|c| c.cert.tbs_certificate.issuer == crl.tbs_cert_list.issuer);
        for cert in in_scope {
            if revoked
                .iter()
                .any(|r| r.serial_number == cert.cert.tbs_certificate.serial_number)
            {
                return None;
            }
        }
    }
    Some(issuer)
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
fn cert_id_hash(oid_bytes: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if cms::is_sha256_oid(oid_bytes) {
        return Some(cms::sha256(data).to_vec());
    }
    if oid_bytes == OID_SHA1_BYTES {
        use sha1::Digest;
        return Some(sha1::Sha1::digest(data).to_vec());
    }
    None
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
) -> Option<(&'a EmbeddedCert, &'a EmbeddedCert)> {
    let oid = cert_id.hash_algorithm.oid.as_bytes();
    embedded
        .iter()
        .chain(anchors.iter())
        .filter(|c| c.cert.tbs_certificate.serial_number == cert_id.serial_number)
        .find_map(|target| {
            let issuer = issuer_candidates(&target.cert.tbs_certificate.issuer, embedded, anchors)
                .find(|cand| issued_by(target, cand))?;
            let subject_der = der::Encode::to_der(&issuer.cert.tbs_certificate.subject).ok()?;
            let key_bytes = issuer
                .cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            if cert_id_hash(oid, &subject_der)? != cert_id.issuer_name_hash.as_bytes() {
                return None;
            }
            if cert_id_hash(oid, key_bytes)? != cert_id.issuer_key_hash.as_bytes() {
                return None;
            }
            Some((target, issuer))
        })
}

/// RFC 6960 §2.6: the responder is the issuer itself, or a delegate
/// carrying the id-kp-OCSPSigning EKU whose certificate is actually issued
/// BY the issuer (delegation chains to the key-bound actual issuer, never
/// to a same-subject shadow). A delegate must additionally be TIME-VALID at
/// the applicable time: delegation rides a certificate, and an expired or
/// not-yet-valid delegate certificate authorizes nothing.
fn ocsp_responder_authorized(
    responder: &EmbeddedCert,
    issuer: &EmbeddedCert,
    at_unix: u64,
) -> bool {
    use der::Decode;
    use x509_cert::ext::pkix::KeyUsage;
    if responder.der == issuer.der {
        return true;
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
    time_valid && has_eku && ku_permits_signing && issued_by(responder, issuer)
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

/// One DSS OCSP entry: successful basic response whose signature verifies
/// under an authorized responder, with every SingleResponse bound to an
/// embedded/anchored cert serial, fresh at the applicable time, and
/// asserting `good`. A `revoked` status invalidates the evidence; `unknown`
/// fails closed (the blueprint leaves it unpinned, §7.5/§7.7). On success
/// returns the DERs of the target certificates the SingleResponses bind
/// to, so the coverage rule can match them against the covered chain.
pub(super) fn ocsp_entry_valid(
    data: &[u8],
    embedded: &[EmbeddedCert],
    anchors: &[EmbeddedCert],
    at_unix: u64,
) -> Option<Vec<Vec<u8>>> {
    use const_oid::AssociatedOid;
    use der::{Decode, Encode};
    let Ok(resp) = x509_ocsp::OcspResponse::from_der(data) else {
        return None;
    };
    if resp.response_status != x509_ocsp::OcspResponseStatus::Successful {
        return None;
    }
    let Some(bytes) = &resp.response_bytes else {
        return None;
    };
    if bytes.response_type != x509_ocsp::BasicOcspResponse::OID {
        return None;
    }
    let Ok(basic) = x509_ocsp::BasicOcspResponse::from_der(bytes.response.as_bytes()) else {
        return None;
    };
    // producedAt sanity bound: RFC 6960 assigns producedAt no freshness
    // semantics, but a response claiming to be produced BEYOND the
    // applicable time (plus a documented clock-skew tolerance) is not
    // plausible evidence and is rejected.
    let produced_at = basic
        .tbs_response_data
        .produced_at
        .0
        .to_unix_duration()
        .as_secs();
    if produced_at > at_unix.saturating_add(OCSP_PRODUCED_AT_MAX_SKEW_SECS) {
        return None;
    }
    if basic.tbs_response_data.responses.is_empty() {
        return None;
    }
    // Candidate responder certs: response-embedded, then DSS, then anchors.
    let mut candidates: Vec<EmbeddedCert> = Vec::new();
    if let Some(certs) = &basic.certs {
        for c in certs {
            let Ok(der_bytes) = c.to_der() else {
                return None;
            };
            candidates.push(EmbeddedCert {
                der: der_bytes,
                cert: c.clone(),
            });
        }
    }
    let responder = candidates
        .iter()
        .find(|c| ocsp_responder_matches(&basic.tbs_response_data.responder_id, &c.cert))
        .or_else(|| {
            embedded
                .iter()
                .chain(anchors.iter())
                .find(|c| ocsp_responder_matches(&basic.tbs_response_data.responder_id, &c.cert))
        })?;
    let mut targets: Vec<Vec<u8>> = Vec::with_capacity(basic.tbs_response_data.responses.len());
    for single in &basic.tbs_response_data.responses {
        let (target, issuer) = ocsp_cert_binding(&single.cert_id, embedded, anchors)?;
        if !ocsp_responder_authorized(responder, issuer, at_unix) {
            return None;
        }
        if !evidence_fresh(
            x509_cert::time::Time::GeneralTime(single.this_update.0),
            single
                .next_update
                .map(|n| x509_cert::time::Time::GeneralTime(n.0)),
            at_unix,
        ) {
            return None;
        }
        // Evaluate the asserted status: only `good` supports validity.
        if !matches!(single.cert_status, x509_ocsp::CertStatus::Good(_)) {
            return None;
        }
        targets.push(target.der.clone());
    }
    let Ok(alg) = cms::cert_signature_algorithm(&responder.der) else {
        return None;
    };
    let oid = basic.signature_algorithm.oid.as_bytes();
    if !cms::sig_alg_permitted(alg, oid) {
        return None;
    }
    let Ok(tbs) = basic.tbs_response_data.to_der() else {
        return None;
    };
    cms::verify_signature_value(alg, &responder.der, &tbs, basic.signature.raw_bytes())
        .is_ok()
        .then_some(targets)
}
