//! Native verifier and profile classifier (§7.7).
//!
//! A parseable but cryptographically invalid sealed PDF yields
//! `Ok(VerifyReport { valid: false, .. })`; [`SealError::InputInvalid`] is
//! reserved for bytes that cannot be safely parsed within limits. A malformed
//! optional timestamp or DSS object is a failed verification, never an
//! absent optional profile.

use lopdf::{Document, LoadOptions, Object};

use crate::api::{
    PadesProfile, SealConfig, Sha256Digest, VerifyCheck, VerifyCheckKind, VerifyCheckStatus,
    VerifyFindingCode, VerifyReport,
};
use crate::error::{InputInvalidCode, SealError};

use super::{cms, pdf, tsp};

pub(crate) struct VerifyCtx<'a> {
    pub config: &'a SealConfig,
    pub clock_ms: u64,
}

fn malformed_input() -> SealError {
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

/// Signer-leaf key-usage gate: when the leaf carries a KeyUsage extension it
/// must permit signing — `digitalSignature` or `contentCommitment`
/// (nonRepudiation). Any other class (e.g. keyEncipherment-only) cannot act
/// as a signing identity. An ABSENT KeyUsage follows RFC 5280 §4.2.1.3 (the
/// key is unconstrained) and passes; this mirrors the vendored pkix-chain
/// TSA profile's treatment of a missing extension. The TSA chain does not
/// ride this gate: tsp.rs keeps it on the vendored `verify_time_stamper`
/// profile, which enforces the RFC 3161 signing-only shape.
fn enforce_signer_leaf_key_usage(leaf: &x509_cert::Certificate) -> Result<(), SealError> {
    use const_oid::AssociatedOid;
    use der::Decode;
    use x509_cert::ext::pkix::KeyUsage;
    let Some(exts) = &leaf.tbs_certificate.extensions else {
        return Ok(());
    };
    for ext in exts {
        if ext.extn_id == KeyUsage::OID {
            let ku = KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|_| cert_path_err())?;
            if !ku.digital_signature() && !ku.non_repudiation() {
                return Err(cert_path_err());
            }
        }
    }
    Ok(())
}

/// CRL-issuer key-usage gate: when the issuer certificate carries a KeyUsage
/// extension it must assert `cRLSign` — a key verified to have signed a CRL
/// is not enough; the certificate must also AUTHORIZE that use. An ABSENT
/// KeyUsage follows the same documented RFC 5280 §4.2.1.3 posture as the
/// signer-leaf gate (unconstrained key, passes).
fn issuer_permits_crl_sign(cert: &x509_cert::Certificate) -> bool {
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
            return ku.crl_sign();
        }
    }
    true
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

fn anchors(config: &SealConfig) -> Vec<pkix_chain::TrustAnchor> {
    use der::Decode;
    config
        .trust_anchors_der
        .iter()
        .filter_map(|d| x509_cert::Certificate::from_der(d).ok())
        .map(pkix_chain::TrustAnchor::from_cert)
        .collect()
}

#[derive(Debug)]
struct SigEntry {
    is_doc_ts: bool,
    byte_range: [u64; 4],
    /// Decoded `/Contents` bytes (DER CMS followed by zero padding).
    contents: Vec<u8>,
}

fn name_eq(obj: &Object, expected: &[u8]) -> bool {
    matches!(obj, Object::Name(n) if n == expected)
}

/// Collect signature/timestamp dictionaries in revision order (earlier
/// revisions cover fewer bytes). Discovery is by `/Type /Sig|DocTimeStamp`
/// AND by the typeless interop shape (real-world signers omit the optional
/// `/Type`). Typeless candidacy requires `/ByteRange`: dictionaries without
/// it are never candidates, whatever `/Contents` holds — an ordinary `/Page`
/// dictionary carries `/Contents` for its page content stream. A
/// `/ByteRange` without `/Contents` is a partial signature shape: malformed
/// input, never a silent skip.
///
/// `/SubFilter` dispatch (fail-closed): a candidate is evaluated ONLY under
/// the handler its `/SubFilter` names — `/Sig` requires
/// `/ETSI.CAdES.detached`, `/DocTimeStamp` requires `/ETSI.RFC3161`. A typed
/// dictionary with an absent or foreign `/SubFilter` (e.g.
/// `/adbe.pkcs7.detached`) is SKIPPED, never evaluated as CAdES; a document
/// left with no evaluable CAdES signature fails verification. The typeless
/// interop path tolerates an ABSENT `/SubFilter` (that is the shape it
/// exists for) but a PRESENT one must still name the CAdES handler.
fn collect_signatures(doc: &Document) -> Result<Vec<SigEntry>, SealError> {
    let mut out = Vec::new();
    for obj in doc.objects.values() {
        let Object::Dictionary(d) = obj else { continue };
        let is_doc_ts = match d.get(b"Type") {
            Ok(t) if name_eq(t, b"Sig") => {
                if !matches!(d.get(b"SubFilter"), Ok(sf) if name_eq(sf, b"ETSI.CAdES.detached")) {
                    continue;
                }
                false
            }
            Ok(t) if name_eq(t, b"DocTimeStamp") => {
                if !matches!(d.get(b"SubFilter"), Ok(sf) if name_eq(sf, b"ETSI.RFC3161")) {
                    continue;
                }
                true
            }
            _ if !d.has(b"ByteRange") => continue,
            _ => {
                if !d.has(b"Contents") {
                    return Err(malformed_input());
                }
                if matches!(d.get(b"SubFilter"), Ok(sf) if !name_eq(sf, b"ETSI.CAdES.detached")) {
                    continue;
                }
                false
            }
        };
        let br_obj = d.get(b"ByteRange").map_err(|_| malformed_input())?;
        let Object::Array(items) = br_obj else {
            return Err(malformed_input());
        };
        if items.len() != 4 {
            return Err(malformed_input());
        }
        let mut br = [0u64; 4];
        for (i, item) in items.iter().enumerate() {
            let Object::Integer(v) = item else {
                return Err(malformed_input());
            };
            br[i] = u64::try_from(*v).map_err(|_| malformed_input())?;
        }
        let Object::String(contents, _) = d.get(b"Contents").map_err(|_| malformed_input())? else {
            return Err(malformed_input());
        };
        out.push(SigEntry {
            is_doc_ts,
            byte_range: br,
            contents: contents.clone(),
        });
    }
    out.sort_by_key(|e| e.byte_range[2].saturating_add(e.byte_range[3]));
    Ok(out)
}

struct Checks {
    list: Vec<VerifyCheck>,
}

impl Checks {
    fn new() -> Self {
        Self { list: Vec::new() }
    }

    fn record(&mut self, kind: VerifyCheckKind, ok: bool, finding: VerifyFindingCode) {
        self.list.push(VerifyCheck {
            kind,
            status: if ok {
                VerifyCheckStatus::Pass
            } else {
                VerifyCheckStatus::Fail
            },
            finding: if ok { None } else { Some(finding) },
        });
    }

    fn absent(&mut self, kind: VerifyCheckKind) {
        self.list.push(VerifyCheck {
            kind,
            status: VerifyCheckStatus::AbsentAllowed,
            finding: None,
        });
    }

    fn passed(&self, kind: VerifyCheckKind) -> bool {
        self.list
            .iter()
            .any(|c| c.kind == kind && c.status == VerifyCheckStatus::Pass)
    }
}

/// PDF white-space (ISO 32000-1 Table 1): legal inside hex strings.
fn is_pdf_whitespace(b: u8) -> bool {
    matches!(b, 0x00 | 0x09 | 0x0A | 0x0C | 0x0D | 0x20)
}

/// ByteRange shape, bounds, non-overlap, and exact `/Contents` exclusion.
fn check_byte_range(bytes: &[u8], e: &SigEntry) -> bool {
    let [s1, l1, s2, l2] = e.byte_range;
    let (s1, l1, s2, l2) = match (
        usize::try_from(s1),
        usize::try_from(l1),
        usize::try_from(s2),
        usize::try_from(l2),
    ) {
        (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
        _ => return false,
    };
    if s1 != 0 || l1 >= s2 {
        return false; // span1 must start at 0 and end before span2
    }
    let Some(end2) = s2.checked_add(l2) else {
        return false;
    };
    if end2 > bytes.len() {
        return false; // out of bounds
    }
    // Exact /Contents exclusion: gap delimiters and hex length must line up.
    if l1 >= bytes.len() || s2 > bytes.len() || s2 < l1 + 2 {
        return false;
    }
    if bytes[l1] != b'<' || bytes[s2 - 1] != b'>' {
        return false;
    }
    // Whitespace inside the hex string is spec-legal: strip it before the
    // length check so padded real-world /Contents values verify.
    let hex_chars = bytes[l1 + 1..s2 - 1]
        .iter()
        .filter(|b| !is_pdf_whitespace(**b))
        .count();
    hex_chars == e.contents.len() * 2
}

/// Strip the zero padding after the leading CMS DER; reject nonzero padding.
fn unpadded_cms(contents: &[u8]) -> Option<&[u8]> {
    let mut r = cms::DerReader::new(contents);
    let first = r.read().ok()?;
    let used = first.full.len();
    if contents[used..].iter().any(|b| *b != 0) {
        return None;
    }
    Some(first.full)
}

/// Verify one CAdES-detached signature dictionary. On a parseable envelope
/// the CMS certificate set is recorded in `covered` so the DSS binding can
/// require the validation material to speak about this chain (§7.5 step 3).
#[allow(clippy::too_many_lines)]
fn verify_cades_sig(
    bytes: &[u8],
    e: &SigEntry,
    ctx: &VerifyCtx<'_>,
    anchors: &[pkix_chain::TrustAnchor],
    checks: &mut Checks,
    covered: &mut Vec<EmbeddedCert>,
) {
    let br_ok = check_byte_range(bytes, e);
    checks.record(
        VerifyCheckKind::ByteRange,
        br_ok,
        VerifyFindingCode::InvalidByteRange,
    );
    let spans_digest = if br_ok {
        pdf::hash_byte_range(bytes, e.byte_range).ok()
    } else {
        None
    };
    let cms_der = unpadded_cms(&e.contents);
    let parsed = cms_der.and_then(|d| cms::parse_cms(d).ok());
    let env_ok = parsed.as_ref().is_some_and(|p| {
        p.content_oid == cms::OID_SIGNED_DATA.as_bytes()
            && p.econtent.is_none()
            && p.econtent_oid == cms::OID_DATA.as_bytes()
            && p.digest_algs.len() == 1
            && cms::is_sha256_oid(&p.digest_algs[0])
            && cms::is_sha256_oid(&p.signer.digest_alg_oid)
    });
    checks.record(
        VerifyCheckKind::CmsEnvelope,
        env_ok,
        VerifyFindingCode::InvalidCms,
    );
    let Some(parsed) = parsed.filter(|_| env_ok) else {
        checks.record(
            VerifyCheckKind::SignedAttributes,
            false,
            VerifyFindingCode::InvalidSignedAttributes,
        );
        checks.record(
            VerifyCheckKind::ContentDigest,
            false,
            VerifyFindingCode::DigestMismatch,
        );
        checks.record(
            VerifyCheckKind::SignatureValue,
            false,
            VerifyFindingCode::SignatureMismatch,
        );
        checks.record(
            VerifyCheckKind::SigningCertificateBinding,
            false,
            VerifyFindingCode::CertificateBindingMismatch,
        );
        checks.record(
            VerifyCheckKind::CertificatePath,
            false,
            VerifyFindingCode::CertificatePathInvalid,
        );
        checks.absent(VerifyCheckKind::SignatureTimestamp);
        return;
    };
    covered.extend(
        parsed
            .certificates
            .iter()
            .filter_map(|d| EmbeddedCert::from_der(d)),
    );
    verify_signer(ctx, anchors, checks, &parsed, spans_digest, covered);
}

/// Signer-level checks after the envelope parses: baseline attributes,
/// content digest, signature value, ESS binding, certificate path, and the
/// optional signature timestamp token.
#[allow(clippy::too_many_lines)]
fn verify_signer(
    ctx: &VerifyCtx<'_>,
    anchors: &[pkix_chain::TrustAnchor],
    checks: &mut Checks,
    parsed: &cms::ParsedCms,
    spans_digest: Option<Sha256Digest>,
    covered: &mut Vec<EmbeddedCert>,
) {
    let signer = &parsed.signer;
    let md = cms::check_baseline_attrs(signer).ok();
    checks.record(
        VerifyCheckKind::SignedAttributes,
        md.is_some(),
        VerifyFindingCode::InvalidSignedAttributes,
    );
    let digest_ok = matches!((md, spans_digest), (Some(a), Some(b)) if a == b);
    checks.record(
        VerifyCheckKind::ContentDigest,
        digest_ok,
        VerifyFindingCode::DigestMismatch,
    );
    let signer_idx = parsed.certificates.iter().position(|c| {
        let Ok((iss, ser)) = cms::issuer_and_serial(c) else {
            return false;
        };
        parsed
            .signer
            .signed_attrs
            .iter()
            .any(|a| cms::check_ess_binding(a, c, &iss, &ser).is_ok())
    });
    checks.record(
        VerifyCheckKind::SigningCertificateBinding,
        signer_idx.is_some(),
        VerifyFindingCode::CertificateBindingMismatch,
    );
    let Some(idx) = signer_idx else {
        checks.record(
            VerifyCheckKind::SignatureValue,
            false,
            VerifyFindingCode::SignatureMismatch,
        );
        checks.record(
            VerifyCheckKind::CertificatePath,
            false,
            VerifyFindingCode::CertificatePathInvalid,
        );
        checks.absent(VerifyCheckKind::SignatureTimestamp);
        return;
    };
    let cert_der = &parsed.certificates[idx];
    let alg = cms::cert_signature_algorithm(cert_der);
    let sig_ok = match alg {
        Ok(a) => {
            cms::sig_alg_permitted(a, &signer.signature_alg_oid)
                && cms::verify_signature_value(
                    a,
                    cert_der,
                    &cms::signed_attrs_signature_input(signer),
                    &signer.signature,
                )
                .is_ok()
        }
        Err(_) => false,
    };
    checks.record(
        VerifyCheckKind::SignatureValue,
        sig_ok,
        VerifyFindingCode::SignatureMismatch,
    );
    let ts_gen_time = verify_ts_token(ctx.clock_ms, signer, anchors, checks, covered);
    let at_unix = ts_gen_time.unwrap_or(ctx.clock_ms / 1000);
    let chain_ders: Vec<Vec<u8>> = std::iter::once(cert_der.clone())
        .chain(
            parsed
                .certificates
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != idx)
                .map(|(_, c)| c.clone()),
        )
        .collect();
    checks.record(
        VerifyCheckKind::CertificatePath,
        validate_chain(&chain_ders, anchors, at_unix).is_ok(),
        VerifyFindingCode::CertificatePathInvalid,
    );
}

/// Validate the optional `signatureTimeStampToken` unsigned attribute.
/// Present-but-malformed fails; absent is allowed. Returns the token genTime
/// (unix seconds) for applicable-time chain validation; a validated token's
/// TSA chain is recorded in `covered` for the DSS binding. The genTime is
/// bounded against the verify clock (`clock_ms`): a future-dated token past
/// the documented skew is rejected, never clamped.
fn verify_ts_token(
    clock_ms: u64,
    signer: &cms::ParsedSignerInfo,
    anchors: &[pkix_chain::TrustAnchor],
    checks: &mut Checks,
    covered: &mut Vec<EmbeddedCert>,
) -> Option<u64> {
    let mut token_der = None;
    for attr in &signer.unsigned_attrs {
        let Ok((oid, value)) = cms::parse_attribute(attr) else {
            checks.record(
                VerifyCheckKind::SignatureTimestamp,
                false,
                VerifyFindingCode::TimestampInvalid,
            );
            return None;
        };
        if oid == cms::OID_ATTR_TS_TOKEN.as_bytes() {
            if token_der.is_some() {
                checks.record(
                    VerifyCheckKind::SignatureTimestamp,
                    false,
                    VerifyFindingCode::TimestampInvalid,
                );
                return None;
            }
            token_der = Some(value.full.to_vec());
        }
    }
    let Some(token) = token_der else {
        checks.absent(VerifyCheckKind::SignatureTimestamp);
        return None;
    };
    let imprint = cms::sha256(&signer.signature);
    match tsp::validate_token_for_verify(&token, &imprint, anchors) {
        Ok((gen_time, tsa_chain_ders)) => {
            if gen_time_beyond_skew(gen_time, clock_ms) {
                checks.record(
                    VerifyCheckKind::SignatureTimestamp,
                    false,
                    VerifyFindingCode::TimestampInvalid,
                );
                return None;
            }
            checks.record(
                VerifyCheckKind::SignatureTimestamp,
                true,
                VerifyFindingCode::TimestampInvalid,
            );
            covered.extend(
                tsa_chain_ders
                    .iter()
                    .filter_map(|d| EmbeddedCert::from_der(d)),
            );
            Some(gen_time)
        }
        Err(_) => {
            checks.record(
                VerifyCheckKind::SignatureTimestamp,
                false,
                VerifyFindingCode::TimestampInvalid,
            );
            None
        }
    }
}

/// Verify one DocTimeStamp dictionary (§7.6/§7.7): ByteRange coverage and
/// the RFC 3161 token over the covered bytes. Only a FULLY accepted
/// DocTimeStamp records its TSA chain in `covered` for the DSS binding — a
/// rejected token leaves no trace in the binding set. Returns the token's
/// genTime (unix seconds) when every check passes; the caller feeds it to
/// DSS evidence freshness only when the ByteRange provably covers the final
/// /DSS revision (`dss_revision_end`). The genTime is bounded against the
/// verify clock (`clock_ms`): a future-dated token past the documented skew
/// is rejected, never clamped.
fn verify_doc_ts(
    bytes: &[u8],
    e: &SigEntry,
    anchors: &[pkix_chain::TrustAnchor],
    checks: &mut Checks,
    is_last: bool,
    covered: &mut Vec<EmbeddedCert>,
    clock_ms: u64,
) -> Option<u64> {
    let br_ok = check_byte_range(bytes, e);
    let covers_end = !is_last
        || e.byte_range
            .get(2..4)
            .and_then(|v| u64::checked_add(v[0], v[1]))
            .is_some_and(|end| {
                let mut tail =
                    &bytes[usize::try_from(end).unwrap_or(usize::MAX).min(bytes.len())..];
                while let [b'\r' | b'\n', rest @ ..] = tail {
                    tail = rest;
                }
                tail.is_empty()
            });
    let token = unpadded_cms(&e.contents).and_then(|der| {
        let imprint = pdf::hash_byte_range(bytes, e.byte_range).ok()?;
        tsp::validate_token_for_verify(der, &imprint, anchors).ok()
    });
    let future_dated = token
        .as_ref()
        .is_some_and(|(gen_time, _)| gen_time_beyond_skew(*gen_time, clock_ms));
    let ok = br_ok && covers_end && token.is_some() && !future_dated;
    checks.record(
        VerifyCheckKind::DocumentTimestamp,
        ok,
        VerifyFindingCode::DocumentTimestampInvalid,
    );
    if !ok {
        return None;
    }
    let (gen_time, tsa_chain_ders) = token?;
    covered.extend(
        tsa_chain_ders
            .iter()
            .filter_map(|d| EmbeddedCert::from_der(d)),
    );
    Some(gen_time)
}

/// Validate the DSS revision when the catalog carries `/DSS` (§7.5/§7.7):
/// global arrays only, and every present entry must cryptographically
/// validate — CRLs against an embedded/anchored issuer cert with a fresh
/// thisUpdate/nextUpdate window and no in-scope serial on its revoked list,
/// OCSP responses with signature, responder authorization, cert-serial
/// binding, freshness, and a `good` cert status. The material must also
/// speak about the document's covered CMS signer/TSA chains: every covered
/// certificate must appear in `/Certs` or be a trust anchor. A present DSS
/// with no arrays at all is evidence-free and fails. Present-but-invalid
/// evidence fails ValidationMaterial; it is never AbsentAllowed. A trailer
/// `/Root` that cannot be read as a catalog (e.g. a spec-invalid direct
/// dictionary) is present-but-unreadable, not absent: it classifies
/// Invalid so a `/DSS` hidden inside it cannot dodge the failed-evidence
/// classification.
fn verify_dss(
    doc: &Document,
    anchors: &[EmbeddedCert],
    covered: &[EmbeddedCert],
    at_unix: u64,
    max_stream_bytes: usize,
    checks: &mut Checks,
) {
    let catalog = match doc.catalog() {
        Ok(c) => c,
        Err(_) => {
            if doc.trailer.has(b"Root") {
                checks.record(
                    VerifyCheckKind::ValidationMaterial,
                    false,
                    VerifyFindingCode::ValidationMaterialInvalid,
                );
            } else {
                checks.absent(VerifyCheckKind::ValidationMaterial);
            }
            return;
        }
    };
    let Ok(dss_obj) = catalog.get(b"DSS") else {
        checks.absent(VerifyCheckKind::ValidationMaterial);
        return;
    };
    let dss = doc
        .dereference(dss_obj)
        .ok()
        .and_then(|(_, o)| o.as_dict().ok());
    let Some(dss) = dss else {
        checks.record(
            VerifyCheckKind::ValidationMaterial,
            false,
            VerifyFindingCode::ValidationMaterialInvalid,
        );
        return;
    };
    if dss.has(b"VRI") {
        checks.record(
            VerifyCheckKind::ValidationMaterial,
            false,
            VerifyFindingCode::ValidationMaterialInvalid,
        );
        return;
    }
    let ok = dss_material_valid(doc, dss, anchors, covered, at_unix, max_stream_bytes);
    checks.record(
        VerifyCheckKind::ValidationMaterial,
        ok,
        VerifyFindingCode::ValidationMaterialInvalid,
    );
}

fn dss_material_valid(
    doc: &Document,
    dss: &lopdf::Dictionary,
    anchors: &[EmbeddedCert],
    covered: &[EmbeddedCert],
    at_unix: u64,
    max_stream_bytes: usize,
) -> bool {
    // ONE shared decompression budget across every DSS entry in all three
    // arrays: all decoded vectors are retained, so N streams each expanding
    // to the per-stream cap would multiply memory by N. The cumulative
    // over-cap fails the material without decoding beyond the shared limit.
    let mut remaining = max_stream_bytes;
    let certs = dss_array(doc, dss, b"Certs", &mut remaining);
    let crls = dss_array(doc, dss, b"CRLs", &mut remaining);
    let ocsps = dss_array(doc, dss, b"OCSPs", &mut remaining);
    // A present DSS with all arrays absent is evidence-free: it must not
    // inflate a B-T document into B-LT.
    if matches!(certs, DssArray::Absent)
        && matches!(crls, DssArray::Absent)
        && matches!(ocsps, DssArray::Absent)
    {
        return false;
    }
    // /Certs first: CRL and OCSP issuer lookups draw from it. A
    // present-but-empty array breaks profile completeness.
    let embedded: Vec<EmbeddedCert> = match certs {
        DssArray::Absent => Vec::new(),
        DssArray::Malformed => return false,
        DssArray::Entries(entries) => {
            if entries.is_empty() {
                return false;
            }
            let mut v = Vec::with_capacity(entries.len());
            for e in &entries {
                let Some(c) = EmbeddedCert::from_der(e) else {
                    return false;
                };
                v.push(c);
            }
            v
        }
    };
    // Binding (§7.5 step 3): the validation set (embedded + anchors) must
    // include every certificate of the CMS signer/TSA chains this report
    // covers; unrelated /Certs must not authenticate the material.
    let bound = covered.iter().all(|c| {
        embedded
            .iter()
            .chain(anchors.iter())
            .any(|e| e.der == c.der)
    });
    if !bound {
        return false;
    }
    // Every CRL entry must be valid; collect the key-bound issuer certs the
    // valid CRLs authenticated under so the coverage rule below can match
    // them against each covered certificate's ACTUAL issuer (name+key).
    let crl_issuers: Vec<&EmbeddedCert> = match crls {
        DssArray::Absent => Vec::new(),
        DssArray::Malformed => return false,
        DssArray::Entries(entries) => {
            if entries.is_empty() {
                return false;
            }
            let mut v = Vec::with_capacity(entries.len());
            for e in &entries {
                let Some(issuer) = crl_entry_valid(e, &embedded, anchors, covered, at_unix) else {
                    return false;
                };
                v.push(issuer);
            }
            v
        }
    };
    // Every OCSP entry must be valid; collect the DERs of the target
    // certificates the valid responses bind to with a `good` status.
    let mut ocsp_targets: Vec<Vec<u8>> = Vec::new();
    match ocsps {
        DssArray::Absent => {}
        DssArray::Malformed => return false,
        DssArray::Entries(entries) => {
            if entries.is_empty() {
                return false;
            }
            for e in &entries {
                let Some(targets) = ocsp_entry_valid(e, &embedded, anchors, at_unix) else {
                    return false;
                };
                ocsp_targets.extend(targets);
            }
        }
    }
    // Revocation coverage (§7.5 steps 2-3): every covered NON-ANCHOR chain
    // certificate needs at least one valid evidence item speaking ABOUT it
    // — a CRL whose key-bound issuer is that certificate's ACTUAL issuer
    // (the covered cert's own signature verifies under the CRL-signing
    // key) or an OCSP SingleResponse bound to it with `cert_status` good.
    // Anchor certificates ride anchor trust and need no coverage. A
    // cert-only DSS, evidence about an irrelevant issuer, or evidence
    // authenticated by a same-subject/different-key shadow fails here —
    // never AbsentAllowed.
    let covered_ok = covered.iter().all(|c| {
        if anchors.iter().any(|a| a.der == c.der) {
            return true;
        }
        crl_issuers.iter().any(|i| issued_by(c, i)) || ocsp_targets.contains(&c.der)
    });
    if !covered_ok {
        return false;
    }
    true
}

/// A parsed certificate with its source DER (signature verification takes
/// the DER form).
pub(crate) struct EmbeddedCert {
    der: Vec<u8>,
    cert: x509_cert::Certificate,
}

impl EmbeddedCert {
    pub(crate) fn from_der(der_bytes: &[u8]) -> Option<Self> {
        use der::Decode;
        Some(Self {
            der: der_bytes.to_vec(),
            cert: x509_cert::Certificate::from_der(der_bytes).ok()?,
        })
    }
}

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

enum DssArray {
    Absent,
    Entries(Vec<Vec<u8>>),
    Malformed,
}

/// Extract the decoded stream contents of one DSS array. Filtered streams
/// (e.g. a FlateDecode-wrapped CRL) are decoded through the bounded
/// decompression path; a malformed filter, a failed decode, or an over-limit
/// expansion is Malformed, never a silent skip. `remaining` is the SHARED
/// decode budget across every DSS array: each entry decodes against what is
/// left (never the full per-document cap) and spends its decoded length, so
/// cumulative expansion past the cap fails instead of decoding further.
fn dss_array(
    doc: &Document,
    dss: &lopdf::Dictionary,
    key: &[u8],
    remaining: &mut usize,
) -> DssArray {
    let Ok(arr_obj) = dss.get(key) else {
        return DssArray::Absent;
    };
    let Some(arr) = doc
        .dereference(arr_obj)
        .ok()
        .and_then(|(_, o)| o.as_array().ok())
    else {
        return DssArray::Malformed;
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let Some(stream) = doc
            .dereference(item)
            .ok()
            .and_then(|(_, o)| o.as_stream().ok())
        else {
            return DssArray::Malformed;
        };
        let Ok(data) = stream.decompressed_content_with_limit(*remaining) else {
            return DssArray::Malformed;
        };
        // The decode cap guarantees data.len() <= *remaining.
        *remaining = remaining.saturating_sub(data.len());
        out.push(data);
    }
    DssArray::Entries(out)
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
fn crl_entry_valid<'a>(
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
const TS_GEN_TIME_MAX_SKEW_SECS: u64 = 300;

/// genTime ahead of the verify clock beyond the documented skew?
fn gen_time_beyond_skew(gen_time: u64, clock_ms: u64) -> bool {
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
    time_valid && has_eku && issued_by(responder, issuer)
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
            sha1::Sha1::digest(key).as_slice() == hash.as_bytes()
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
fn ocsp_entry_valid(
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

/// Total reference-chain traversal budget across every `/DSS` array in one
/// `dss_revision_end` evaluation. Chains are followed per array OCCURRENCE,
/// so N repetitions of one deep chain must not multiply work without bound:
/// past this many total hops the measurement fails closed.
const MAX_REFERENCE_WORK: usize = 16_384;

/// Follow a reference chain exactly as `Document::dereference` does at
/// evaluation time, recording every traversed object id (link and target
/// alike) into a set shared across all chains — repetitions of one chain
/// collapse to its unique objects, so the id set can never expand past the
/// document's object count no matter how often a chain appears in the DSS
/// arrays. `work` accumulates hops across every chain and fails closed past
/// [`MAX_REFERENCE_WORK`]. `None` on a dangling, cyclic, or over-limit
/// chain: coverage of the terminal object is then unprovable and the
/// caller fails closed. The per-chain hop bound mirrors lopdf's
/// dereference limit (128); a chain the evaluator would reject as
/// over-limit is unprovable here too.
fn collect_reference_chain(
    doc: &Document,
    id: lopdf::ObjectId,
    ids: &mut std::collections::BTreeSet<lopdf::ObjectId>,
    work: &mut usize,
) -> Option<()> {
    let mut current = id;
    for _ in 0..128 {
        *work = work.checked_add(1)?;
        if *work > MAX_REFERENCE_WORK {
            return None;
        }
        ids.insert(current);
        let obj = doc.objects.get(&current)?;
        let Ok(next) = obj.as_reference() else {
            return Some(());
        };
        current = next;
    }
    None
}

/// Byte offset the effective `/DSS` revision provably ends before: the
/// smallest xref-table offset beyond the newest DSS-related object (the
/// final catalog, the `/DSS` dictionary, and its `/Certs` `/OCSPs` `/CRLs`
/// array and stream objects), or the final `startxref` when no later object
/// exists. Objects of one revision precede that revision's xref, so a
/// DocTimeStamp whose ByteRange end reaches this offset covers every byte
/// of the revision the `/DSS` lives in; an earlier end validates evidence
/// no timestamp attests. `None` when coverage is unprovable (no `/DSS`,
/// compressed or missing xref entries, unparsable catalog): the
/// archival-time selection must then fall back to the verification clock so
/// stale evidence fails instead of laundering through an unrelated old
/// timestamp.
///
/// The measured id set must mirror the EVALUATION dereference paths exactly:
/// `Document::dereference` follows reference CHAINS, so every traversed
/// object is collected — a bare-reference link collected without its target
/// would let terminal evidence sit past the measured offsets, planted in a
/// revision no DocTimeStamp attests (probe_c regression).
fn dss_revision_end(doc: &Document, bytes: &[u8]) -> Option<u64> {
    let catalog = doc.catalog().ok()?;
    let dss_obj = catalog.get(b"DSS").ok()?;
    let mut ids: std::collections::BTreeSet<lopdf::ObjectId> = std::collections::BTreeSet::new();
    let mut work = 0usize;
    if let Ok(root) = doc.trailer.get(b"Root").and_then(Object::as_reference) {
        collect_reference_chain(doc, root, &mut ids, &mut work)?;
    }
    if let Object::Reference(id) = dss_obj {
        collect_reference_chain(doc, *id, &mut ids, &mut work)?;
    }
    let dss = doc
        .dereference(dss_obj)
        .ok()
        .and_then(|(_, o)| o.as_dict().ok())?;
    for key in [b"Certs".as_slice(), b"OCSPs".as_slice(), b"CRLs".as_slice()] {
        let Ok(arr_obj) = dss.get(key) else {
            continue;
        };
        if let Object::Reference(id) = arr_obj {
            collect_reference_chain(doc, *id, &mut ids, &mut work)?;
        }
        let Some(arr) = doc
            .dereference(arr_obj)
            .ok()
            .and_then(|(_, o)| o.as_array().ok())
        else {
            continue;
        };
        for item in arr {
            if let Object::Reference(id) = item {
                collect_reference_chain(doc, *id, &mut ids, &mut work)?;
            }
        }
    }
    let mut newest = None;
    for (num, generation) in ids {
        match doc.reference_table.get(num) {
            Some(lopdf::xref::XrefEntry::Normal {
                offset,
                generation: g,
            }) if *g == generation => {
                let offset = u64::from(*offset);
                newest = Some(newest.map_or(offset, |n: u64| n.max(offset)));
            }
            _ => return None, // compressed or missing: coverage unprovable
        }
    }
    let newest = newest?;
    doc.reference_table
        .entries
        .values()
        .filter_map(|e| match e {
            lopdf::xref::XrefEntry::Normal { offset, .. } => Some(u64::from(*offset)),
            _ => None,
        })
        .filter(|o| *o > newest)
        .min()
        .or_else(|| pdf::last_startxref(bytes).ok())
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
fn classify(checks: &Checks, valid: bool, covering_dts_valid: bool) -> Option<PadesProfile> {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use const_oid::AssociatedOid;
    use der::{Decode, Encode};
    use lopdf::{Object, Stream};

    use super::*;

    /// 2026-07-30T08:00:00Z — the applicable verification time.
    const AT_UNIX: u64 = 1_785_398_400;

    struct TestCa {
        cert_der: Vec<u8>,
        cert: x509_cert::Certificate,
        key: p256::ecdsa::SigningKey,
        rcgen_params: rcgen::CertificateParams,
        rcgen_key: rcgen::KeyPair,
    }

    fn test_ca(cn: &str) -> TestCa {
        ca_with_kus(
            cn,
            vec![
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::CrlSign,
            ],
        )
    }

    /// A self-signed CA-shaped identity with caller-chosen KeyUsage purposes.
    fn ca_with_kus(cn: &str, kus: Vec<rcgen::KeyUsagePurpose>) -> TestCa {
        use p256::pkcs8::DecodePrivateKey;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = kus;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        TestCa {
            cert_der,
            cert,
            key,
            rcgen_params: params,
            rcgen_key: key_pair,
        }
    }

    /// A leaf certificate issued by `ca` (fresh key pair, DER only).
    fn leaf_under(ca: &TestCa, cn: &str) -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let issuer = rcgen::Issuer::from_params(&ca.rcgen_params, &ca.rcgen_key);
        params.signed_by(&key_pair, &issuer).unwrap().der().to_vec()
    }

    /// A leaf under `ca` with a caller-chosen serial number.
    fn leaf_with_serial(ca: &TestCa, cn: &str, serial: u64) -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.serial_number = Some(rcgen::SerialNumber::from(serial));
        let issuer = rcgen::Issuer::from_params(&ca.rcgen_params, &ca.rcgen_key);
        params.signed_by(&key_pair, &issuer).unwrap().der().to_vec()
    }

    /// A leaf under `ca` with caller-chosen KeyUsage purposes (empty = no
    /// KeyUsage extension).
    fn leaf_with_ku(ca: &TestCa, cn: &str, kus: Vec<rcgen::KeyUsagePurpose>) -> Vec<u8> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = kus;
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        let issuer = rcgen::Issuer::from_params(&ca.rcgen_params, &ca.rcgen_key);
        params.signed_by(&key_pair, &issuer).unwrap().der().to_vec()
    }

    /// An OCSP delegate certificate issued by `issuer`: digitalSignature KU,
    /// id-kp-OCSPSigning EKU, caller-chosen validity window.
    fn ocsp_delegate(
        issuer: &TestCa,
        cn: &str,
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> TestCa {
        use p256::pkcs8::DecodePrivateKey;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn.to_string());
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let eku = cms::tlv(
            0x30,
            &cms::oid_tlv(&der::asn1::ObjectIdentifier::new_unwrap(
                "1.3.6.1.5.5.7.3.9",
            )),
        );
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 37],
                eku,
            ));
        let issuer_rc = rcgen::Issuer::from_params(&issuer.rcgen_params, &issuer.rcgen_key);
        let cert = params.signed_by(&key_pair, &issuer_rc).unwrap();
        let cert_der = cert.der().to_vec();
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        TestCa {
            cert_der,
            cert,
            key,
            rcgen_params: params,
            rcgen_key: key_pair,
        }
    }

    /// An intermediate CA issued by `parent` (fresh key pair).
    fn child_ca(parent: &TestCa, cn: &str) -> TestCa {
        use p256::pkcs8::DecodePrivateKey;
        let key_pair = rcgen::KeyPair::generate().unwrap();
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
        let issuer = rcgen::Issuer::from_params(&parent.rcgen_params, &parent.rcgen_key);
        let cert = params.signed_by(&key_pair, &issuer).unwrap();
        let cert_der = cert.der().to_vec();
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        TestCa {
            cert_der,
            cert,
            key,
            rcgen_params: params,
            rcgen_key: key_pair,
        }
    }

    fn sign_p256(key: &p256::ecdsa::SigningKey, data: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(data);
        let sig: p256::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        sig.to_der().as_bytes().to_vec()
    }

    fn ecdsa_alg() -> spki::AlgorithmIdentifierOwned {
        spki::AlgorithmIdentifierOwned {
            oid: cms::OID_ECDSA_SHA256,
            parameters: None,
        }
    }

    fn gt(secs: u64) -> der::asn1::GeneralizedTime {
        der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(secs))
            .unwrap()
    }

    fn x509_time(secs: u64) -> x509_cert::time::Time {
        x509_cert::time::Time::GeneralTime(gt(secs))
    }

    fn build_crl(
        ca: &TestCa,
        this: u64,
        next: Option<u64>,
        sign_with: Option<&p256::ecdsa::SigningKey>,
        revoked: Vec<x509_cert::serial_number::SerialNumber>,
    ) -> Vec<u8> {
        build_crl_ext(ca, this, next, sign_with, revoked, Vec::new())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_crl_ext(
        ca: &TestCa,
        this: u64,
        next: Option<u64>,
        sign_with: Option<&p256::ecdsa::SigningKey>,
        revoked: Vec<x509_cert::serial_number::SerialNumber>,
        crl_extensions: Vec<x509_cert::ext::Extension>,
    ) -> Vec<u8> {
        let alg = ecdsa_alg();
        let revoked_certificates = if revoked.is_empty() {
            None
        } else {
            Some(
                revoked
                    .into_iter()
                    .map(|serial_number| x509_cert::crl::RevokedCert {
                        serial_number,
                        revocation_date: x509_time(this),
                        crl_entry_extensions: None,
                    })
                    .collect(),
            )
        };
        let tbs = x509_cert::crl::TbsCertList {
            version: x509_cert::Version::V2,
            signature: alg.clone(),
            issuer: ca.cert.tbs_certificate.subject.clone(),
            this_update: x509_time(this),
            next_update: next.map(x509_time),
            revoked_certificates,
            crl_extensions: if crl_extensions.is_empty() {
                None
            } else {
                Some(crl_extensions)
            },
        };
        let tbs_der = tbs.to_der().unwrap();
        let sig = sign_p256(sign_with.unwrap_or(&ca.key), &tbs_der);
        x509_cert::crl::CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: alg,
            signature: der::asn1::BitString::from_bytes(&sig).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    fn build_ocsp(
        ca: &TestCa,
        serial: x509_cert::serial_number::SerialNumber,
        this: u64,
        next: Option<u64>,
        status: x509_ocsp::CertStatus,
    ) -> Vec<u8> {
        build_ocsp_full(ca, serial, this, next, status, this, ca, false)
    }

    /// Full OCSP fixture: CertID hashes against `id_ca` (the target's
    /// issuer), response signed by `responder` with responderID =
    /// responder's subject, `produced_at` as given, and the responder
    /// certificate embedded when `embed_responder` (the delegate shape).
    #[allow(clippy::too_many_arguments)]
    fn build_ocsp_full(
        id_ca: &TestCa,
        serial: x509_cert::serial_number::SerialNumber,
        this: u64,
        next: Option<u64>,
        status: x509_ocsp::CertStatus,
        produced_at: u64,
        responder: &TestCa,
        embed_responder: bool,
    ) -> Vec<u8> {
        use sha1::Digest;
        let subject_der = id_ca.cert.tbs_certificate.subject.to_der().unwrap();
        let key_bytes = id_ca
            .cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let cert_id = x509_ocsp::CertId {
            hash_algorithm: spki::AlgorithmIdentifierOwned {
                oid: der::asn1::ObjectIdentifier::new_unwrap("1.3.14.3.2.26"),
                parameters: Some(der::asn1::Null.into()),
            },
            issuer_name_hash: der::asn1::OctetString::new(
                sha1::Sha1::digest(&subject_der).to_vec(),
            )
            .unwrap(),
            issuer_key_hash: der::asn1::OctetString::new(sha1::Sha1::digest(key_bytes).to_vec())
                .unwrap(),
            serial_number: serial,
        };
        let single = x509_ocsp::SingleResponse {
            cert_id,
            cert_status: status,
            this_update: x509_ocsp::OcspGeneralizedTime(gt(this)),
            next_update: next.map(|n| x509_ocsp::OcspGeneralizedTime(gt(n))),
            single_extensions: None,
        };
        let data = x509_ocsp::ResponseData {
            version: Default::default(),
            responder_id: x509_ocsp::ResponderId::ByName(
                responder.cert.tbs_certificate.subject.clone(),
            ),
            produced_at: x509_ocsp::OcspGeneralizedTime(gt(produced_at)),
            responses: vec![single],
            response_extensions: None,
        };
        let tbs_der = data.to_der().unwrap();
        let sig = sign_p256(&responder.key, &tbs_der);
        let basic = x509_ocsp::BasicOcspResponse {
            tbs_response_data: data,
            signature_algorithm: ecdsa_alg(),
            signature: der::asn1::BitString::from_bytes(&sig).unwrap(),
            certs: if embed_responder {
                Some(vec![responder.cert.clone()])
            } else {
                None
            },
        };
        let basic_der = basic.to_der().unwrap();
        x509_ocsp::OcspResponse {
            response_status: x509_ocsp::OcspResponseStatus::Successful,
            response_bytes: Some(x509_ocsp::ResponseBytes {
                response_type: x509_ocsp::BasicOcspResponse::OID,
                response: der::asn1::OctetString::new(basic_der).unwrap(),
            }),
        }
        .to_der()
        .unwrap()
    }

    /// In-memory document carrying a catalog `/DSS` with the given global
    /// arrays (empty arrays are omitted).
    fn dss_doc(certs: &[Vec<u8>], crls: &[Vec<u8>], ocsps: &[Vec<u8>]) -> Document {
        let mut doc = Document::with_version("1.4");
        let mut dss = lopdf::Dictionary::new();
        dss.set("Type", Object::Name(b"DSS".to_vec()));
        for (key, items) in [("Certs", certs), ("CRLs", crls), ("OCSPs", ocsps)] {
            if items.is_empty() {
                continue;
            }
            let refs: Vec<Object> = items
                .iter()
                .map(|d| {
                    let s = Stream::new(lopdf::Dictionary::new(), d.clone());
                    Object::Reference(doc.add_object(Object::Stream(s)))
                })
                .collect();
            dss.set(key, Object::Array(refs));
        }
        let dss_id = doc.add_object(Object::Dictionary(dss));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("DSS", Object::Reference(dss_id));
        let cat_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(cat_id));
        doc
    }

    fn dss_check(doc: &Document, covered: &[EmbeddedCert]) -> Checks {
        let mut checks = Checks::new();
        verify_dss(doc, &[], covered, AT_UNIX, usize::MAX, &mut checks);
        checks
    }

    fn covered_of(ders: &[&[u8]]) -> Vec<EmbeddedCert> {
        ders.iter()
            .map(|d| EmbeddedCert::from_der(d).unwrap())
            .collect()
    }

    fn dss_finding(checks: &Checks) -> (VerifyCheckStatus, Option<VerifyFindingCode>) {
        let c = checks
            .list
            .iter()
            .find(|c| c.kind == VerifyCheckKind::ValidationMaterial)
            .unwrap();
        (c.status, c.finding)
    }

    fn assert_material_fails(checks: &Checks) {
        assert_eq!(
            dss_finding(checks),
            (
                VerifyCheckStatus::Fail,
                Some(VerifyFindingCode::ValidationMaterialInvalid)
            )
        );
    }

    #[test]
    fn dss_valid_crl_and_ocsp_pass() {
        let ca = test_ca("dss-ca");
        let crl = build_crl(&ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let ocsp = build_ocsp(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_empty_dss_is_evidence_free_and_fails() {
        // /DSS present with /Certs, /CRLs, /OCSPs all absent must not
        // inflate a B-T document into B-LT.
        let doc = dss_doc(&[], &[], &[]);
        let checks = dss_check(&doc, &[]);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_unrelated_certs_fail_binding() {
        // Authenticated material about unrelated self-signed /Certs must not
        // authenticate the document's covered signer chain.
        let dss_ca = test_ca("dss-ca");
        let signer = test_ca("signer-ca");
        let crl = build_crl(&dss_ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc(std::slice::from_ref(&dss_ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&signer.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_anchor_only_binding_passes() {
        // A covered certificate that is a trust anchor satisfies the binding
        // without appearing in /Certs.
        let ca = test_ca("dss-ca");
        let crl = build_crl(&ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let anchor = EmbeddedCert::from_der(&ca.cert_der).unwrap();
        let covered = covered_of(&[&ca.cert_der]);
        let mut checks = Checks::new();
        verify_dss(
            &doc,
            std::slice::from_ref(&anchor),
            &covered,
            AT_UNIX,
            usize::MAX,
            &mut checks,
        );
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_crl_bad_signature_fails_validation_material() {
        let ca = test_ca("dss-ca");
        let other = test_ca("dss-other");
        let crl = build_crl(
            &ca,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            Some(&other.key),
            vec![],
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_crl_stale_next_update_fails_never_absent() {
        let ca = test_ca("dss-ca");
        let crl = build_crl(&ca, AT_UNIX - 7200, Some(AT_UNIX - 60), None, vec![]);
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_crl_listing_in_scope_serial_fails() {
        // A covered leaf revoked by its CA's CRL: the evidence asserts a
        // revocation and can never support validity.
        let ca = test_ca("dss-ca");
        let leaf_der = leaf_under(&ca, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let crl = build_crl(
            &ca,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            None,
            vec![leaf.tbs_certificate.serial_number],
        );
        let doc = dss_doc(&[ca.cert_der.clone(), leaf_der.clone()], &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_crl_listing_out_of_scope_serial_passes() {
        // A revoked serial that matches no validation-set certificate does
        // not invalidate the evidence.
        let ca = test_ca("dss-ca");
        let stranger = x509_cert::serial_number::SerialNumber::new(&[0x11, 0x22, 0x33]).unwrap();
        let crl = build_crl(
            &ca,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            None,
            vec![stranger],
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_ocsp_unbound_serial_fails() {
        let ca = test_ca("dss-ca");
        let serial = x509_cert::serial_number::SerialNumber::new(&[0x7f, 0x7f, 0x01]).unwrap();
        let ocsp = build_ocsp(
            &ca,
            serial,
            AT_UNIX - 60,
            None,
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_stale_next_update_fails() {
        let ca = test_ca("dss-ca");
        let ocsp = build_ocsp(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 7200,
            Some(AT_UNIX - 60),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_revoked_status_fails() {
        let ca = test_ca("dss-ca");
        let ocsp = build_ocsp(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::revoked(x509_ocsp::RevokedInfo {
                revocation_time: x509_ocsp::OcspGeneralizedTime(gt(AT_UNIX - 120)),
                revocation_reason: None,
            }),
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_unknown_status_fails_closed() {
        // The blueprint leaves `unknown` unpinned (§7.5/§7.7): fail closed.
        let ca = test_ca("dss-ca");
        let ocsp = build_ocsp(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::unknown(),
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_cert_only_fails_revocation_coverage() {
        // A /Certs-only DSS (chain DERs present, /CRLs and /OCSPs absent)
        // carries zero revocation material and must not inflate B-LT.
        let ca = test_ca("dss-ca");
        let leaf_der = leaf_under(&ca, "leaf");
        let doc = dss_doc(&[ca.cert_der.clone(), leaf_der.clone()], &[], &[]);
        let covered = covered_of(&[&ca.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_irrelevant_issuer_evidence_fails_coverage() {
        // Authentic-but-irrelevant evidence: an attacker-embedded
        // self-signed "issuer" with its own fresh CRL/OCSP says nothing
        // about the covered chain.
        let real_ca = test_ca("real-ca");
        let leaf_der = leaf_under(&real_ca, "signer");
        let evil = test_ca("evil-ca");
        let evil_crl = build_crl(&evil, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let evil_ocsp = build_ocsp(
            &evil,
            evil.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(
            &[real_ca.cert_der.clone(), leaf_der.clone(), evil.cert_der],
            &[evil_crl],
            &[evil_ocsp],
        );
        let covered = covered_of(&[&real_ca.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_crl_covers_chain_passes() {
        // One CRL issued by the CA covers both the CA (self-issued) and the
        // leaf it issued.
        let ca = test_ca("dss-ca");
        let leaf_der = leaf_under(&ca, "leaf");
        let crl = build_crl(&ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc(&[ca.cert_der.clone(), leaf_der.clone()], &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_ocsp_covers_chain_passes() {
        // OCSP responses bound to each covered cert with `good` status.
        let ca = test_ca("dss-ca");
        let leaf_der = leaf_under(&ca, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let ocsp_ca = build_ocsp(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let ocsp_leaf = build_ocsp(
            &ca,
            leaf.tbs_certificate.serial_number,
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(
            &[ca.cert_der.clone(), leaf_der.clone()],
            &[],
            &[ocsp_ca, ocsp_leaf],
        );
        let covered = covered_of(&[&ca.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_mixed_crl_ocsp_coverage_passes() {
        // Three-tier chain where each evidence kind proves its own path:
        // the root and the intermediate it issued ride the root's CRL (the
        // CRL cannot cover the leaf — the leaf's ACTUAL issuer is the
        // intermediate, not the CRL signer), and the leaf rides an OCSP
        // response bound to it via the intermediate. Dropping either entry
        // must fail coverage.
        let root = test_ca("root");
        let inter = child_ca(&root, "intermediate");
        let leaf_der = leaf_under(&inter, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let crl = build_crl(&root, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let ocsp_leaf = build_ocsp(
            &inter,
            leaf.tbs_certificate.serial_number,
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(
            &[
                root.cert_der.clone(),
                inter.cert_der.clone(),
                leaf_der.clone(),
            ],
            &[crl],
            &[ocsp_leaf],
        );
        let covered = covered_of(&[&root.cert_der, &inter.cert_der, &leaf_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_crl_same_dn_fake_issuer_rejected() {
        // Same-subject fake-issuer shadowing on the CRL path: a real
        // covered leaf issued by anchor A; /Certs orders [leaf, F] where F
        // is attacker self-signed with subject DN == A's DN. A fresh EMPTY
        // CRL signed by F (issuer = A's DN) must fail ValidationMaterial —
        // never pass, never AbsentAllowed.
        let anchor = test_ca("issuer");
        let leaf_der = leaf_under(&anchor, "leaf");
        let fake = test_ca("issuer");
        let crl = build_crl(&fake, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc(&[leaf_der.clone(), fake.cert_der], &[crl], &[]);
        let anchor_cert = EmbeddedCert::from_der(&anchor.cert_der).unwrap();
        let covered = covered_of(&[&leaf_der]);
        let mut checks = Checks::new();
        verify_dss(
            &doc,
            std::slice::from_ref(&anchor_cert),
            &covered,
            AT_UNIX,
            usize::MAX,
            &mut checks,
        );
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_same_dn_fake_issuer_rejected() {
        // Same shadowing on the OCSP path: a `good` SingleResponse for the
        // real leaf's serial whose CertID issuer name/key hashes are
        // computed against F and whose response is signed by F must fail
        // ValidationMaterial.
        let anchor = test_ca("issuer");
        let leaf_der = leaf_under(&anchor, "leaf");
        let leaf = x509_cert::Certificate::from_der(&leaf_der).unwrap();
        let fake = test_ca("issuer");
        let ocsp = build_ocsp(
            &fake,
            leaf.tbs_certificate.serial_number,
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(&[leaf_der.clone(), fake.cert_der], &[], &[ocsp]);
        let anchor_cert = EmbeddedCert::from_der(&anchor.cert_der).unwrap();
        let covered = covered_of(&[&leaf_der]);
        let mut checks = Checks::new();
        verify_dss(
            &doc,
            std::slice::from_ref(&anchor_cert),
            &covered,
            AT_UNIX,
            usize::MAX,
            &mut checks,
        );
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_anchor_exempt_from_coverage_passes() {
        // Anchor certificates ride anchor trust: the covered anchor needs
        // no evidence of its own; the non-anchor intermediate is covered by
        // an OCSP response bound to it.
        let anchor_ca = test_ca("anchor-ca");
        let inter_der = leaf_under(&anchor_ca, "intermediate");
        let inter = x509_cert::Certificate::from_der(&inter_der).unwrap();
        let ocsp_inter = build_ocsp(
            &anchor_ca,
            inter.tbs_certificate.serial_number,
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(
            &[anchor_ca.cert_der.clone(), inter_der.clone()],
            &[],
            &[ocsp_inter],
        );
        let anchor = EmbeddedCert::from_der(&anchor_ca.cert_der).unwrap();
        let covered = covered_of(&[&anchor_ca.cert_der, &inter_der]);
        let mut checks = Checks::new();
        verify_dss(
            &doc,
            std::slice::from_ref(&anchor),
            &covered,
            AT_UNIX,
            usize::MAX,
            &mut checks,
        );
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_ocsp_target_binds_serial_and_issuer_together() {
        // Two covered-set leaves share a serial under DIFFERENT issuers. The
        // OCSP response (issued by ca2) must bind to leaf2 even though leaf1
        // sorts first in the embedded set: serial alone is not identity.
        let ca1 = test_ca("ca-one");
        let ca2 = test_ca("ca-two");
        let leaf1_der = leaf_with_serial(&ca1, "leaf-one", 0x5EED);
        let leaf2_der = leaf_with_serial(&ca2, "leaf-two", 0x5EED);
        let leaf2 = x509_cert::Certificate::from_der(&leaf2_der).unwrap();
        let ocsp = build_ocsp(
            &ca2,
            leaf2.tbs_certificate.serial_number,
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
        );
        let doc = dss_doc(&[leaf1_der, leaf2_der.clone(), ca2.cert_der], &[], &[ocsp]);
        let covered = covered_of(&[&leaf2_der]);
        let checks = dss_check(&doc, &covered);
        assert!(
            checks.passed(VerifyCheckKind::ValidationMaterial),
            "binding must walk past the serial-matching wrong-issuer leaf"
        );
    }

    #[test]
    fn dss_freshness_uses_archival_applicable_time() {
        // A CRL fresh at the archival (DocTimeStamp) time but expired by the
        // verification clock is valid evidence for an archived document: the
        // DocTimeStamp covers the DSS revision and attests it as of genTime.
        let ca = test_ca("dss-ca");
        let archival = AT_UNIX - 86_400;
        let crl = build_crl(&ca, archival - 3600, Some(archival + 3600), None, vec![]);
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let mut checks = Checks::new();
        verify_dss(&doc, &[], &covered, archival, usize::MAX, &mut checks);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
        // The same material judged at the verification clock is stale.
        let checks_now = dss_check(&doc, &covered);
        assert_material_fails(&checks_now);
    }

    #[test]
    fn dss_direct_dict_root_classifies_invalid() {
        // lopdf catalog() errs on a spec-invalid direct-dictionary trailer
        // /Root; a /DSS hidden inside it must classify Invalid, never
        // Absent.
        let mut doc = Document::with_version("1.4");
        let mut dss = lopdf::Dictionary::new();
        dss.set("Type", Object::Name(b"DSS".to_vec()));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("DSS", Object::Dictionary(dss));
        doc.trailer.set("Root", Object::Dictionary(catalog));
        let checks = dss_check(&doc, &[]);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_no_trailer_root_stays_absent() {
        // A genuinely DSS-free document (no trailer /Root at all) keeps the
        // AbsentAllowed classification.
        let doc = Document::with_version("1.4");
        let checks = dss_check(&doc, &[]);
        assert_eq!(
            dss_finding(&checks),
            (VerifyCheckStatus::AbsentAllowed, None)
        );
    }

    // --- botfix3a gates: signer-leaf KU, CRL scope, OCSP delegate/producedAt,
    // --- tsp content-type, covered-on-valid-only ------------------------------

    fn anchors_of(ca: &TestCa) -> Vec<pkix_chain::TrustAnchor> {
        vec![pkix_chain::TrustAnchor::from_cert(ca.cert.clone())]
    }

    #[test]
    fn signer_leaf_key_encipherment_only_fails_certificate_path() {
        let ca = test_ca("ku-ca");
        let leaf = leaf_with_ku(
            &ca,
            "ku-leaf",
            vec![rcgen::KeyUsagePurpose::KeyEncipherment],
        );
        assert!(
            validate_chain(&[leaf], &anchors_of(&ca), AT_UNIX).is_err(),
            "a keyEncipherment-only leaf must not pass as a signing identity"
        );
    }

    #[test]
    fn signer_leaf_digital_signature_or_absent_ku_passes() {
        let ca = test_ca("ku-ca");
        let ds = leaf_with_ku(
            &ca,
            "ds-leaf",
            vec![rcgen::KeyUsagePurpose::DigitalSignature],
        );
        assert!(validate_chain(&[ds], &anchors_of(&ca), AT_UNIX).is_ok());
        let cc = leaf_with_ku(
            &ca,
            "cc-leaf",
            vec![rcgen::KeyUsagePurpose::ContentCommitment],
        );
        assert!(validate_chain(&[cc], &anchors_of(&ca), AT_UNIX).is_ok());
        // No KeyUsage extension at all: RFC 5280-unconstrained, permitted.
        let bare = leaf_with_ku(&ca, "bare-leaf", Vec::new());
        assert!(validate_chain(&[bare], &anchors_of(&ca), AT_UNIX).is_ok());
    }

    fn crl_ext(oid: &str, value_der: Vec<u8>) -> x509_cert::ext::Extension {
        x509_cert::ext::Extension {
            extn_id: der::asn1::ObjectIdentifier::new_unwrap(oid),
            critical: false,
            extn_value: der::asn1::OctetString::new(value_der).unwrap(),
        }
    }

    #[test]
    fn dss_delta_crl_is_not_revocation_evidence() {
        // deltaCRLIndicator (2.5.29.46): changes since a base, fail-closed.
        let ca = test_ca("dss-ca");
        let delta_ext = crl_ext(
            "2.5.29.46",
            der::asn1::Int::new(&[1]).unwrap().to_der().unwrap(),
        );
        let crl = build_crl_ext(
            &ca,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            None,
            vec![],
            vec![delta_ext],
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_idp_scoped_crl_is_not_revocation_evidence() {
        // IssuingDistributionPoint (2.5.29.28): subset coverage, fail-closed.
        let ca = test_ca("dss-ca");
        let idp_ext = crl_ext("2.5.29.28", vec![0x30, 0x00]);
        let crl = build_crl_ext(
            &ca,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            None,
            vec![],
            vec![idp_ext],
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_future_produced_at_fails() {
        // producedAt one day beyond the applicable time: not plausible
        // evidence (skew tolerance is 300s).
        let ca = test_ca("dss-ca");
        let ocsp = build_ocsp_full(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
            AT_UNIX + 86_400,
            &ca,
            false,
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
        // The same response produced AT the applicable time passes.
        let ok = build_ocsp_full(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
            AT_UNIX,
            &ca,
            false,
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ok]);
        let checks = dss_check(&doc, &covered_of(&[&ca.cert_der]));
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn dss_ocsp_expired_delegate_response_fails() {
        // Delegate cert expired before the applicable time: its `good`
        // response authorizes nothing.
        let ca = test_ca("dss-ca");
        let delegate = ocsp_delegate(&ca, "ocsp-delegate", (2020, 1, 1), (2021, 1, 1));
        let ocsp = build_ocsp_full(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
            AT_UNIX - 60,
            &delegate,
            true,
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn dss_ocsp_time_valid_delegate_passes() {
        let ca = test_ca("dss-ca");
        let delegate = ocsp_delegate(&ca, "ocsp-delegate", (2020, 1, 1), (2030, 1, 1));
        let ocsp = build_ocsp_full(
            &ca,
            ca.cert.tbs_certificate.serial_number.clone(),
            AT_UNIX - 60,
            Some(AT_UNIX + 3600),
            x509_ocsp::CertStatus::good(),
            AT_UNIX - 60,
            &delegate,
            true,
        );
        let doc = dss_doc(std::slice::from_ref(&ca.cert_der), &[], &[ocsp]);
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert!(checks.passed(VerifyCheckKind::ValidationMaterial));
    }

    #[test]
    fn tsp_token_without_content_type_attr_is_rejected() {
        // RFC 3161 §2.4.2: signedAttrs must carry content-type id-ct-TSTInfo.
        let tsa = tsa_ca();
        let imprint = [9u8; 32];
        let anchors = anchors_of(&tsa);
        let missing = mint_token_shaped(&tsa, &imprint, AT_UNIX, false);
        assert!(
            tsp::validate_token_for_verify(&missing, &imprint, &anchors).is_err(),
            "a token without the content-type attribute must fail"
        );
        let complete = mint_token_shaped(&tsa, &imprint, AT_UNIX, true);
        assert!(tsp::validate_token_for_verify(&complete, &imprint, &anchors).is_ok());
    }

    #[test]
    fn tsp_v2_token_is_rejected_on_verify_path() {
        // TSTInfo version is enforced on BOTH tsp paths: a v2 token must be
        // rejected by validate_token_for_verify, not only at seal time.
        let tsa = tsa_ca();
        let imprint = [9u8; 32];
        let anchors = anchors_of(&tsa);
        let mut token = mint_token(&tsa, &imprint, AT_UNIX);
        // The TSTInfo body opens `INTEGER 1` (version) immediately followed
        // by the policy OID tag — a byte pattern unique to the eContent.
        let marker = [0x02, 0x01, 0x01, 0x06];
        let pos = token
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("TSTInfo version marker present");
        token[pos + 2] = 0x02; // version := v2
        assert!(
            tsp::validate_token_for_verify(&token, &imprint, &anchors).is_err(),
            "a non-v1 TSTInfo must fail the verify path"
        );
    }

    #[test]
    fn tsp_digest_algs_surface_checked_on_both_paths() {
        // The SignedData digestAlgorithms SET is policy surface: an extra
        // weak entry must fail the verify path AND the response path, not
        // just the CAdES envelope gate.
        let tsa = tsa_ca();
        let imprint = [9u8; 32];
        let nonce = [7u8; 16];
        let anchors = anchors_of(&tsa);
        let wrap_granted = |token: &[u8]| {
            let mut body = cms::tlv(0x30, &cms::tlv(0x02, &[0]));
            body.extend_from_slice(token);
            cms::tlv(0x30, &body)
        };
        let weak = mint_token_custom(&tsa, &imprint, AT_UNIX, true, Some(nonce), true);
        assert!(
            tsp::validate_token_for_verify(&weak, &imprint, &anchors).is_err(),
            "extra weak digest alg must fail the verify path"
        );
        assert!(
            tsp::validate_response(&wrap_granted(&weak), &imprint, &nonce, None, &anchors).is_err(),
            "extra weak digest alg must fail the response path"
        );
        let clean = mint_token_custom(&tsa, &imprint, AT_UNIX, true, Some(nonce), false);
        assert!(tsp::validate_token_for_verify(&clean, &imprint, &anchors).is_ok());
        assert!(
            tsp::validate_response(&wrap_granted(&clean), &imprint, &nonce, None, &anchors).is_ok()
        );
    }

    #[test]
    fn future_dated_ts_token_is_rejected_within_skew_passes() {
        // genTime ahead of the verify clock past the documented skew anchors
        // the applicable time in the future: rejected, never clamped.
        let signer = test_ca("skew-signer");
        let tsa = tsa_ca();
        let input = base_input();
        let anchors = vec![signer.cert_der.clone(), tsa.cert_der.clone()];
        let future = append_sig_revision(
            &input,
            &signer,
            "skew-a",
            Some(&tsa),
            AT_UNIX + TS_GEN_TIME_MAX_SKEW_SECS + 1,
        );
        let engine = verify_engine(anchors, AT_UNIX);
        let report = engine.verify_sealed_pdf(&future).unwrap();
        assert!(!report.valid, "future-dated token must fail verification");
        let ts = report
            .checks
            .iter()
            .find(|c| c.kind == VerifyCheckKind::SignatureTimestamp)
            .unwrap();
        assert_eq!(
            (ts.status, ts.finding),
            (
                VerifyCheckStatus::Fail,
                Some(VerifyFindingCode::TimestampInvalid)
            )
        );
        // Within skew: TSA/verifier clocks are not assumed synchronized.
        let near = append_sig_revision(
            &input,
            &signer,
            "skew-b",
            Some(&tsa),
            AT_UNIX + TS_GEN_TIME_MAX_SKEW_SECS - 1,
        );
        let report = engine.verify_sealed_pdf(&near).unwrap();
        assert!(report.valid, "within-skew token must pass: {report:?}");
        assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineT));
    }

    #[test]
    fn future_dated_doc_timestamp_is_rejected() {
        // The DocTimeStamp genTime feeds archival evidence freshness; a
        // future-dated one must fail, not launder stale evidence.
        let signer = test_ca("dts-skew-signer");
        let tsa = tsa_ca();
        let input = base_input();
        let b1 = append_sig_revision(&input, &signer, "dts-skew", Some(&tsa), AT_UNIX);
        let b2 = append_doc_ts_revision(&b1, &tsa, AT_UNIX + TS_GEN_TIME_MAX_SKEW_SECS + 1);
        let engine = verify_engine(vec![signer.cert_der, tsa.cert_der], AT_UNIX);
        let report = engine.verify_sealed_pdf(&b2).unwrap();
        let dts = report
            .checks
            .iter()
            .find(|c| c.kind == VerifyCheckKind::DocumentTimestamp)
            .unwrap();
        assert_eq!(
            (dts.status, dts.finding),
            (
                VerifyCheckStatus::Fail,
                Some(VerifyFindingCode::DocumentTimestampInvalid)
            ),
            "future-dated DocTimeStamp must fail its check"
        );
        assert!(!report.valid);
    }

    #[test]
    fn dss_crl_issuer_key_usage_without_crl_sign_fails() {
        // Key verification is not authorization: a CRL signed by a cert
        // whose KeyUsage lacks cRLSign fails even though its signature
        // verifies against that cert's key.
        let issuer = ca_with_kus("no-crlsign", vec![rcgen::KeyUsagePurpose::DigitalSignature]);
        let crl = build_crl(&issuer, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc(std::slice::from_ref(&issuer.cert_der), &[crl], &[]);
        let covered = covered_of(&[&issuer.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
        // Control: the same shape with cRLSign asserted is accepted.
        let ok_issuer = ca_with_kus(
            "with-crlsign",
            vec![
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::CrlSign,
            ],
        );
        let crl = build_crl(
            &ok_issuer,
            AT_UNIX - 3600,
            Some(AT_UNIX + 3600),
            None,
            vec![],
        );
        let doc = dss_doc(std::slice::from_ref(&ok_issuer.cert_der), &[crl], &[]);
        let covered = covered_of(&[&ok_issuer.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert!(
            checks.passed(VerifyCheckKind::ValidationMaterial),
            "cRLSign-authorized CRL must pass"
        );
    }

    #[test]
    fn rejected_doc_ts_leaves_no_trace_in_covered() {
        // A DocTimeStamp whose ByteRange is malformed must not extend the
        // DSS binding set, even when its token would validate.
        let tsa = tsa_ca();
        let anchors = anchors_of(&tsa);
        let bytes = b"%PDF-fake-body-for-hash";
        let entry = SigEntry {
            is_doc_ts: true,
            byte_range: [4, 2, 10, 4], // s1 != 0: ByteRange check fails
            contents: {
                // Token over the (well-formed) span digest: it WOULD
                // validate — the rejection comes from the ByteRange alone.
                let mut spans = Vec::new();
                spans.extend_from_slice(&bytes[4..6]);
                spans.extend_from_slice(&bytes[10..14]);
                mint_token(&tsa, &cms::sha256(&spans), AT_UNIX)
            },
        };
        let mut checks = Checks::new();
        let mut covered: Vec<EmbeddedCert> = Vec::new();
        let got = verify_doc_ts(
            bytes,
            &entry,
            &anchors,
            &mut checks,
            false,
            &mut covered,
            AT_UNIX * 1000,
        );
        assert!(got.is_none(), "bad ByteRange rejects the DocTimeStamp");
        assert!(
            covered.is_empty(),
            "a rejected DocTimeStamp leaves its TSA chain out of the binding set"
        );
    }

    // --- archival-time /DSS coverage binding: end-to-end through ----------

    // --- verify_sealed_pdf (the gap that let the bypass through) ----------

    use std::sync::Arc;

    use super::super::{engine, profile};
    use crate::api::{
        BackendError, BackendSignature, FetchError, FetchPolicy, FetchRequest, FetchResponse,
        PdfSealEngine, SealBackend, SealClock, SealFetcher, SealResourceLimits, SignDigestRequest,
        SignatureAlgorithm, SigningIdentity,
    };

    /// Verify clock for the regression: two hours after the seal/archival
    /// time so evidence fresh at AT_UNIX is stale by then.
    const VERIFY_SECS: u64 = AT_UNIX + 7200;

    /// A TSA identity: end entity with exactly one critical
    /// id-kp-timeStamping EKU (RFC 3161 §2.3).
    fn tsa_ca() -> TestCa {
        use p256::pkcs8::DecodePrivateKey;
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-tsa".to_string());
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let eku = cms::tlv(
            0x30,
            &cms::oid_tlv(&der::asn1::ObjectIdentifier::new_unwrap(
                "1.3.6.1.5.5.7.3.8",
            )),
        );
        let mut ext = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 37], eku);
        ext.set_criticality(true);
        params.custom_extensions.push(ext);
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        TestCa {
            cert_der,
            cert,
            key,
            rcgen_params: params,
            rcgen_key: key_pair,
        }
    }

    fn alg_id(oid: der::asn1::ObjectIdentifier, with_null: bool) -> Vec<u8> {
        let mut body = cms::oid_tlv(&oid);
        if with_null {
            body.extend_from_slice(&[0x05, 0x00]);
        }
        cms::tlv(0x30, &body)
    }

    /// Mint a TimeStampToken ContentInfo over `imprint` (RFC 3161, detached
    /// signature shape with eContent TSTInfo), signed by `tsa`.
    fn mint_token(tsa: &TestCa, imprint: &Sha256Digest, gen_time: u64) -> Vec<u8> {
        mint_token_custom(tsa, imprint, gen_time, true, None, false)
    }

    /// `mint_token` with a shape switch: `with_content_type` drops the
    /// RFC 3161 §2.4.2 content-type signed attribute when false.
    fn mint_token_shaped(
        tsa: &TestCa,
        imprint: &Sha256Digest,
        gen_time: u64,
        with_content_type: bool,
    ) -> Vec<u8> {
        mint_token_custom(tsa, imprint, gen_time, with_content_type, None, false)
    }

    /// Full fixture switchboard: `nonce` populates TSTInfo.nonce (needed by
    /// the seal-side response path), `extra_digest_alg` adds a weak SHA-1
    /// entry to the SignedData digestAlgorithms SET.
    fn mint_token_custom(
        tsa: &TestCa,
        imprint: &Sha256Digest,
        gen_time: u64,
        with_content_type: bool,
        nonce: Option<[u8; 16]>,
        extra_digest_alg: bool,
    ) -> Vec<u8> {
        let tst = x509_tsp::TstInfo {
            version: x509_tsp::TspVersion::V1,
            policy: der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4.5"),
            message_imprint: x509_tsp::MessageImprint {
                hash_algorithm: spki::AlgorithmIdentifierOwned {
                    oid: cms::OID_SHA256,
                    parameters: Some(der::asn1::Null.into()),
                },
                hashed_message: der::asn1::OctetString::new(imprint.to_vec()).unwrap(),
            },
            serial_number: der::asn1::Int::new(&[0x2a]).unwrap(),
            gen_time: gt(gen_time),
            accuracy: None,
            ordering: false,
            nonce: nonce.map(|n| der::asn1::Int::new(&n).unwrap()),
            tsa: None,
            extensions: None,
        };
        let tst_der = tst.to_der().unwrap();
        let (issuer, serial) = cms::issuer_and_serial(&tsa.cert_der).unwrap();
        let ct_oid = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
        let mut ct_body = cms::oid_tlv(&cms::OID_ATTR_CONTENT_TYPE);
        ct_body.extend_from_slice(&cms::tlv(0x31, &cms::oid_tlv(&ct_oid)));
        let mut attrs = vec![
            cms::attr_message_digest(&cms::sha256(&tst_der)),
            cms::attr_signing_cert_v2(&tsa.cert_der, &issuer, &serial),
        ];
        if with_content_type {
            attrs.push(cms::tlv(0x30, &ct_body));
        }
        let (wire, signing) = cms::assemble_signed_attrs(attrs);
        let sig = sign_p256(&tsa.key, &signing);
        let mut si = cms::tlv(0x02, &[1]);
        let mut sid = issuer;
        sid.extend_from_slice(&serial);
        si.extend_from_slice(&cms::tlv(0x30, &sid));
        si.extend_from_slice(&alg_id(cms::OID_SHA256, true));
        si.extend_from_slice(&wire);
        si.extend_from_slice(&alg_id(cms::OID_ECDSA_SHA256, false));
        si.extend_from_slice(&cms::tlv(0x04, &sig));
        let signer_info = cms::tlv(0x30, &si);
        let mut sd = cms::tlv(0x02, &[3]);
        // DER SET OF sorting: the SHA-1 AlgorithmIdentifier (30 09 ...)
        // encodes before SHA-256 (30 0D ...), so the weak entry lands first.
        let digest_algs = if extra_digest_alg {
            let sha1 = der::asn1::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
            let mut both = alg_id(sha1, true);
            both.extend_from_slice(&alg_id(cms::OID_SHA256, true));
            both
        } else {
            alg_id(cms::OID_SHA256, true)
        };
        sd.extend_from_slice(&cms::tlv(0x31, &digest_algs));
        let mut eci = cms::oid_tlv(&ct_oid);
        eci.extend_from_slice(&cms::tlv(0xA0, &cms::tlv(0x04, &tst_der)));
        sd.extend_from_slice(&cms::tlv(0x30, &eci));
        sd.extend_from_slice(&cms::tlv(0xA0, &tsa.cert_der));
        sd.extend_from_slice(&cms::tlv(0x31, &signer_info));
        let sd = cms::tlv(0x30, &sd);
        let mut ci = cms::oid_tlv(&cms::OID_SIGNED_DATA);
        ci.extend_from_slice(&cms::tlv(0xA0, &sd));
        cms::tlv(0x30, &ci)
    }

    /// Append one CAdES signature revision signed by `ca`; with `tsa`, embed
    /// a signature timestamp minted at `gen_time` (B-T).
    fn append_sig_revision(
        bytes: &[u8],
        ca: &TestCa,
        op: &str,
        tsa: Option<&TestCa>,
        gen_time: u64,
    ) -> Vec<u8> {
        let state = pdf::reparse_revision(bytes, &SealResourceLimits::default()).unwrap();
        let kind = pdf::RevisionKind::Signature {
            field_name: pdf::field_name_for(op),
            date_str: pdf::pdf_date(AT_UNIX * 1000),
        };
        let mut draft = pdf::append_revision(bytes, &state, &kind, 64 * 1024).unwrap();
        let br = draft.byte_range.unwrap();
        let digest = pdf::hash_byte_range(&draft.bytes, br).unwrap();
        let (issuer, serial) = cms::issuer_and_serial(&ca.cert_der).unwrap();
        let attrs = vec![
            cms::attr_content_type_data(),
            cms::attr_message_digest(&digest),
            cms::attr_signing_cert_v2(&ca.cert_der, &issuer, &serial),
        ];
        let (wire, signing) = cms::assemble_signed_attrs(attrs);
        let sig = sign_p256(&ca.key, &signing);
        let unsigned: Vec<Vec<u8>> = tsa
            .map(|t| mint_token(t, &cms::sha256(&sig), gen_time))
            .into_iter()
            .map(|t| cms::attr_ts_token(&t))
            .collect();
        let material = cms::SignerMaterial {
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            signer_cert_der: &ca.cert_der,
            issuer_name_der: &issuer,
            serial_der: &serial,
            chain_ders: &[],
        };
        let cms_der = cms::build_signed_data(&material, &wire, &sig, &unsigned);
        pdf::patch_contents(&mut draft, &cms_der).unwrap();
        draft.bytes
    }

    /// Append an UNSIGNED /DSS revision (catalog update + global arrays).
    fn append_dss_revision(bytes: &[u8], certs: Vec<Vec<u8>>, crls: Vec<Vec<u8>>) -> Vec<u8> {
        let state = pdf::reparse_revision(bytes, &SealResourceLimits::default()).unwrap();
        let material = profile::DssMaterial {
            certs_der: certs,
            ocsps_der: Vec::new(),
            crls_der: crls,
        };
        let (objs, dss_num) = profile::build_dss_objects(&material, state.max_obj + 1).unwrap();
        let draft = pdf::append_revision(
            bytes,
            &state,
            &pdf::RevisionKind::Dss {
                material_objects: objs,
                dss_obj: dss_num,
            },
            0,
        )
        .unwrap();
        draft.bytes
    }

    /// Append a DocTimeStamp revision minted at `gen_time` (B-LTA shape).
    fn append_doc_ts_revision(bytes: &[u8], tsa: &TestCa, gen_time: u64) -> Vec<u8> {
        let state = pdf::reparse_revision(bytes, &SealResourceLimits::default()).unwrap();
        let mut draft = pdf::append_revision(
            bytes,
            &state,
            &pdf::RevisionKind::DocumentTimestamp,
            64 * 1024,
        )
        .unwrap();
        let br = draft.byte_range.unwrap();
        let imprint = pdf::hash_byte_range(&draft.bytes, br).unwrap();
        let token = mint_token(tsa, &imprint, gen_time);
        pdf::patch_contents(&mut draft, &token).unwrap();
        draft.bytes
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
        ) -> Result<BackendSignature, BackendError> {
            Err(BackendError::Unavailable {
                retry_after_ms: None,
            })
        }
    }

    struct NoopFetcher;

    #[async_trait::async_trait]
    impl SealFetcher for NoopFetcher {
        async fn fetch(&self, _request: FetchRequest) -> Result<FetchResponse, FetchError> {
            Err(FetchError::Unavailable)
        }
    }

    struct ClockMs(u64);

    impl SealClock for ClockMs {
        fn unix_time_ms(&self) -> u64 {
            self.0
        }
    }

    fn verify_engine(anchors: Vec<Vec<u8>>, clock_secs: u64) -> engine::NativeSealEngine {
        engine::NativeSealEngine::new(
            SealConfig {
                trust_anchors_der: anchors,
                timestamp_authorities: Vec::new(),
                fetch_policy: FetchPolicy::default(),
                resource_limits: SealResourceLimits::default(),
            },
            Arc::new(NoopBackend),
            Arc::new(NoopFetcher),
            Arc::new(ClockMs(clock_secs * 1000)),
        )
        .unwrap()
    }

    /// A valid multi-signature archived document: CAdES sig A with a
    /// signature timestamp, a covered /DSS revision carrying a CRL fresh at
    /// AT_UNIX (stale at VERIFY_SECS), a DocTimeStamp covering that /DSS,
    /// and a second valid CAdES signature appended AFTER the DocTimeStamp.
    struct LtaFixture {
        bytes: Vec<u8>,
        anchors: Vec<Vec<u8>>,
        signer_cert: Vec<u8>,
        stale_later_crl: Vec<u8>,
    }

    fn lta_multisig() -> LtaFixture {
        let signer = test_ca("lta-signer");
        let signer2 = test_ca("lta-signer-two");
        let tsa = tsa_ca();
        let input = std::fs::read(format!(
            "{}/tests/fixtures/pdf-input/classic_1page.pdf",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let b1 = append_sig_revision(&input, &signer, "lta-a", Some(&tsa), AT_UNIX);
        let crl = build_crl(&signer, AT_UNIX - 60, Some(AT_UNIX + 3600), None, vec![]);
        let b2 = append_dss_revision(
            &b1,
            vec![signer.cert_der.clone(), tsa.cert_der.clone()],
            vec![crl.clone()],
        );
        let b3 = append_doc_ts_revision(&b2, &tsa, AT_UNIX);
        let b4 = append_sig_revision(&b3, &signer2, "lta-b", None, 0);
        LtaFixture {
            bytes: b4,
            anchors: vec![signer.cert_der.clone(), signer2.cert_der, tsa.cert_der],
            signer_cert: signer.cert_der,
            stale_later_crl: crl,
        }
    }

    #[test]
    fn covering_doc_timestamp_keeps_lta_at_later_verify_clock() {
        // The final /DSS IS covered by the DocTimeStamp: its genTime is the
        // archival applicable time, so evidence stale at the verify clock
        // but fresh then still validates and the profile is kept.
        let fx = lta_multisig();
        let engine = verify_engine(fx.anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&fx.bytes).unwrap();
        assert!(
            report.valid,
            "covering DocTimeStamp must keep the archived profile: {report:?}"
        );
        assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineLta));
    }

    #[test]
    fn uncovered_dss_evidence_cannot_launder_through_old_timestamp() {
        // Attack: an UNSIGNED /DSS incremental revision appended after every
        // signature, carrying evidence fresh at the old DocTimeStamp genTime
        // but stale at the verify clock. No DocTimeStamp covers this
        // revision, so its genTime must not feed freshness: the stale
        // evidence fails ValidationMaterial and the profile drops below
        // B-LT/LTA.
        let fx = lta_multisig();
        let attacked = append_dss_revision(
            &fx.bytes,
            vec![fx.signer_cert.clone()],
            vec![fx.stale_later_crl.clone()],
        );
        let engine = verify_engine(fx.anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&attacked).unwrap();
        assert_ne!(report.achieved_profile, Some(PadesProfile::BaselineLt));
        assert_ne!(report.achieved_profile, Some(PadesProfile::BaselineLta));
        let vm = report
            .checks
            .iter()
            .find(|c| c.kind == VerifyCheckKind::ValidationMaterial)
            .unwrap();
        assert_eq!(
            (vm.status, vm.finding),
            (
                VerifyCheckStatus::Fail,
                Some(VerifyFindingCode::ValidationMaterialInvalid)
            ),
            "stale uncovered evidence must fail ValidationMaterial"
        );
    }

    // --- dss_revision_end adversarial probes: the re-checker's shapes -----
    // --- (A filler span-craft, B dormant activation) plus the reference ---
    // --- chain sharpening found while building them -----------------------

    /// Classic-table incremental revision emitter for hand-crafted layouts
    /// the writer machinery cannot express (mixed doc-ts + DSS revisions,
    /// dormant objects, placeholder overwrites, trailer /Root switches).
    /// Mirrors append_revision's table emission; /Info and /ID (both
    /// optional) are omitted. Returns (bytes, [(num, obj_offset, body_start)]).
    fn emit_revision(
        input: &[u8],
        state: &pdf::RevisionState,
        objs: &[(u32, Vec<u8>)],
        root: Option<lopdf::ObjectId>,
    ) -> (Vec<u8>, Vec<(u32, u64, u64)>) {
        assert_eq!(state.xref_style, pdf::XrefStyle::Table);
        let mut out = input.to_vec();
        let mut written: Vec<(u32, u64, u64)> = Vec::with_capacity(objs.len());
        for (num, body) in objs {
            let obj_offset = out.len() as u64;
            out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
            written.push((*num, obj_offset, out.len() as u64));
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        let max_used = written
            .iter()
            .map(|w| w.0)
            .max()
            .unwrap_or(0)
            .max(state.max_obj);
        let xref_offset = out.len() as u64;
        let mut sorted = written.clone();
        sorted.sort_by_key(|w| w.0);
        out.extend_from_slice(b"xref\n");
        let mut idx = 0;
        while idx < sorted.len() {
            let start = sorted[idx].0;
            let mut end = start;
            while idx + 1 < sorted.len() && sorted[idx + 1].0 == end + 1 {
                idx += 1;
                end = sorted[idx].0;
            }
            let count = end - start + 1;
            out.extend_from_slice(format!("{start} {count}\n").as_bytes());
            for w in &sorted[idx + 1 - count as usize..=idx] {
                out.extend_from_slice(format!("{:010} 00000 n\r\n", w.1).as_bytes());
            }
            idx += 1;
        }
        let (rn, rg) = root.unwrap_or(state.root);
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Prev {} /Root {rn} {rg} R >>\n",
                max_used + 1,
                state.prev_startxref
            )
            .as_bytes(),
        );
        out.extend_from_slice(format!("startxref\n{xref_offset}\n%%EOF").as_bytes());
        (out, written)
    }

    /// /ByteRange placeholder digits, mirroring pdf's BYTERANGE_DIGITS.
    const BR_DIGITS: usize = 20;

    /// DocTimeStamp dictionary body with patchable /ByteRange and /Contents
    /// (mirrors pdf's sig_dict_body for the timestamp kind). Returns
    /// (body, byterange_patch_rel, contents_lt_rel).
    fn doc_ts_body(capacity: usize) -> (Vec<u8>, usize, usize) {
        let mut body = Vec::with_capacity(capacity * 2 + 256);
        body.extend_from_slice(
            b"<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 /ByteRange [0 ",
        );
        let br_rel = body.len();
        for i in 0..3 {
            body.extend_from_slice(b"00000000000000000000");
            if i < 2 {
                body.push(b' ');
            }
        }
        body.extend_from_slice(b"] /Contents <");
        let lt_rel = body.len() - 1;
        body.extend(std::iter::repeat_n(b'0', capacity * 2));
        body.extend_from_slice(b"> >>");
        (body, br_rel, lt_rel)
    }

    /// Patch the three trailing /ByteRange fields (l1 s2 l2) at `pos`.
    fn patch_br(out: &mut [u8], pos: usize, br: [u64; 4]) {
        for (i, v) in br[1..4].iter().enumerate() {
            let at = pos + i * (BR_DIGITS + 1);
            let field = format!("{v:0BR_DIGITS$}");
            out[at..at + BR_DIGITS].copy_from_slice(field.as_bytes());
        }
    }

    /// Write the token DER hex into the /Contents gap (zero padding stays).
    fn fill_contents(out: &mut [u8], lt: usize, gt: usize, der: &[u8]) {
        let hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
        assert!(hex.len() < gt - lt, "token exceeds contents capacity");
        out[lt + 1..lt + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    }

    /// Stream object body, mirroring profile's stream_obj.
    fn stream_body(data: &[u8]) -> Vec<u8> {
        let mut body = format!("<< /Length {} >>\nstream\n", data.len()).into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(b"\nendstream");
        body
    }

    /// Catalog body for hand-built revisions: the current catalog plus a
    /// /DSS key. Reads /Pages and /AcroForm from the revision state.
    fn catalog_body(state: &pdf::RevisionState, dss_num: Option<u32>) -> Vec<u8> {
        let pages = state
            .root_dict
            .get(b"Pages")
            .and_then(Object::as_reference)
            .unwrap();
        let af = state.acroform.unwrap();
        let dss = dss_num
            .map(|n| format!(" /DSS {n} 0 R"))
            .unwrap_or_default();
        format!(
            "<< /Type /Catalog /Pages {} {} R /AcroForm {} {} R{dss} >>",
            pages.0, pages.1, af.0, af.1
        )
        .into_bytes()
    }

    /// Parse as the verifier does and return (doc, doc-ts br_end) for the
    /// single DocTimeStamp in the file.
    fn doc_and_ts_br_end(bytes: &[u8]) -> (Document, u64) {
        let doc = Document::load_mem_with_options(
            bytes,
            LoadOptions {
                strict: true,
                max_decompressed_size: Some(SealResourceLimits::default().max_input_bytes),
                ..LoadOptions::default()
            },
        )
        .unwrap();
        let sigs = collect_signatures(&doc).unwrap();
        let ts = sigs.iter().find(|e| e.is_doc_ts).unwrap();
        (doc, ts.byte_range[2] + ts.byte_range[3])
    }

    fn base_input() -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/pdf-input/classic_1page.pdf",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    /// Probe A (the re-checker's first shape): one incremental revision
    /// carrying an effective /DSS, a DocTimeStamp dictionary BEFORE the /DSS
    /// objects in byte order, and filler objects after the newest
    /// DSS-related object. The doc-ts /ByteRange span2 ends exactly at the
    /// first filler object — the value dss_revision_end computes — which is
    /// BEFORE the revision's own xref/trailer. Returns (final bytes,
    /// anchors, br_end, revision xref offset, newest DSS-object offset).
    fn span_craft_fixture() -> (Vec<u8>, Vec<Vec<u8>>, u64, u64, u64) {
        let signer = test_ca("span-signer");
        let signer2 = test_ca("span-signer-two");
        let tsa = tsa_ca();
        let b1 = append_sig_revision(&base_input(), &signer, "span-a", Some(&tsa), AT_UNIX);
        let state = pdf::reparse_revision(&b1, &SealResourceLimits::default()).unwrap();
        let m = state.max_obj;
        let crl = build_crl(&signer, AT_UNIX - 60, Some(AT_UNIX + 3600), None, vec![]);
        let material = profile::DssMaterial {
            certs_der: vec![signer.cert_der.clone(), tsa.cert_der.clone()],
            ocsps_der: Vec::new(),
            crls_der: vec![crl],
        };
        // ts object first (m+1), then the DSS material (m+2..=dss_num).
        let (mut dss_objs, dss_num) = profile::build_dss_objects(&material, m + 2).unwrap();
        let (ts_body, br_rel, lt_rel) = doc_ts_body(64 * 1024);
        let cat_body = catalog_body(&state, Some(dss_num));
        let mut objs: Vec<(u32, Vec<u8>)> = vec![(m + 1, ts_body)];
        objs.append(&mut dss_objs);
        objs.push((state.root.0, cat_body));
        let filler1 = dss_num + 1;
        objs.push((filler1, b"<< /Probe /FillerOne >>".to_vec()));
        objs.push((dss_num + 2, b"<< /Probe /FillerTwo >>".to_vec()));
        let (mut bytes, written) = emit_revision(&b1, &state, &objs, None);
        let at = |num: u32| written.iter().find(|w| w.0 == num).copied().unwrap();
        let (_, _, ts_body_start) = at(m + 1);
        let (_, x, _) = at(filler1);
        let newest_dss = at(state.root.0).1;
        let capacity = 64 * 1024;
        let lt = (ts_body_start as usize) + lt_rel;
        let gt = lt + 1 + capacity * 2;
        let br = [0, lt as u64, gt as u64 + 1, x - (gt as u64 + 1)];
        patch_br(&mut bytes, (ts_body_start as usize) + br_rel, br);
        let imprint = pdf::hash_byte_range(&bytes, br).unwrap();
        let token = mint_token(&tsa, &imprint, AT_UNIX);
        fill_contents(&mut bytes, lt, gt, &token);
        let rev_xref = pdf::last_startxref(&bytes).unwrap();
        let b3 = append_sig_revision(&bytes, &signer2, "span-b", None, 0);
        let anchors = vec![signer.cert_der, signer2.cert_der, tsa.cert_der];
        (b3, anchors, x, rev_xref, newest_dss)
    }

    #[test]
    fn probe_a_filler_span_craft_attests_every_evaluated_byte() {
        // Precondition: filler objects after the newest DSS-related object
        // let the doc-ts span2 stop at dss_revision_end BEFORE the owning
        // revision's xref/trailer. The gate passes — and the grant is SOUND:
        // every object the /DSS evaluation dereferences is in the measured
        // id set, so its offset is <= newest < dss_end == br_end and its
        // bytes sit inside the hashed spans (the only excluded range is the
        // /Contents gap inside the doc-ts object itself). The uncovered
        // filler/xref/trailer bytes feed no evidence evaluation; the xref
        // chain is attested by the final covering signature. Regression pin:
        // a gate change to revision-end semantics flips this honest-but-
        // unusual document to Invalid (dss_revision_end no longer == br_end).
        let (bytes, anchors, br_end, rev_xref, newest_dss) = span_craft_fixture();
        assert!(
            br_end < rev_xref,
            "span2 must stop before the revision xref"
        );
        let (doc, ts_br_end) = doc_and_ts_br_end(&bytes);
        assert_eq!(ts_br_end, br_end);
        assert_eq!(dss_revision_end(&doc, &bytes), Some(br_end));
        assert!(newest_dss < br_end);
        let engine = verify_engine(anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&bytes).unwrap();
        eprintln!(
            "PROBE-A br_end={br_end} dss_end={:?} rev_xref={rev_xref} newest_dss={newest_dss} -> {:?}",
            dss_revision_end(&doc, &bytes),
            report.achieved_profile
        );
        assert!(report.valid, "attested evidence must validate: {report:?}");
        assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineLta));
    }

    #[test]
    fn non_covering_doc_timestamp_confers_lt_not_lta() {
        // A VALID DocTimeStamp that does NOT cover the final /DSS keeps its
        // DocumentTimestamp check but must not confer B-LTA: fresh-at-clock
        // evidence plus a non-covering DTS classifies BaselineLt.
        let signer = test_ca("nc-signer");
        let signer2 = test_ca("nc-signer-two");
        let tsa = tsa_ca();
        let b1 = append_sig_revision(&base_input(), &signer, "nc-a", Some(&tsa), AT_UNIX);
        // DocTimeStamp BEFORE the /DSS revision: it cannot cover it.
        let b2 = append_doc_ts_revision(&b1, &tsa, AT_UNIX);
        // Evidence fresh at the VERIFY clock, so ValidationMaterial passes
        // without any archival time.
        let crl = build_crl(
            &signer,
            AT_UNIX - 60,
            Some(VERIFY_SECS + 3600),
            None,
            vec![],
        );
        let b3 = append_dss_revision(
            &b2,
            vec![signer.cert_der.clone(), tsa.cert_der.clone()],
            vec![crl],
        );
        let b4 = append_sig_revision(&b3, &signer2, "nc-b", None, 0);
        let anchors = vec![signer.cert_der, signer2.cert_der, tsa.cert_der];
        let engine = verify_engine(anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&b4).unwrap();
        assert!(report.valid, "fresh evidence must validate: {report:?}");
        let dts = report
            .checks
            .iter()
            .find(|c| c.kind == VerifyCheckKind::DocumentTimestamp)
            .unwrap();
        assert_eq!(dts.status, VerifyCheckStatus::Pass);
        assert_eq!(
            report.achieved_profile,
            Some(PadesProfile::BaselineLt),
            "a non-covering DocTimeStamp confers no archival rung"
        );
    }

    /// Probe B1 (dormant staging, activation by a LATER catalog /DSS key):
    /// /DSS objects sit in pre-timestamp revisions (covered by the doc-ts)
    /// but unnamed by the catalog; a post-timestamp revision's catalog
    /// update activates them. The gate must FAIL: the final trailer /Root
    /// object is itself in the measured id set, and the activating catalog
    /// instance lives past the doc-ts ByteRange end, so dss_revision_end
    /// exceeds br_end and the verification clock applies.
    #[test]
    fn probe_b1_late_catalog_activation_misses_archival_time() {
        let signer = test_ca("dorm-signer");
        let signer2 = test_ca("dorm-signer-two");
        let tsa = tsa_ca();
        let b1 = append_sig_revision(&base_input(), &signer, "dorm-a", Some(&tsa), AT_UNIX);
        let state = pdf::reparse_revision(&b1, &SealResourceLimits::default()).unwrap();
        let crl = build_crl(&signer, AT_UNIX - 60, Some(AT_UNIX + 3600), None, vec![]);
        let material = profile::DssMaterial {
            certs_der: vec![signer.cert_der.clone(), tsa.cert_der.clone()],
            ocsps_der: Vec::new(),
            crls_der: vec![crl],
        };
        let (dss_objs, dss_num) = profile::build_dss_objects(&material, state.max_obj + 1).unwrap();
        // Dormant staging: material objects only, no catalog /DSS key.
        let (b2, _) = emit_revision(&b1, &state, &dss_objs, None);
        let b3 = append_doc_ts_revision(&b2, &tsa, AT_UNIX);
        // Activation: a post-timestamp catalog update naming the staged DSS.
        let state4 = pdf::reparse_revision(&b3, &SealResourceLimits::default()).unwrap();
        let cat_body = catalog_body(&state4, Some(dss_num));
        let (b4, written4) = emit_revision(&b3, &state4, &[(state4.root.0, cat_body)], None);
        let cat_offset = written4[0].1;
        let b5 = append_sig_revision(&b4, &signer2, "dorm-b", None, 0);
        let anchors = vec![signer.cert_der, signer2.cert_der, tsa.cert_der];
        let (doc, ts_br_end) = doc_and_ts_br_end(&b5);
        let dss_end = dss_revision_end(&doc, &b5).unwrap();
        eprintln!(
            "PROBE-B1 ts_br_end={ts_br_end} dss_end={dss_end} activating_catalog@{cat_offset}"
        );
        assert!(cat_offset >= ts_br_end);
        assert!(
            dss_end > ts_br_end,
            "gate must measure the activating catalog"
        );
        let engine = verify_engine(anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&b5).unwrap();
        eprintln!("PROBE-B1 outcome -> {:?}", report.achieved_profile);
        assert!(!report.valid, "stale unattested evidence must not launder");
        assert_eq!(report.achieved_profile, None);
        let vm = report
            .checks
            .iter()
            .find(|c| c.kind == VerifyCheckKind::ValidationMaterial)
            .unwrap();
        assert_eq!(
            (vm.status, vm.finding),
            (
                VerifyCheckStatus::Fail,
                Some(VerifyFindingCode::ValidationMaterialInvalid)
            )
        );
    }

    /// Probe B2 (dormant staging, activation by trailer /Root switch): the
    /// staged bytes include a dormant ALTERNATE catalog C2 carrying the /DSS
    /// key; a post-timestamp revision only switches the trailer /Root to C2.
    /// The gate passes (every measured id resolves to a pre-timestamp
    /// offset) — and the grant is SOUND: the timestamp attests C2 and every
    /// /DSS object the evaluation reads; only the switching trailer is
    /// unattested by the doc-ts, and it is attested by the final covering
    /// signature. Regression pin: precondition dormant-staging; documents
    /// that the offset gate measures object identity, not activation time.
    #[test]
    fn probe_b2_root_switch_attests_staged_catalog_and_evidence() {
        let signer = test_ca("switch-signer");
        let signer2 = test_ca("switch-signer-two");
        let tsa = tsa_ca();
        let b1 = append_sig_revision(&base_input(), &signer, "switch-a", Some(&tsa), AT_UNIX);
        let state = pdf::reparse_revision(&b1, &SealResourceLimits::default()).unwrap();
        let m = state.max_obj;
        let crl = build_crl(&signer, AT_UNIX - 60, Some(AT_UNIX + 3600), None, vec![]);
        let material = profile::DssMaterial {
            certs_der: vec![signer.cert_der.clone(), tsa.cert_der.clone()],
            ocsps_der: Vec::new(),
            crls_der: vec![crl],
        };
        let (mut dss_objs, dss_num) = profile::build_dss_objects(&material, m + 1).unwrap();
        let c2_num = dss_num + 1;
        dss_objs.push((c2_num, catalog_body(&state, Some(dss_num))));
        // Dormant staging: C2 present in bytes, trailer /Root unchanged.
        let (b2, written2) = emit_revision(&b1, &state, &dss_objs, None);
        let c2_offset = written2.iter().find(|w| w.0 == c2_num).unwrap().1;
        let b3 = append_doc_ts_revision(&b2, &tsa, AT_UNIX);
        // Activation: trailer /Root switch only (one filler object carries
        // the revision; the doc-ts does not cover this revision).
        let state4 = pdf::reparse_revision(&b3, &SealResourceLimits::default()).unwrap();
        let filler = state4.max_obj + 1;
        let (b4, _) = emit_revision(
            &b3,
            &state4,
            &[(filler, b"<< /Probe /RootSwitch >>".to_vec())],
            Some((c2_num, 0)),
        );
        let b5 = append_sig_revision(&b4, &signer2, "switch-b", None, 0);
        let anchors = vec![signer.cert_der, signer2.cert_der, tsa.cert_der];
        let (doc, ts_br_end) = doc_and_ts_br_end(&b5);
        let dss_end = dss_revision_end(&doc, &b5).unwrap();
        eprintln!("PROBE-B2 ts_br_end={ts_br_end} dss_end={dss_end} staged_catalog_c2@{c2_offset}");
        assert!(c2_offset < ts_br_end, "C2 is staged pre-timestamp");
        assert!(dss_end <= ts_br_end, "gate passes over staged objects");
        let engine = verify_engine(anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&b5).unwrap();
        eprintln!("PROBE-B2 outcome -> {:?}", report.achieved_profile);
        assert!(
            report.valid,
            "attested staged evidence must validate: {report:?}"
        );
        assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineLta));
    }

    /// Probe C (the sharpening found while building A/B): the /CRLs array
    /// item is a REFERENCE CHAIN — a covered bare-reference object whose
    /// target stream is planted in a POST-timestamp revision (a placeholder
    /// reserves the object number pre-timestamp). The evaluation path
    /// (dss_array -> Document::dereference) follows chains, so the verifier
    /// reads the planted CRL; but dss_revision_end collected only the direct
    /// reference, so the terminal stream escaped the measured offsets, the
    /// gate passed, and stale-at-clock evidence validated at the archival
    /// genTime. WITHOUT the dss_revision_end chain-resolution fix this test
    /// FAILS (the document verifies BaselineLta): the mutation pin for the
    /// laundering hole. WITH the fix the gate measures the planted stream's
    /// post-timestamp offset and the verification clock applies.
    #[test]
    fn probe_c_reference_chain_cannot_smuggle_unattested_evidence() {
        let signer = test_ca("chain-signer");
        let signer2 = test_ca("chain-signer-two");
        let tsa = tsa_ca();
        let b1 = append_sig_revision(&base_input(), &signer, "chain-a", Some(&tsa), AT_UNIX);
        let state = pdf::reparse_revision(&b1, &SealResourceLimits::default()).unwrap();
        let m = state.max_obj;
        let crl = build_crl(&signer, AT_UNIX - 60, Some(AT_UNIX + 3600), None, vec![]);
        let (c1, c2, dss_n, link, hole) = (m + 1, m + 2, m + 3, m + 4, m + 5);
        let dss_body =
            format!("<< /Type /DSS /Certs [{c1} 0 R {c2} 0 R] /CRLs [{link} 0 R] >>").into_bytes();
        let objs = vec![
            (c1, stream_body(&signer.cert_der)),
            (c2, stream_body(&tsa.cert_der)),
            (dss_n, dss_body),
            (link, format!("{hole} 0 R").into_bytes()),
            (hole, b"null".to_vec()),
            (state.root.0, catalog_body(&state, Some(dss_n))),
        ];
        let (b2, _) = emit_revision(&b1, &state, &objs, None);
        let b3 = append_doc_ts_revision(&b2, &tsa, AT_UNIX);
        // Plant the terminal CRL stream AFTER the timestamp, overwriting the
        // placeholder: the doc-ts attests "null", the evaluation reads this.
        let state4 = pdf::reparse_revision(&b3, &SealResourceLimits::default()).unwrap();
        let (b4, written4) = emit_revision(&b3, &state4, &[(hole, stream_body(&crl))], None);
        let planted_offset = written4[0].1;
        let b5 = append_sig_revision(&b4, &signer2, "chain-b", None, 0);
        let anchors = vec![signer.cert_der, signer2.cert_der, tsa.cert_der];
        let (doc, ts_br_end) = doc_and_ts_br_end(&b5);
        let dss_end = dss_revision_end(&doc, &b5).unwrap();
        eprintln!("PROBE-C ts_br_end={ts_br_end} dss_end={dss_end} planted_crl@{planted_offset}");
        assert!(
            planted_offset >= ts_br_end,
            "planted evidence is post-timestamp"
        );
        let engine = verify_engine(anchors, VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&b5).unwrap();
        eprintln!("PROBE-C outcome -> {:?}", report.achieved_profile);
        assert!(
            dss_end > ts_br_end,
            "chain-resolved gate must measure the planted stream"
        );
        assert!(
            !report.valid,
            "unattested planted evidence laundered to {:?}",
            report.achieved_profile
        );
        assert_eq!(report.achieved_profile, None);
        let vm = report
            .checks
            .iter()
            .find(|c| c.kind == VerifyCheckKind::ValidationMaterial)
            .unwrap();
        assert_eq!(
            (vm.status, vm.finding),
            (
                VerifyCheckStatus::Fail,
                Some(VerifyFindingCode::ValidationMaterialInvalid)
            )
        );
    }

    // --- bot-fix leg 3b pins: DSS stream decode, object cap, typeless ----
    // --- signature discovery, hex whitespace in /Contents -----------------

    /// zlib wrapper around one final DEFLATE stored block (no compressor
    /// dependency needed for the fixture).
    fn zlib_store(data: &[u8]) -> Vec<u8> {
        assert!(u16::try_from(data.len()).is_ok());
        let len = data.len() as u16;
        let mut out = vec![0x78u8, 0x01, 0x01];
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(data);
        let (mut a, mut b) = (1u32, 0u32);
        for &x in data {
            a = (a + u32::from(x)) % 65521;
            b = (b + a) % 65521;
        }
        out.extend_from_slice(&((b << 16) | a).to_be_bytes());
        out
    }

    /// Mirror of `dss_doc` whose CRL entry rides a /FlateDecode stream.
    fn dss_doc_flate_crl(certs: &[Vec<u8>], crl_stream_bytes: Vec<u8>) -> Document {
        let mut doc = Document::with_version("1.4");
        let mut dss = lopdf::Dictionary::new();
        dss.set("Type", Object::Name(b"DSS".to_vec()));
        if !certs.is_empty() {
            let refs: Vec<Object> = certs
                .iter()
                .map(|d| {
                    let s = Stream::new(lopdf::Dictionary::new(), d.clone());
                    Object::Reference(doc.add_object(Object::Stream(s)))
                })
                .collect();
            dss.set("Certs", Object::Array(refs));
        }
        let mut crl_dict = lopdf::Dictionary::new();
        crl_dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        let crl_ref = Object::Reference(
            doc.add_object(Object::Stream(Stream::new(crl_dict, crl_stream_bytes))),
        );
        dss.set("CRLs", Object::Array(vec![crl_ref]));
        let dss_id = doc.add_object(Object::Dictionary(dss));
        let mut catalog = lopdf::Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("DSS", Object::Reference(dss_id));
        let cat_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(cat_id));
        doc
    }

    #[test]
    fn dss_flate_wrapped_crl_validates() {
        // Filtered DSS evidence must be decoded before parsing: a
        // FlateDecode-wrapped CRL covering the chain validates exactly like
        // its raw form.
        let ca = test_ca("flate-dss-ca");
        let crl = build_crl(&ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc_flate_crl(std::slice::from_ref(&ca.cert_der), zlib_store(&crl));
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert!(
            checks.passed(VerifyCheckKind::ValidationMaterial),
            "FlateDecode-wrapped CRL evidence must validate"
        );
    }

    #[test]
    fn dss_broken_filter_stream_is_malformed_never_skipped() {
        // A stream whose declared filter cannot decode is Malformed, which
        // fails ValidationMaterial — never a silent skip to AbsentAllowed.
        let ca = test_ca("flate-broken-ca");
        let doc = dss_doc_flate_crl(std::slice::from_ref(&ca.cert_der), b"not zlib".to_vec());
        let covered = covered_of(&[&ca.cert_der]);
        let checks = dss_check(&doc, &covered);
        assert_material_fails(&checks);
    }

    #[test]
    fn verify_enforces_max_pdf_objects() {
        // The seal side rejects over-cap object counts; the verify side
        // must enforce the same configured cap.
        let signer = test_ca("objcap-signer");
        let bytes = append_sig_revision(&base_input(), &signer, "objcap", None, 0);
        let limits = SealResourceLimits {
            max_pdf_objects: 2,
            ..SealResourceLimits::default()
        };
        let engine = engine::NativeSealEngine::new(
            SealConfig {
                trust_anchors_der: vec![signer.cert_der],
                timestamp_authorities: Vec::new(),
                fetch_policy: FetchPolicy::default(),
                resource_limits: limits,
            },
            Arc::new(NoopBackend),
            Arc::new(NoopFetcher),
            Arc::new(ClockMs(VERIFY_SECS * 1000)),
        )
        .unwrap();
        let err = engine.verify_sealed_pdf(&bytes).unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: InputInvalidCode::ObjectLimitExceeded
            }
        ));
    }

    /// Signature dictionary body with patchable /ByteRange and /Contents,
    /// /Type optional (the typeless interop shape). Mirrors pdf's
    /// sig_dict_body. Returns (body, byterange_patch_rel, contents_lt_rel).
    fn sig_body_shaped(capacity: usize, typed: bool) -> (Vec<u8>, usize, usize) {
        let mut body = Vec::with_capacity(capacity * 2 + 256);
        body.extend_from_slice(b"<< ");
        if typed {
            body.extend_from_slice(b"/Type /Sig ");
        }
        body.extend_from_slice(
            b"/Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0 ",
        );
        let br_rel = body.len();
        for i in 0..3 {
            body.extend_from_slice(b"00000000000000000000");
            if i < 2 {
                body.push(b' ');
            }
        }
        body.extend_from_slice(b"] /Contents <");
        let lt_rel = body.len() - 1;
        body.extend(std::iter::repeat_n(b'0', capacity * 2));
        body.extend_from_slice(b"> >>");
        (body, br_rel, lt_rel)
    }

    /// Write the CMS DER hex into the gap with spec-legal whitespace (two
    /// spaces every 16 bytes — an even count, so the digit total stays
    /// even); the rest of the gap stays zero padding.
    fn fill_contents_spaced(out: &mut [u8], lt: usize, gt: usize, der: &[u8]) {
        let mut hex = String::new();
        for (i, b) in der.iter().enumerate() {
            if i > 0 && i % 16 == 0 {
                hex.push_str("  ");
            }
            hex.push_str(&format!("{b:02x}"));
        }
        assert!(hex.len() < gt - lt, "token exceeds contents capacity");
        out[lt + 1..lt + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    }

    /// Hand-emit a one-object signature revision (no field/widget — the
    /// native verifier discovers signatures by object scan) with a real CMS
    /// over the ByteRange digest.
    fn crafted_sig_revision(name: &str, typed: bool, spaced_hex: bool) -> (Vec<u8>, TestCa) {
        let signer = test_ca(name);
        let input = base_input();
        let state = pdf::reparse_revision(&input, &SealResourceLimits::default()).unwrap();
        let capacity = 64 * 1024;
        let (body, br_rel, lt_rel) = sig_body_shaped(capacity, typed);
        let sig_num = state.max_obj + 1;
        let (mut bytes, written) = emit_revision(&input, &state, &[(sig_num, body)], None);
        let (_, _, body_start) = written.iter().find(|w| w.0 == sig_num).copied().unwrap();
        let lt = (body_start as usize) + lt_rel;
        let gt = lt + 1 + capacity * 2;
        let total = bytes.len() as u64;
        let br = [0, lt as u64, gt as u64 + 1, total - (gt as u64 + 1)];
        patch_br(&mut bytes, (body_start as usize) + br_rel, br);
        let digest = pdf::hash_byte_range(&bytes, br).unwrap();
        let (issuer, serial) = cms::issuer_and_serial(&signer.cert_der).unwrap();
        let attrs = vec![
            cms::attr_content_type_data(),
            cms::attr_message_digest(&digest),
            cms::attr_signing_cert_v2(&signer.cert_der, &issuer, &serial),
        ];
        let (wire, signing) = cms::assemble_signed_attrs(attrs);
        let sig = sign_p256(&signer.key, &signing);
        let material = cms::SignerMaterial {
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            signer_cert_der: &signer.cert_der,
            issuer_name_der: &issuer,
            serial_der: &serial,
            chain_ders: &[],
        };
        let cms_der = cms::build_signed_data(&material, &wire, &sig, &[]);
        if spaced_hex {
            fill_contents_spaced(&mut bytes, lt, gt, &cms_der);
        } else {
            fill_contents(&mut bytes, lt, gt, &cms_der);
        }
        (bytes, signer)
    }

    #[test]
    fn typeless_signature_dictionary_verifies() {
        // Interop: real-world signers omit the optional /Type on the
        // signature dictionary. The /ByteRange + /Contents shape must be
        // discovered and verified, not silently skipped into "no cades".
        let (bytes, signer) = crafted_sig_revision("typeless-sig", false, false);
        let engine = verify_engine(vec![signer.cert_der], VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&bytes).unwrap();
        assert!(
            report.valid,
            "typeless signature doc must verify: {report:?}"
        );
        assert_eq!(report.achieved_profile, Some(PadesProfile::BaselineB));
    }

    #[test]
    fn partial_signature_shape_is_malformed_never_skipped() {
        // /ByteRange WITHOUT /Contents (or vice versa) is malformed input,
        // never a silent skip.
        let mut doc = Document::with_version("1.4");
        let mut d = lopdf::Dictionary::new();
        d.set(
            "ByteRange",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(1),
                Object::Integer(2),
                Object::Integer(3),
            ]),
        );
        doc.add_object(Object::Dictionary(d));
        assert!(collect_signatures(&doc).is_err());
    }

    #[test]
    fn whitespace_padded_contents_verifies() {
        // PDF permits whitespace inside hex strings: a /Contents value
        // padded with spaces must verify, with the length check counting
        // only hex digits.
        let (bytes, signer) = crafted_sig_revision("ws-sig", true, true);
        let engine = verify_engine(vec![signer.cert_der], VERIFY_SECS);
        let report = engine.verify_sealed_pdf(&bytes).unwrap();
        assert!(
            report.valid,
            "whitespace-padded /Contents must verify: {report:?}"
        );
    }

    #[test]
    fn byte_range_hex_length_counts_digits_not_whitespace() {
        // Direct mutation probe on the gate: "<AB CD>" decodes to two
        // bytes; a one-byte /Contents claim must still FAIL (whitespace is
        // stripped, not counted as content).
        let bytes = b"xx<AB CD>yy";
        let ok = SigEntry {
            is_doc_ts: false,
            byte_range: [0, 2, 9, 2],
            contents: vec![0xAB, 0xCD],
        };
        assert!(check_byte_range(bytes, &ok));
        let short = SigEntry {
            is_doc_ts: false,
            byte_range: [0, 2, 9, 2],
            contents: vec![0xAB],
        };
        assert!(!check_byte_range(bytes, &short));
        let long = SigEntry {
            is_doc_ts: false,
            byte_range: [0, 2, 9, 2],
            contents: vec![0xAB, 0xCD, 0xEF],
        };
        assert!(!check_byte_range(bytes, &long));
    }

    // --- bot-fix leg 4 pins -------------------------------------------------

    #[test]
    fn contents_without_byte_range_is_never_a_signature_candidate() {
        // P1-1: ordinary /Page dictionaries carry /Contents (the page
        // content stream) without /ByteRange — typeless candidacy requires
        // /ByteRange, so these must be IGNORED, never rejected as malformed
        // (leg 3b's XOR gate false-rejected every non-blank page).
        let mut doc = Document::with_version("1.4");
        let mut page = lopdf::Dictionary::new();
        page.set("Type", Object::Name(b"Page".to_vec()));
        page.set("Contents", Object::Reference((42, 0)));
        doc.add_object(Object::Dictionary(page));
        let mut bare = lopdf::Dictionary::new();
        bare.set("Contents", Object::string_literal(b"BT ET".to_vec()));
        doc.add_object(Object::Dictionary(bare));
        let found = collect_signatures(&doc).unwrap();
        assert!(found.is_empty(), "page /Contents is not a signature");
    }

    #[test]
    fn byte_range_without_contents_stays_malformed() {
        // P1-1 rejection pin: a /ByteRange dictionary with no /Contents is
        // a partial signature shape — malformed, never a silent skip.
        let mut doc = Document::with_version("1.4");
        let mut d = lopdf::Dictionary::new();
        d.set(
            "ByteRange",
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(1),
                Object::Integer(2),
                Object::Integer(3),
            ]),
        );
        doc.add_object(Object::Dictionary(d));
        assert!(collect_signatures(&doc).is_err());
    }

    #[test]
    fn subfilter_dispatch_is_fail_closed() {
        // A candidate is evaluated ONLY under the handler its /SubFilter
        // names; absent/foreign SubFilter on a typed dict is skipped, never
        // evaluated as CAdES.
        fn doc_with(type_name: Option<&[u8]>, subfilter: Option<&[u8]>) -> Document {
            let mut doc = Document::with_version("1.4");
            let mut d = lopdf::Dictionary::new();
            if let Some(t) = type_name {
                d.set("Type", Object::Name(t.to_vec()));
            }
            if let Some(sf) = subfilter {
                d.set("SubFilter", Object::Name(sf.to_vec()));
            }
            d.set(
                "ByteRange",
                Object::Array(vec![
                    Object::Integer(0),
                    Object::Integer(1),
                    Object::Integer(2),
                    Object::Integer(3),
                ]),
            );
            d.set(
                "Contents",
                Object::String(vec![0u8; 2], lopdf::StringFormat::Hexadecimal),
            );
            doc.add_object(Object::Dictionary(d));
            doc
        }
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let rfc3161: &[u8] = b"ETSI.RFC3161";
        // The finding's shape: /Sig with /adbe.pkcs7.detached is NOT CAdES.
        assert!(
            collect_signatures(&doc_with(Some(b"Sig"), Some(b"adbe.pkcs7.detached")))
                .unwrap()
                .is_empty()
        );
        // Typed dicts with ABSENT SubFilter are skipped too.
        assert!(
            collect_signatures(&doc_with(Some(b"Sig"), None))
                .unwrap()
                .is_empty()
        );
        assert!(
            collect_signatures(&doc_with(Some(b"DocTimeStamp"), None))
                .unwrap()
                .is_empty()
        );
        // Wrong handler for the type: an RFC3161-subfiltered /Sig and a
        // CAdES-subfiltered DocTimeStamp are both skipped.
        assert!(
            collect_signatures(&doc_with(Some(b"Sig"), Some(rfc3161)))
                .unwrap()
                .is_empty()
        );
        assert!(
            collect_signatures(&doc_with(Some(b"DocTimeStamp"), Some(cades)))
                .unwrap()
                .is_empty()
        );
        // Correct handler per type is collected.
        let found = collect_signatures(&doc_with(Some(b"Sig"), Some(cades))).unwrap();
        assert_eq!(found.len(), 1);
        assert!(!found[0].is_doc_ts);
        let found = collect_signatures(&doc_with(Some(b"DocTimeStamp"), Some(rfc3161))).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].is_doc_ts);
        // Typeless interop: absent SubFilter tolerated, foreign one skipped.
        let found = collect_signatures(&doc_with(None, None)).unwrap();
        assert_eq!(found.len(), 1);
        assert!(!found[0].is_doc_ts);
        assert!(
            collect_signatures(&doc_with(None, Some(b"adbe.pkcs7.detached")))
                .unwrap()
                .is_empty()
        );
    }

    /// A chain of `hops` reference-linked objects ending in a terminal
    /// dictionary; returns the document and the chain's head id.
    fn reference_chain_doc(hops: usize) -> (Document, lopdf::ObjectId) {
        assert!(hops >= 1);
        let mut doc = Document::with_version("1.4");
        let terminal = doc.add_object(Object::Dictionary(lopdf::Dictionary::new()));
        let mut head = terminal;
        for _ in 1..hops {
            head = doc.add_object(Object::Reference(head));
        }
        (doc, head)
    }

    #[test]
    fn reference_chain_repetition_stays_bounded_by_unique_set() {
        // P1-2: N repetitions of one deep chain (one per DSS array
        // occurrence) must collapse into the chain's UNIQUE object set —
        // the id collection can never expand to 128*N.
        let (doc, head) = reference_chain_doc(128);
        let mut ids = std::collections::BTreeSet::new();
        let mut work = 0usize;
        for _ in 0..128 {
            collect_reference_chain(&doc, head, &mut ids, &mut work).unwrap();
        }
        assert_eq!(ids.len(), 128, "only unique objects are collected");
        assert_eq!(work, 128 * 128, "work counts hops across all chains");
        // The global budget fails closed past the cap: the 129th full
        // traversal would exceed MAX_REFERENCE_WORK.
        assert!(collect_reference_chain(&doc, head, &mut ids, &mut work).is_none());
    }

    #[test]
    fn reference_chain_cycle_and_over_limit_stay_fail_closed() {
        // P1-2: a reference cycle fails closed (the per-chain 128-hop bound
        // is kept), as does a 129-hop chain; a 128-hop chain still
        // resolves (the bound mirrors lopdf's dereference limit).
        let mut doc = Document::with_version("1.4");
        let a = doc.add_object(Object::Null);
        let b = doc.add_object(Object::Null);
        doc.objects.insert(a, Object::Reference(b));
        doc.objects.insert(b, Object::Reference(a));
        let mut ids = std::collections::BTreeSet::new();
        let mut work = 0usize;
        assert!(collect_reference_chain(&doc, a, &mut ids, &mut work).is_none());

        let (doc, head_129) = reference_chain_doc(129);
        let mut ids = std::collections::BTreeSet::new();
        let mut work = 0usize;
        assert!(collect_reference_chain(&doc, head_129, &mut ids, &mut work).is_none());

        let (doc, head_128) = reference_chain_doc(128);
        let mut ids = std::collections::BTreeSet::new();
        let mut work = 0usize;
        assert!(collect_reference_chain(&doc, head_128, &mut ids, &mut work).is_some());
        assert_eq!(ids.len(), 128);
    }

    #[test]
    fn dss_decode_budget_is_cumulative_across_entries() {
        // P1-3: two FlateDecode DSS streams each individually under the cap
        // but cumulatively over it must fail ValidationMaterial — the
        // budget is ONE shared remaining across every DSS entry, not a
        // per-stream allowance.
        let ca = test_ca("budget-dss-ca");
        let crl = build_crl(&ca, AT_UNIX - 3600, Some(AT_UNIX + 3600), None, vec![]);
        let doc = dss_doc_flate_crl(std::slice::from_ref(&ca.cert_der), zlib_store(&crl));
        let covered = covered_of(&[&ca.cert_der]);
        let total = ca.cert_der.len() + crl.len();
        // Control: a budget covering both entries validates (the streams
        // are individually and cumulatively fine).
        let mut checks = Checks::new();
        verify_dss(&doc, &[], &covered, AT_UNIX, total, &mut checks);
        assert!(
            checks.passed(VerifyCheckKind::ValidationMaterial),
            "cumulative-fitting evidence must validate"
        );
        // One byte short cumulatively: the /Certs entry still decodes (it
        // fits the full cap alone), but the shared remainder is one byte
        // too small for the FlateDecode-wrapped CRL — the material fails
        // WITHOUT decoding beyond the shared limit. The pre-fix per-stream
        // cap decoded both and validated.
        let mut checks = Checks::new();
        verify_dss(&doc, &[], &covered, AT_UNIX, total - 1, &mut checks);
        assert_material_fails(&checks);
    }
}
