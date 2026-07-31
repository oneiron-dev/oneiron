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

/// RFC 5280 path validation against configured trust anchors at the
/// applicable time. Shared by the assembler (B-LT chain pre-check) and the
/// verifier.
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
        .map_err(|_| SealError::Fatal {
            stage: crate::error::SealStage::Verification,
            code: crate::error::FatalCode::CertificatePathInvalid,
        })?;
    pkix_chain::verify_chain(
        &chain,
        anchors,
        &pkix_chain::ValidationPolicy::new(at_unix),
        &pkix_chain::DefaultVerifier,
        &pkix_chain::NoRevocation,
        &pkix_chain::NoAiaFetcher,
    )
    .map(|_| ())
    .map_err(|_| SealError::Fatal {
        stage: crate::error::SealStage::Verification,
        code: crate::error::FatalCode::CertificatePathInvalid,
    })
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
/// revisions cover fewer bytes).
fn collect_signatures(doc: &Document) -> Result<Vec<SigEntry>, SealError> {
    let mut out = Vec::new();
    for obj in doc.objects.values() {
        let Object::Dictionary(d) = obj else { continue };
        let Ok(t) = d.get(b"Type") else { continue };
        let is_sig = name_eq(t, b"Sig");
        let is_ts = name_eq(t, b"DocTimeStamp");
        if !is_sig && !is_ts {
            continue;
        }
        let br_obj = d.get(b"ByteRange").map_err(|_| SealError::InputInvalid {
            code: InputInvalidCode::MalformedXref,
        })?;
        let Object::Array(items) = br_obj else {
            return Err(SealError::InputInvalid {
                code: InputInvalidCode::MalformedXref,
            });
        };
        if items.len() != 4 {
            return Err(SealError::InputInvalid {
                code: InputInvalidCode::MalformedXref,
            });
        }
        let mut br = [0u64; 4];
        for (i, item) in items.iter().enumerate() {
            let Object::Integer(v) = item else {
                return Err(SealError::InputInvalid {
                    code: InputInvalidCode::MalformedXref,
                });
            };
            br[i] = u64::try_from(*v).map_err(|_| SealError::InputInvalid {
                code: InputInvalidCode::MalformedXref,
            })?;
        }
        let Object::String(contents, _) = d.get(b"Contents").map_err(|_| {
            SealError::InputInvalid {
                code: InputInvalidCode::MalformedXref,
            }
        })?
        else {
            return Err(SealError::InputInvalid {
                code: InputInvalidCode::MalformedXref,
            });
        };
        out.push(SigEntry {
            is_doc_ts: is_ts,
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
    let Some(end2) = s2.checked_add(l2) else { return false };
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
    let hex_chars = s2 - l1 - 2;
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

/// Verify one CAdES-detached signature dictionary.
#[allow(clippy::too_many_lines)]
fn verify_cades_sig(
    bytes: &[u8],
    e: &SigEntry,
    ctx: &VerifyCtx<'_>,
    anchors: &[pkix_chain::TrustAnchor],
    checks: &mut Checks,
) {
    let br_ok = check_byte_range(bytes, e);
    checks.record(VerifyCheckKind::ByteRange, br_ok, VerifyFindingCode::InvalidByteRange);
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
                && p.digest_algs == vec![cms::sha256_oid_bytes()]
                && p.signer.digest_alg_oid == cms::sha256_oid_bytes()
        });
    checks.record(VerifyCheckKind::CmsEnvelope, env_ok, VerifyFindingCode::InvalidCms);
    let Some(parsed) = parsed.filter(|_| env_ok) else {
        checks.record(
            VerifyCheckKind::SignedAttributes,
            false,
            VerifyFindingCode::InvalidSignedAttributes,
        );
        checks.record(VerifyCheckKind::ContentDigest, false, VerifyFindingCode::DigestMismatch);
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
    verify_signer(ctx, anchors, checks, &parsed, spans_digest);
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
        let Ok((iss, ser)) = cms::issuer_and_serial(c) else { return false };
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
            cms::sig_alg_oid_matches(a, &signer.signature_alg_oid)
                && !cms::is_denied_alg_oid(&signer.signature_alg_oid)
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
    let ts_gen_time = verify_ts_token(signer, anchors, checks);
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
/// (unix seconds) for applicable-time chain validation.
fn verify_ts_token(
    signer: &cms::ParsedSignerInfo,
    anchors: &[pkix_chain::TrustAnchor],
    checks: &mut Checks,
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
        Ok(gen_time) => {
            checks.record(
                VerifyCheckKind::SignatureTimestamp,
                true,
                VerifyFindingCode::TimestampInvalid,
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
/// the RFC 3161 token over the covered bytes.
fn verify_doc_ts(
    bytes: &[u8],
    e: &SigEntry,
    anchors: &[pkix_chain::TrustAnchor],
    checks: &mut Checks,
    is_last: bool,
) {
    let br_ok = check_byte_range(bytes, e);
    let covers_end = !is_last
        || e
            .byte_range
            .get(2..4)
            .and_then(|v| u64::checked_add(v[0], v[1]))
            .is_some_and(|end| {
                let mut tail = &bytes[usize::try_from(end).unwrap_or(usize::MAX).min(bytes.len())..];
                while let [b'\r' | b'\n', rest @ ..] = tail {
                    tail = rest;
                }
                tail.is_empty()
            });
    let token_ok = unpadded_cms(&e.contents)
        .and_then(|der| {
            let imprint = pdf::hash_byte_range(bytes, e.byte_range).ok()?;
            tsp::validate_token_for_verify(der, &imprint, anchors).ok()
        })
        .is_some();
    checks.record(
        VerifyCheckKind::DocumentTimestamp,
        br_ok && covers_end && token_ok,
        VerifyFindingCode::DocumentTimestampInvalid,
    );
}

/// Validate the DSS revision when the catalog carries `/DSS` (§7.5/§7.7):
/// global arrays only, every entry must parse.
fn verify_dss(doc: &Document, checks: &mut Checks) {
    let Ok(catalog) = doc.catalog() else {
        checks.absent(VerifyCheckKind::ValidationMaterial);
        return;
    };
    let Ok(dss_obj) = catalog.get(b"DSS") else {
        checks.absent(VerifyCheckKind::ValidationMaterial);
        return;
    };
    let dss = doc.dereference(dss_obj).ok().and_then(|(_, o)| o.as_dict().ok());
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
    let ok = dss_array_valid(doc, dss, b"Certs", MaterialKind::Cert)
        && dss_array_valid(doc, dss, b"OCSPs", MaterialKind::Ocsp)
        && dss_array_valid(doc, dss, b"CRLs", MaterialKind::Crl);
    checks.record(
        VerifyCheckKind::ValidationMaterial,
        ok,
        VerifyFindingCode::ValidationMaterialInvalid,
    );
}

enum MaterialKind {
    Cert,
    Ocsp,
    Crl,
}

fn dss_array_valid(doc: &Document, dss: &lopdf::Dictionary, key: &[u8], kind: MaterialKind) -> bool {
    let Ok(arr_obj) = dss.get(key) else {
        return true; // array absent is fine
    };
    let Some(arr) = doc
        .dereference(arr_obj)
        .ok()
        .and_then(|(_, o)| o.as_array().ok())
    else {
        return false;
    };
    if arr.is_empty() && matches!(kind, MaterialKind::Cert) {
        return false; // profile completeness: signer chain certs must be embedded
    }
    arr.iter().all(|item| {
        let data = doc
            .dereference(item)
            .ok()
            .and_then(|(_, o)| o.as_stream().ok().map(|s| s.content.clone()));
        let Some(data) = data else { return false };
        match kind {
            MaterialKind::Cert => der::Decode::from_der(&data)
                .map(|_: x509_cert::Certificate| ())
                .is_ok(),
            MaterialKind::Crl => der::Decode::from_der(&data)
                .map(|_: x509_cert::crl::CertificateList| ())
                .is_ok(),
            MaterialKind::Ocsp => der::Decode::from_der(&data)
                .map(|_: x509_ocsp::OcspResponse| ())
                .is_ok(),
        }
    })
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
    let doc = Document::load_mem_with_options(bytes, options).map_err(|_| {
        SealError::InputInvalid {
            code: InputInvalidCode::MalformedXref,
        }
    })?;
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
    let sigs = collect_signatures(&doc)?;
    let last_idx = sigs.len().saturating_sub(1);
    let mut saw_cades = false;
    for (i, e) in sigs.iter().enumerate() {
        if e.is_doc_ts {
            verify_doc_ts(bytes, e, &anchors, &mut checks, i == last_idx);
        } else {
            saw_cades = true;
            verify_cades_sig(bytes, e, ctx, &anchors, &mut checks);
        }
    }
    if !saw_cades {
        checks.absent(VerifyCheckKind::SignatureTimestamp);
    }
    verify_dss(&doc, &mut checks);
    let valid = saw_cades
        && eof_ok
        && !checks
            .list
            .iter()
            .any(|c| c.status == VerifyCheckStatus::Fail);
    let achieved = classify(&checks, valid);
    Ok(VerifyReport {
        valid,
        achieved_profile: achieved,
        evidence_sha256,
        checks: checks.list,
    })
}

/// Highest achieved baseline profile from the check outcomes.
fn classify(checks: &Checks, valid: bool) -> Option<PadesProfile> {
    if !valid {
        return None;
    }
    let t = checks.passed(VerifyCheckKind::SignatureTimestamp);
    let lt = t && checks.passed(VerifyCheckKind::ValidationMaterial);
    let lta = lt && checks.passed(VerifyCheckKind::DocumentTimestamp);
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
