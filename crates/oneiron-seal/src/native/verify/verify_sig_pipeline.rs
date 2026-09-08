//! Signature discovery and evaluation: AcroForm collection plus CAdES signer, signature-timestamp and DocTimeStamp checks with Checks recording.

use lopdf::{Document, Object};

use crate::api::{
    Sha256Digest, VerifyCheck, VerifyCheckKind, VerifyCheckStatus, VerifyFindingCode,
};
use crate::error::SealError;

use super::super::{cms, pdf, tsp};
use super::verify_chain_gates::{VerifyCtx, malformed_input, validate_chain};
use super::verify_dss_core::EmbeddedCert;
use super::verify_revocation::gen_time_beyond_skew;

#[derive(Debug)]
pub(super) struct SigEntry {
    pub(super) is_doc_ts: bool,
    pub(super) byte_range: [u64; 4],
    /// Decoded `/Contents` bytes (DER CMS followed by zero padding).
    pub(super) contents: Vec<u8>,
}

fn name_eq(obj: &Object, expected: &[u8]) -> bool {
    matches!(obj, Object::Name(n) if n == expected)
}

/// Total nodes one AcroForm field-tree descent may visit. Real signature
/// hierarchies are a handful of nodes deep; past this the tree is hostile
/// (or corrupt) and discovery fails closed rather than burning work. The
/// cycle guard alone bounds a self-referential `/Kids`, but a legal,
/// acyclic, extremely wide tree still deserves a ceiling.
const MAX_FIELD_TREE_WORK: usize = 16_384;

/// Collect signature/timestamp dictionaries in revision order (earlier
/// revisions cover fewer bytes). Discovery is by REACHABILITY: only
/// dictionaries named by the `/V` of a signature field in the catalog's
/// `/AcroForm` field TREE are evaluated — the walk descends `/Kids` and
/// carries the inheritable `/FT` down, so a terminal signature field nested
/// under a non-terminal parent is reached (ISO 32000 §12.7.3.2; the shape
/// honest PAdES writers emit). A reachable field-`/V` candidate is then
/// checked by
/// `/Type /Sig|DocTimeStamp` AND by the typeless interop shape (real-world
/// signers omit the optional `/Type`). Typeless candidacy requires
/// `/ByteRange`: dictionaries without it are never candidates, whatever
/// `/Contents` holds — an ordinary `/Page` dictionary carries `/Contents`
/// for its page content stream. A `/ByteRange` without `/Contents` is a
/// partial signature shape: malformed input, never a silent skip.
///
/// An orphaned signature-shaped dictionary (well-formed but unreferenced
/// from `/Fields`) is NEVER evaluated: the malformed checks must bind the
/// verdict only to bytes the verifier actually reaches — a hostile document
/// must not wedge an honest document's verification by carrying
/// never-referenced malformed signature-shaped baggage. A document whose
/// only signature shape is orphan-bound is left with no evaluable CAdES
/// signature and fails verification; a dangling or non-dictionary `/V`
/// (partial field shape) is malformed input, never a silent skip.
///
/// When the catalog carries no `/AcroForm` at all, or the `/AcroForm` holds
/// no `/Fields`, the document contains no reachable signature field: no
/// candidates, no evaluation. A PRESENT `/AcroForm` that does not resolve
/// to a dictionary, or whose `/Fields` does not resolve to an array, is
/// malformed input (a hostile catalog must not dodge the malformed verdict
/// by hiding broken form state); both dereferences are bounded and
/// fail-closed through lopdf's chain limit.
///
/// `/SubFilter` dispatch (fail-closed): a candidate is evaluated ONLY under
/// the handler its `/SubFilter` names — `/Sig` requires
/// `/ETSI.CAdES.detached`, `/DocTimeStamp` requires `/ETSI.RFC3161`. A typed
/// dictionary with an absent or foreign `/SubFilter` (e.g.
/// `/adbe.pkcs7.detached`) is SKIPPED, never evaluated as CAdES; a document
/// left with no evaluable CAdES signature fails verification. The typeless
/// interop path tolerates an ABSENT `/SubFilter` (that is the shape it
/// exists for) but a PRESENT one must still name the CAdES handler. The
/// interop allowance itself is gated on an ABSENT `/Type`: a present
/// `/Type` naming neither handler — or not even a name — is skipped, never
/// laundered into CAdES candidacy through the typeless path.
pub(super) fn collect_signatures(doc: &Document) -> Result<Vec<SigEntry>, SealError> {
    let mut out = Vec::new();
    let catalog = doc.catalog().map_err(|_| malformed_input())?;
    let Ok(af_obj) = catalog.get(b"AcroForm") else {
        return Ok(out);
    };
    let af = doc
        .dereference(af_obj)
        .map_err(|_| malformed_input())?
        .1
        .as_dict()
        .map_err(|_| malformed_input())?;
    let Ok(fields_obj) = af.get(b"Fields") else {
        return Ok(out);
    };
    let fields = doc
        .dereference(fields_obj)
        .map_err(|_| malformed_input())?
        .1
        .as_array()
        .map_err(|_| malformed_input())?;
    // ISO 32000 §12.7.3.2: AcroForm fields form a TREE — a non-terminal
    // field carries `/Kids`, and `/FT` is INHERITABLE, so a terminal
    // signature field may carry only `/T` and `/V` with its `/FT` living on
    // an ancestor. Honest PAdES writers emit exactly that shape, so a flat
    // read of `/Fields` would treat a nested signature as unreachable and
    // fail an honest document. `/V` is never inherited: each terminal field
    // carries its own or is legally unfilled.
    //
    // The descent is bounded on both axes and fail-closed: `visited` stops a
    // hostile `/Kids` cycle (self-loop or mutual) from spinning, and
    // `MAX_FIELD_TREE_WORK` caps total nodes so a wide-and-deep tree cannot
    // burn unbounded work. Every dereference stays bounded by lopdf's chain
    // limit and maps a failure to malformed input, exactly as the flat walk
    // did. Orphan carve-out unchanged: a signature-shaped object NOT reached
    // through this tree is never evaluated.
    let mut visited: std::collections::BTreeSet<lopdf::ObjectId> =
        std::collections::BTreeSet::new();
    let mut work = 0usize;
    let mut stack: Vec<(&Object, bool)> = Vec::new();
    for field in fields.iter().rev() {
        stack.push((field, false));
    }
    while let Some((node, inherited_sig_ft)) = stack.pop() {
        work = work.checked_add(1).ok_or_else(malformed_input)?;
        if work > MAX_FIELD_TREE_WORK {
            return Err(malformed_input());
        }
        let (node_id, node_obj) = doc.dereference(node).map_err(|_| malformed_input())?;
        // A field reached twice (shared kid, or a /Kids cycle) is walked
        // once: re-walking cannot discover a new signature, and refusing to
        // recurse is what makes a cycle terminate.
        if let Some(id) = node_id
            && !visited.insert(id)
        {
            continue;
        }
        let field = node_obj.as_dict().map_err(|_| malformed_input())?;
        // /FT is inheritable: a node's own /FT overrides, otherwise the
        // ancestor's verdict carries down.
        let is_sig_ft = match field.get(b"FT") {
            Ok(ft) => name_eq(ft, b"Sig"),
            Err(_) => inherited_sig_ft,
        };
        // Descend /Kids whenever present. A node's /Kids may hold CHILD
        // FIELDS (the nesting this walk exists to reach) or, on a terminal
        // field, its WIDGET annotations — ISO 32000 §12.7.3.1 permits both,
        // and this crate's own writer emits the merged shape (`/FT /Sig /T
        // ... /V n 0 R /Kids [widget]`). So descent and /V evaluation are
        // NOT exclusive: a widget kid carries neither /FT nor /V and simply
        // contributes nothing, while a child field is reached either way.
        if let Ok(kids_obj) = field.get(b"Kids") {
            let kids = doc
                .dereference(kids_obj)
                .map_err(|_| malformed_input())?
                .1
                .as_array()
                .map_err(|_| malformed_input())?;
            for kid in kids.iter().rev() {
                stack.push((kid, is_sig_ft));
            }
        }
        // Signature-discovery looks only at SIGNATURE fields (/FT /Sig,
        // own or inherited): a text/choice/button field carries an ordinary
        // value /V (a draft string, an option index), never a signature
        // dictionary, and must not trip the malformed gates below.
        if !is_sig_ft {
            continue;
        }
        let Ok(v) = field.get(b"V") else {
            // An unfilled signature field (absent /V) is a legal AcroForm
            // shape, never evaluated.
            continue;
        };
        let Object::Dictionary(d) = doc.dereference(v).map_err(|_| malformed_input())?.1 else {
            return Err(malformed_input());
        };
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
            // A PRESENT /Type naming neither handler (or not a name at all)
            // is never a candidate: the typeless interop allowance exists
            // only for an ABSENT /Type.
            Ok(_) => continue,
            Err(_) if !d.has(b"ByteRange") => continue,
            Err(_) => {
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

pub(super) struct Checks {
    pub(super) list: Vec<VerifyCheck>,
}

impl Checks {
    pub(super) fn new() -> Self {
        Self { list: Vec::new() }
    }

    pub(super) fn record(&mut self, kind: VerifyCheckKind, ok: bool, finding: VerifyFindingCode) {
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

    pub(super) fn absent(&mut self, kind: VerifyCheckKind) {
        self.list.push(VerifyCheck {
            kind,
            status: VerifyCheckStatus::AbsentAllowed,
            finding: None,
        });
    }

    pub(super) fn passed(&self, kind: VerifyCheckKind) -> bool {
        self.list
            .iter()
            .any(|c| c.kind == kind && c.status == VerifyCheckStatus::Pass)
    }
}

/// PDF white-space (ISO 32000-1 Table 1): legal inside hex strings.
fn is_pdf_whitespace(b: u8) -> bool {
    matches!(b, 0x00 | 0x09 | 0x0A | 0x0C | 0x0D | 0x20)
}

/// Defense-in-depth cap on the post-whitespace-strip decoded `/Contents`:
/// the decoded bytes live inside the document that carries them, so a
/// decoded count larger than the input file is structurally impossible.
/// Checked separately from the hex-digit count so a future reordering of
/// `check_byte_range`'s clauses cannot silently admit an oversized claim.
pub(super) fn decoded_contents_within_input(decoded_len: usize, input_len: usize) -> bool {
    decoded_len <= input_len
}

/// ByteRange shape, bounds, non-overlap, and exact `/Contents` exclusion.
pub(super) fn check_byte_range(bytes: &[u8], e: &SigEntry) -> bool {
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
    // botfix7 P3: enforce the bytes cap on the decoded /Contents (defense
    // in depth) after the whitespace strip has measured the digit count.
    if !decoded_contents_within_input(e.contents.len(), bytes.len()) {
        return false;
    }
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
pub(super) fn verify_cades_sig(
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
pub(super) fn verify_doc_ts(
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
