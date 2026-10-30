//! B-B/B-T/B-LTA orchestration: backend signing, TSA failover, capacity ladder, DocTimeStamp, degrade warnings.

use std::sync::Arc;

use rsa::rand_core::RngCore;

use crate::api::{
    Counter, FetchError, FetchMethod, FetchPurpose, FetchRequest, PadesProfile, PreparedRevision,
    ProfileDegradeReason, SealBackend, SealConfig, SealFetcher, SealResourceLimits, SealWarning,
    Sha256Digest, SignRevisionRequest, SignatureAlgorithm, SigningIdentity,
};
use crate::error::{FatalCode, RetryableCode, SealError, SealStage};

use super::super::{cms, pdf, tsp};
use super::dss::append_dss;
use super::material::{gather_validation_material, trust_anchors};

/// `/Contents` DER capacity ladder in bytes (§7.2 rule 5): the first
/// capacities a revision this engine writes tries. Past the last, a
/// signature or document timestamp the engine writes grows its hole to what
/// its DER needs (Rule 5); the caller's revisions hold the capacities it
/// wrote, and past the largest the caller is told the DER bytes it needs
/// (`observed.contents_bytes`), to write a larger one (FIX 6270).
pub(crate) const CAPACITY_LADDER: [usize; 3] = [64 * 1024, 128 * 1024, 256 * 1024];

/// The capacity to try after `capacity` held too little for `needed` DER
/// bytes: the ladder's next rung, or past the ladder the larger of twice
/// `capacity` and `needed` to the next power of two, so a fresh signature
/// or token a few bytes longer than the last still fits.
fn next_capacity(capacity: usize, needed: usize) -> usize {
    match CAPACITY_LADDER.iter().find(|rung| **rung > capacity) {
        Some(rung) => *rung,
        None => capacity
            .saturating_mul(2)
            .max(needed.checked_next_power_of_two().unwrap_or(usize::MAX)),
    }
}

/// The capacities of the caller's revisions, smallest first: each one's
/// hole, less its delimiters, holds half as many DER bytes as hex digits.
fn supplied_capacities(revisions: &[PreparedRevision<'_>]) -> Vec<usize> {
    let mut capacities: Vec<usize> = revisions
        .iter()
        .filter_map(|revision| {
            let [_, open, close, _] = revision.byte_range;
            let hex = close.checked_sub(open)?.checked_sub(2)?;
            usize::try_from(hex / 2)
                .ok()
                .filter(|_| hex.is_multiple_of(2))
        })
        .collect();
    capacities.sort_unstable();
    capacities.dedup();
    capacities
}

/// What one capacity's attempt came to: the signed revision, or the DER
/// bytes it needed and its hole could not hold.
enum Fit<T> {
    Signed(T),
    Short(usize),
}

/// Everything the profile assembler needs, bundled to keep signatures small.
pub(crate) struct SealContext<'a> {
    pub config: &'a SealConfig,
    /// The config's limits, scoped to this seal's memory ledger: every
    /// parse in the profile reserves under it (FIX 7654).
    pub limits: &'a SealResourceLimits,
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

/// Derived per-attempt operation id: the caller id as the backend sees it
/// (itself, or its bounded alias past the suffix budget, FIX 6271) plus a
/// fixed-shape suffix, so it always fits the backend's
/// [`crate::api::MAX_OPERATION_ID_BYTES`] bound. The engine host binds the
/// same prefix.
pub(crate) fn sub_operation_id(
    operation_id: &str,
    input_sha256: &Sha256Digest,
    phase: &str,
    capacity: usize,
) -> String {
    let operation_id = oneiron_organ_protocol::seal::backend_operation_id(operation_id);
    debug_assert!(
        operation_id.len() + crate::api::OPERATION_ID_SUFFIX_RESERVE
            <= crate::api::MAX_OPERATION_ID_BYTES,
        "backend operation id exceeds the reserved suffix budget"
    );
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

/// Request one signature over a revision's signed attributes from the
/// backend and verify it against the signer certificate before any
/// embedding (§4 seam rules).
async fn request_signature(
    ctx: &SealContext<'_>,
    identity: &SigningIdentity,
    request: SignRevisionRequest,
    signing_input: &[u8],
) -> Result<Vec<u8>, SealError> {
    let signed = ctx
        .backend
        .sign_revision(request)
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
/// that passes every §7.4-step-5 check. A response memory refused is the
/// seal's own resource error, never a reason to try the next authority.
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
        let resp = match response {
            Ok(resp) => resp,
            Err(FetchError::Memory(refusal)) => {
                return Err(refusal.seal_error(SealStage::Timestamp));
            }
            // Denied, unreachable, timed out or invalid: the next authority.
            Err(_) => continue,
        };
        let validated = tsp::validate_response(
            &resp.body,
            imprint,
            &nonce,
            endpoint.expected_policy_oid.as_deref(),
            &anchors,
            ctx.clock_ms,
        );
        if let Ok(token) = validated {
            return Ok(Some(token));
        }
    }
    Ok(None)
}

struct SignedCandidate {
    draft: pdf::DraftRevision,
    token: Option<tsp::ValidatedToken>,
}

/// The caller's revision whose hole holds `capacity` DER bytes, as a draft,
/// with its index. Its hole must be all zeros after the prepared input,
/// and its ByteRange must leave out exactly that hole.
fn supplied_draft(
    input: &[u8],
    revisions: &[PreparedRevision<'_>],
    capacity: usize,
    limits: &SealResourceLimits,
) -> Result<(u32, pdf::DraftRevision), SealError> {
    let invalid = || SealError::Fatal {
        stage: SealStage::PdfIncrementalUpdate,
        code: FatalCode::PdfInvariantFailed,
    };
    let (id, revision) = (0u32..)
        .zip(revisions)
        .find(|(_, revision)| {
            let [_, open, close, _] = revision.byte_range;
            close.checked_sub(open) == Some(2 + 2 * capacity as u64)
        })
        .ok_or_else(invalid)?;
    // The draft is the seal's own copy: reserved before it is made (FIX 8452).
    limits
        .memory
        .admit::<u8>(input.len().saturating_add(revision.suffix.len()))
        .map_err(|refusal| refusal.seal_error(SealStage::PdfIncrementalUpdate))?;
    let bytes = [input, revision.suffix].concat();
    let [start, open, close, rest] = revision.byte_range.map(|at| usize::try_from(at).ok());
    let (open, close, rest) = (open.ok_or_else(invalid)?, close.ok_or_else(invalid)?, rest);
    if start != Some(0)
        || open < input.len()
        || close.checked_add(rest.ok_or_else(invalid)?) != Some(bytes.len())
        || bytes[open] != b'<'
        || bytes[close - 1] != b'>'
        || bytes[open + 1..close - 1].iter().any(|b| *b != b'0')
    {
        return Err(invalid());
    }
    Ok((
        id,
        pdf::DraftRevision {
            bytes,
            contents_gap: Some((open, close - 1)),
            byte_range: Some(revision.byte_range),
        },
    ))
}

/// Build the signature revision at one capacity, returning the DER bytes
/// the CMS needed when it does not fit and the caller must rebuild at a
/// larger capacity. With `revisions`, the caller's revision of that
/// capacity is signed and none is written here.
#[allow(clippy::too_many_arguments)]
async fn try_capacity(
    ctx: &SealContext<'_>,
    prepared: &pdf::PreparedInput,
    revisions: &[PreparedRevision<'_>],
    operation_id: &str,
    input_sha: &Sha256Digest,
    identity: &SigningIdentity,
    target: PadesProfile,
    capacity: usize,
) -> Result<Fit<SignedCandidate>, SealError> {
    let (revision_id, mut draft) = if revisions.is_empty() {
        let kind = pdf::RevisionKind::Signature {
            field_name: pdf::field_name_for(operation_id),
            date_str: pdf::pdf_date(ctx.clock_ms),
        };
        let draft = pdf::append_revision(&prepared.bytes, &prepared.state, &kind, capacity)?;
        charge_draft(ctx.limits, &draft, SealStage::PdfIncrementalUpdate)?;
        (None, draft)
    } else {
        let (id, draft) = supplied_draft(&prepared.bytes, revisions, capacity, ctx.limits)?;
        (Some(id), draft)
    };
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
    let request = SignRevisionRequest {
        operation_id: sub_operation_id(operation_id, input_sha, "sign", capacity),
        revision_id,
        byte_range: br,
        signed_attributes_der: wire.clone(),
        digest: cms::sha256(&signing),
    };
    let signature = request_signature(ctx, identity, request, &signing).await?;
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
    ctx.limits
        .observed
        .note(Counter::ContentsBytes, cms_der.len());
    match pdf::patch_contents(&mut draft, &cms_der) {
        Ok(()) => Ok(Fit::Signed(SignedCandidate { draft, token })),
        Err(SealError::Fatal {
            code: FatalCode::ContentsCapacityExceeded,
            ..
        }) => Ok(Fit::Short(cms_der.len())),
        Err(e) => Err(e),
    }
}

/// Charges a draft the seal wrote to its operation as it is built (FIX
/// 8452): the draft holds a whole copy of the PDF it extends.
pub(super) fn charge_draft(
    limits: &SealResourceLimits,
    draft: &pdf::DraftRevision,
    stage: SealStage,
) -> Result<(), SealError> {
    limits
        .memory
        .admit::<u8>(draft.bytes.capacity())
        .map_err(|refusal| refusal.seal_error(stage))
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

/// Append the DocTimeStamp revision for B-LTA (§7.6). `Ok(None)` means the
/// archival timestamp could not be produced; caller degrades to B-LT. The
/// engine writes this revision, so past the ladder its hole grows to the
/// token's size and a fresh token is fetched for it (Rule 5).
async fn append_doc_timestamp(
    bytes: &[u8],
    ctx: &SealContext<'_>,
) -> Result<Option<Vec<u8>>, SealError> {
    let mut capacity = CAPACITY_LADDER[0];
    loop {
        let state = pdf::reparse_revision(bytes, ctx.limits)?;
        let mut draft = pdf::append_revision(
            bytes,
            &state,
            &pdf::RevisionKind::DocumentTimestamp,
            capacity,
        )?;
        charge_draft(ctx.limits, &draft, SealStage::DocumentTimestamp)?;
        let br = draft.byte_range.ok_or(SealError::Fatal {
            stage: SealStage::DocumentTimestamp,
            code: FatalCode::PdfInvariantFailed,
        })?;
        let imprint = pdf::hash_byte_range(&draft.bytes, br)?;
        let Some(token) = fetch_timestamp_token(ctx, &imprint).await? else {
            return Ok(None);
        };
        let needed = token.content_info_der.len();
        ctx.limits.observed.note(Counter::ContentsBytes, needed);
        match pdf::patch_contents(&mut draft, &token.content_info_der) {
            Ok(()) => return Ok(Some(draft.bytes)),
            Err(SealError::Fatal {
                code: FatalCode::ContentsCapacityExceeded,
                ..
            }) => {
                capacity = next_capacity(capacity, needed);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Full profile assembly (§7). Always produces at least B-B or an error;
/// higher profiles degrade with structured warnings. With `revisions`, the
/// ordinary signature goes into one of the caller's revisions.
pub(crate) async fn assemble(
    ctx: &SealContext<'_>,
    prepared: &pdf::PreparedInput,
    revisions: &[PreparedRevision<'_>],
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
    // Each capacity is a fresh revision, signed once under its own derived
    // operation id. A revision this engine writes grows past the ladder; the
    // caller's revisions are tried smallest first, and past the largest the
    // DER bytes needed are in the call's counts for the caller to write a
    // larger one (FIX 6270).
    let supplied = supplied_capacities(revisions);
    let mut capacity = supplied.first().copied().unwrap_or(CAPACITY_LADDER[0]);
    let SignedCandidate { draft, token } = loop {
        match try_capacity(
            ctx,
            prepared,
            revisions,
            operation_id,
            &input_sha,
            &identity,
            target,
            capacity,
        )
        .await?
        {
            Fit::Signed(candidate) => break candidate,
            Fit::Short(needed) if revisions.is_empty() => {
                capacity = next_capacity(capacity, needed);
            }
            Fit::Short(_) => {
                capacity = supplied
                    .iter()
                    .copied()
                    .find(|supplied| *supplied > capacity)
                    .ok_or(SealError::Fatal {
                        stage: SealStage::PdfIncrementalUpdate,
                        code: FatalCode::ContentsCapacityExceeded,
                    })?;
            }
        }
    };
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
        match gather_validation_material(ctx, &identity, token.as_ref()).await? {
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
    // The output grows by whatever its validation material and timestamps
    // need (Rule 5): the host measures that growth against its `[limits]`
    // row. The one refusal left is the format bound: the sealer never emits
    // a document past lopdf's u32 offsets, which the verifier (and every
    // later reader here) could not parse. Both read the same bound.
    if bytes.len() > ctx.limits.max_input_bytes {
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
