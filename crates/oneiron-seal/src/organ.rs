//! The seal organ: `seal.pdf` (schema 2) and `seal.verify`, `seal.inspect`
//! and `seal.prepare` (schema 1), run as its own process behind the organ
//! host (ARCH-0064 section 7, ARCH-0075 `#organ-host-design-seal-move` and
//! `#organ-host-design-seal-binding`).
//!
//! The engine prepares the PDF, writes its ordinary signature revision for
//! each contents capacity, and lends both; it keeps the signing key. The
//! organ builds only the CMS for one of those revisions, then any validation
//! data and document timestamp after it. It asks the engine back, protocol
//! 1.1, for the signing identity (`seal.identity`), for the signature over
//! the revision's signed attributes (`seal.sign`), and for every timestamp
//! and CRL/OCSP fetch (`net.fetch`, inside the allowlist the install grant
//! names). Each verb asks it for the memory its PDF decodes and its
//! fetched bytes take, before they allocate it (`memory.grow`, FIX 7654):
//! the engine's host leases it from the machine's memory floor and holds it
//! until the call ends. Its clock is the engine's `now_ms` plus the time
//! since the call began.
//!
//! Args, MessagePack with named fields:
//! - `seal.pdf`: `{operation_id, profile, now_ms, config,
//!   signature_revisions: [{id, suffix_offset, suffix_len, byte_range}]}`,
//!   two inputs: the `application/pdf` prepared PDF, then the revisions'
//!   suffixes one after another as `application/octet-stream`. Revision
//!   `id` is the PDF followed by its suffix.
//! - `seal.verify`: `{now_ms, config}`, one `application/pdf` input. It
//!   asks only for memory: never a signature or a fetch.
//! - `seal.inspect`: `{}`, one `application/pdf` input. It asks only for
//!   memory: never a signature or a fetch.
//! - `seal.prepare`: `{document_ref, item, canonical_url, artifact_ref,
//!   original_version, title, audit_rows, rejection?, recipients,
//!   signatures, fields, values, raster_index, chain, trail}`, two inputs:
//!   the `application/pdf` original, then the signature rasters one after
//!   another as `application/octet-stream`. It asks only for memory: never
//!   a signature or a fetch.
//! - `config`: `{trust_anchors: [bin], timestamp_authorities: [{url,
//!   policy_oid?}]}`. The seal's only size limits are format bounds, its
//!   own (`SealResourceLimits::default`); nothing on size is configured.
//!
//! Reports: `{sealed: {evidence_sha256, requested, achieved, degraded,
//! self_verify}}` with the output `sealed.pdf`, `{verified: verdict}`,
//! `{inspected: {pages}}`, `{prepared: {original_sha256,
//! audit_chain_sha256, original_pages, appendix_pages}}` with the output
//! `prepared.pdf`, or `{failed: <seal error>}`. A verdict is `{verdict,
//! reasons, achieved,
//! self_verify_ok, report_json, classification}`, the classification the
//! native verification's revision chain (the `report` child); the error
//! names the seal's own stage and code.
//! Beside the outcome every report carries `observed`, what the native
//! analysis counted (`SealObserved`), on a failure too: the engine measures
//! each count against its `[limits]` row before it reads the outcome.

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::Instant;

use async_trait::async_trait;
use oneiron_organ_protocol::{
    ASK_MEMORY_GROW, ASK_NET_FETCH, Answer, AnswerMemory, AskCode, AskRefusal, AskReply, Asker,
    ByteBuf, CallContext, ErrorCode, FetchAnswer, FetchAsk, MemoryAnswer, MemoryAsk, Organ,
    OrganError, OrganIdentity, OutputBytes, Value, VerbSpec, read_cost,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::api::{
    BackendError, BackendRejectCode, BackendSignature, FetchError, FetchMethod, FetchPolicy,
    FetchPurpose, FetchRequest, FetchResponse, PadesProfile, PdfSealEngine, PreparedRevision,
    ProfileDegradeReason, SealBackend, SealClock, SealConfig, SealFetcher, SealObservations,
    SealRequest, SealResourceLimits, SealWarning, SignDigestRequest, SignRevisionRequest,
    SignatureAlgorithm, SigningIdentity, TsaEndpoint,
};
use crate::error::{FatalCode, InputInvalidCode, RetryableCode, SealError, SealStage};
use crate::memory::{
    AdmittedBytes, AdmittedStr, MemoryLedger, SealMemory, SealMemoryProvider,
    SealMemoryRefusal,
};
use crate::native::NativeSealEngine;
use crate::native::pdf::{
    BurnField, BurnValue, FieldGeometry, WorkError, WorkLimits, WorkPrepareRequest, WorkRaster,
    WorkRecipient, WorkSignature, inspect_in, prepare_in,
};

mod report;

use self::report::Verdict;

pub const VERB_SEAL: &str = "seal.pdf";
pub const VERB_VERIFY: &str = "seal.verify";
pub const VERB_INSPECT: &str = "seal.inspect";
pub const VERB_PREPARE: &str = "seal.prepare";
/// `seal.pdf`'s schema: the engine's revisions, lent beside the PDF.
pub const SEAL_SCHEMA: u32 = 2;
pub const INSPECT_SCHEMA: u32 = 1;
pub const PREPARE_SCHEMA: u32 = 1;
/// Ask: the signing identity, `{}` → `{algorithm, signer_certificate,
/// chain}`.
pub const ASK_IDENTITY: &str = "seal.identity";
/// Ask: one signature, `{operation_id, revision_id, byte_range,
/// signed_attributes_der}` → `{signature}`. The engine hashes the
/// revision's ByteRange and the attributes itself.
pub const ASK_SIGN: &str = "seal.sign";
/// The media type of the lent revision suffixes.
pub const REVISIONS: &str = "application/octet-stream";
/// The name of the sealed output.
pub const SEALED_OUTPUT: &str = "sealed.pdf";
/// The report JSON a verdict carries past which the engine's `[limits]`
/// row asks (`seal_report_json_bytes`). Every report is carried whole,
/// however many signatures it names (Rule 5), across as many reply frames
/// as it takes.
pub const MAX_REPORT_JSON_BYTES: usize = 8 * 1024 * 1024;
const PDF: &str = "application/pdf";

/// The seal organ. It holds nothing between calls.
#[derive(Debug, Clone, Copy, Default)]
pub struct SealOrgan;

impl Organ for SealOrgan {
    fn identity(&self) -> OrganIdentity {
        OrganIdentity {
            name: "seal".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    fn verbs(&self) -> Vec<VerbSpec> {
        [
            (VERB_SEAL, SEAL_SCHEMA),
            (VERB_VERIFY, 1),
            (VERB_INSPECT, INSPECT_SCHEMA),
            (VERB_PREPARE, PREPARE_SCHEMA),
        ]
        .into_iter()
        .map(|(name, schema)| VerbSpec {
            name: name.to_owned(),
            schema,
            kinds: Vec::new(),
        })
        .collect()
    }

    fn call(&self, call: &CallContext<'_>) -> Result<Answer, OrganError> {
        let began = Instant::now();
        match call.verb {
            VERB_SEAL => seal(call, began),
            VERB_VERIFY => verify(call, began),
            VERB_INSPECT => inspect(call, began),
            VERB_PREPARE => prepare(call, began),
            other => Err(OrganError::new(
                ErrorCode::UnknownVerb,
                format!("no verb {other}"),
            )),
        }
    }
}

#[derive(Deserialize)]
struct SealArgs {
    operation_id: String,
    profile: PadesProfile,
    now_ms: u64,
    config: ConfigArgs,
    signature_revisions: Vec<RevisionArgs>,
}

/// One of the engine's revisions: its suffix in the second input.
#[derive(Deserialize)]
struct RevisionArgs {
    id: u32,
    suffix_offset: u64,
    suffix_len: u64,
    byte_range: [u64; 4],
}

#[derive(Deserialize)]
struct VerifyArgs {
    now_ms: u64,
    config: ConfigArgs,
}

#[derive(Deserialize)]
struct ConfigArgs {
    trust_anchors: Vec<ByteBuf>,
    #[serde(default)]
    timestamp_authorities: Vec<TsaArgs>,
}

#[derive(Deserialize)]
struct TsaArgs {
    url: String,
    #[serde(default)]
    policy_oid: Option<String>,
}

/// `seal.inspect` carries the caller's existing per-stream codec bound.
/// PDF work needs no trust anchors.
#[derive(Deserialize)]
struct InspectArgs {
    stream_decode_bytes: u64,
}

/// `seal.prepare` args (schema 1): the host's projection of the engine's
/// preparation, lent scalars the ported pipeline takes as-is. The organ's
/// own mirror of the host's `PrepareArgs`: no `H/` type crosses the
/// process boundary.
#[derive(Deserialize)]
struct PrepareArgs {
    document_ref: String,
    item: u32,
    canonical_url: String,
    artifact_ref: String,
    original_version: u64,
    title: String,
    audit_rows: usize,
    rejection: Option<String>,
    recipients: Vec<WireRecipient>,
    signatures: Vec<WireSignature>,
    fields: Vec<WireField>,
    values: std::collections::BTreeMap<String, WireValue>,
    raster_index: Vec<RasterEntry>,
    chain: ByteBuf,
    trail: Vec<String>,
}

#[derive(Deserialize)]
struct WireRecipient {
    id: String,
    name: String,
    email: String,
    natural_person: Option<String>,
}

#[derive(Deserialize)]
struct WireSignature {
    field: String,
    recipient: String,
    at: u64,
}

#[derive(Deserialize)]
struct WireField {
    id: String,
    geometry: WireGeometry,
}

#[derive(Deserialize)]
struct WireGeometry {
    page: u32,
    x_percent: f64,
    y_percent: f64,
    width_percent: f64,
    height_percent: f64,
}

/// The engine's `FieldValue` row, adjacently tagged exactly like it, as the
/// host sent it.
#[derive(Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum WireValue {
    Text(String),
    Checked(bool),
    Signature { image_ref: String },
}

/// One raster's slice of the lent rasters blob: offsets into it.
#[derive(Deserialize)]
struct RasterEntry {
    image_ref: String,
    width: u32,
    height: u32,
    offset: u64,
    len: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum SealReport {
    Sealed {
        evidence_sha256: ByteBuf,
        requested: PadesProfile,
        achieved: PadesProfile,
        degraded: Vec<Degrade>,
        self_verify: Verdict,
    },
    Failed(Failure),
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum VerifyReply {
    Verified(Verdict),
    Failed(Failure),
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum InspectReply {
    Inspected { pages: Vec<WirePage> },
    Failed(Failure),
}

/// One page's geometry, as the port's `PageGeometry`.
#[derive(Serialize)]
struct WirePage {
    crop: [f64; 4],
    rotation: u16,
    user_unit: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum PrepareReply {
    Prepared {
        original_sha256: ByteBuf,
        audit_chain_sha256: ByteBuf,
        original_pages: u32,
        appendix_pages: u32,
    },
    Failed(Failure),
}

#[derive(Serialize)]
struct Degrade {
    requested: PadesProfile,
    achieved: PadesProfile,
    reason: ProfileDegradeReason,
}

/// [`SealError`], as the engine's adapter reads it.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Failure {
    Retryable {
        stage: SealStage,
        code: RetryableCode,
        retry_after_ms: Option<u64>,
    },
    Fatal {
        stage: SealStage,
        code: FatalCode,
    },
    VerifyFailed {
        verdict: Box<Verdict>,
    },
    BackendUnavailable {
        retry_after_ms: Option<u64>,
    },
    InputInvalid {
        code: InputInvalidCode,
    },
    /// The engine's revisions held too little: the CMS needed `needed` DER
    /// bytes, for the engine to write a larger revision (FIX 6270).
    ContentsShort {
        needed: u64,
    },
}

impl Failure {
    /// The seal's error; a failed verification's verdict is of `pdf`, when
    /// this side holds the bytes it verified.
    fn of(err: SealError, pdf: Option<&[u8]>, memory: &ReplyMemory) -> Result<Self, OrganError> {
        Ok(match err {
            SealError::Retryable {
                stage,
                code,
                retry_after_ms,
            } => Self::Retryable {
                stage,
                code,
                retry_after_ms,
            },
            SealError::Fatal { stage, code } => Self::Fatal { stage, code },
            SealError::VerifyFailed { report } => Self::VerifyFailed {
                verdict: Box::new(Verdict::of(&report, pdf, &|bytes| memory.reserve(bytes))?),
            },
            SealError::BackendUnavailable { retry_after_ms } => {
                Self::BackendUnavailable { retry_after_ms }
            }
            SealError::InputInvalid { code } => Self::InputInvalid { code },
        })
    }
}

fn seal(call: &CallContext<'_>, began: Instant) -> Result<Answer, OrganError> {
    if call.schema != SEAL_SCHEMA {
        return Err(bad("seal.pdf is schema 2"));
    }
    let memory = ReplyMemory(call.asker());
    let args: SealArgs = memory.args(call.args, "seal args")?;
    let (pdf, suffixes) = match call.inputs {
        [pdf, suffixes] if pdf.media_type == PDF && suffixes.media_type == REVISIONS => {
            (&pdf[..], &suffixes[..])
        }
        _ => return Err(bad("an application/pdf input, then the revisions")),
    };
    let revisions = (0u32..)
        .zip(&args.signature_revisions)
        .map(|(id, revision)| {
            let start = usize::try_from(revision.suffix_offset).ok();
            let len = usize::try_from(revision.suffix_len).ok();
            let suffix = start
                .zip(len)
                .and_then(|(start, len)| suffixes.get(start..start.checked_add(len)?))
                .filter(|_| revision.id == id)
                .ok_or_else(|| bad("a revision outside its input"))?;
            Ok(PreparedRevision {
                suffix,
                byte_range: revision.byte_range,
            })
        })
        .collect::<Result<Vec<_>, OrganError>>()?;
    let (observed, engine) = engine(args.config, args.now_ms, began, call.asker())?;
    let failed = |err: SealError| -> Result<Answer, OrganError> {
        let failure = match err {
            // Past the largest revision the engine wrote, the DER bytes the
            // CMS needed are the call's own count (FIX 6270).
            SealError::Fatal {
                stage: SealStage::PdfIncrementalUpdate,
                code: FatalCode::ContentsCapacityExceeded,
            } => Failure::ContentsShort {
                needed: observed.observed().contents_bytes,
            },
            err => Failure::of(err, None, &memory)?,
        };
        report(&SealReport::Failed(failure), &observed, &memory)
    };
    let engine = match engine {
        Ok(engine) => engine,
        Err(err) => return failed(err),
    };
    let request = SealRequest {
        operation_id: args.operation_id,
        target_profile: args.profile,
    };
    let sealed = match block_on(engine.seal_pdf_in_revisions(pdf, &request, &revisions)) {
        Ok(sealed) => sealed,
        Err(err) => return failed(err),
    };
    let degraded = sealed
        .warnings
        .into_iter()
        .map(|warning| match warning {
            SealWarning::ProfileDegraded {
                requested,
                achieved,
                reason,
            } => Degrade {
                requested,
                achieved,
                reason,
            },
        })
        .collect();
    // A shared output buffer is copied for the reply, so its bytes ride
    // this call's reply reservation first; a sole owner's buffer moves
    // without copying (FIX 8452).
    if Arc::strong_count(&sealed.bytes) != 1 {
        memory.reserve(sealed.bytes.len() as u64)?;
    }
    let mut answer = report(
        &SealReport::Sealed {
            evidence_sha256: ByteBuf::from(sealed.evidence_sha256.to_vec()),
            requested: sealed.requested_profile,
            achieved: sealed.achieved_profile,
            degraded,
            self_verify: Verdict::of(&sealed.self_verify_report, Some(&sealed.bytes), &|bytes| {
                memory.reserve(bytes)
            })?,
        },
        &observed,
        &memory,
    )?;
    answer.outputs.push(OutputBytes {
        name: SEALED_OUTPUT.to_owned(),
        media_type: PDF.to_owned(),
        bytes: crate::memory::AdmittedBytes::into_vec(sealed.bytes),
    });
    Ok(answer)
}

fn verify(call: &CallContext<'_>, began: Instant) -> Result<Answer, OrganError> {
    let memory = ReplyMemory(call.asker());
    let args: VerifyArgs = memory.args(call.args, "verify args")?;
    let pdf = the_pdf(call)?;
    // Verification asks only for memory: its host gives it no signing or
    // fetch handler.
    let (observed, engine) = engine(args.config, args.now_ms, began, call.asker())?;
    let checked = engine.and_then(|engine| engine.verify_sealed_pdf(pdf));
    let reserve = |bytes| memory.reserve(bytes);
    match checked {
        Ok(checked) => report(
            &VerifyReply::Verified(Verdict::of(&checked, Some(pdf), &reserve)?),
            &observed,
            &memory,
        ),
        Err(err) => report(
            &VerifyReply::Failed(Failure::of(err, Some(pdf), &memory)?),
            &observed,
            &memory,
        ),
    }
}

/// The ported pipeline's limits: this call's operation ledger, which bills
/// `asker` through `memory.grow` like seal/verify, and its counts. The
/// ledger was opened from this asker; the parameter pins the call site to
/// it.
fn work_limits<'a>(
    asker: &Asker,
    observed: &'a SealObservations,
    ledger: &'a Arc<MemoryLedger>,
) -> WorkLimits<'a> {
    let _ = asker;
    WorkLimits {
        ledger,
        observed,
        stream_decode_bytes: None,
    }
}

/// The call's operation ledger and counts for the ported pipeline: the
/// same `AskedMemory`/`CallAsks` ask path as seal/verify, so the pdf
/// decodes reserve via `memory.grow`; a fresh count sink per call, read by
/// the report.
fn pdf_work_operation(asker: Asker) -> Result<(SealResourceLimits, Arc<MemoryLedger>), OrganError> {
    let asks = Arc::new(CallAsks { asker });
    let provider = SealMemoryProvider::new(Arc::new(AskedMemory { asks }));
    let mut resource = SealResourceLimits::default();
    resource.memory = provider;
    let operation = resource
        .operation(SealStage::InputValidation)
        .map_err(|err| OrganError::new(ErrorCode::Internal, format!("pdf work memory: {err}")))?;
    let ledger = operation.memory.ledger().map_err(|refusal| {
        OrganError::new(ErrorCode::Internal, format!("pdf work ledger: {refusal}"))
    })?;
    Ok((operation, ledger))
}

fn inspect(call: &CallContext<'_>, began: Instant) -> Result<Answer, OrganError> {
    let _ = began;
    if call.schema != INSPECT_SCHEMA {
        return Err(bad("seal.inspect is schema 1"));
    }
    let memory = ReplyMemory(call.asker());
    let args: InspectArgs = memory.args(call.args, "inspect args")?;
    let pdf = the_pdf(call)?;
    let asker = call.asker();
    let (operation, ledger) = pdf_work_operation(asker.clone())?;
    let mut limits = work_limits(&asker, &operation.observed, &ledger);
    limits.stream_decode_bytes =
        Some(usize::try_from(args.stream_decode_bytes).unwrap_or(usize::MAX));
    let failed = |err: SealError| -> Result<Answer, OrganError> {
        let failure = InspectReply::Failed(Failure::of(err, Some(pdf), &memory)?);
        report(&failure, &operation.observed, &memory)
    };
    match inspect_in(pdf, &limits) {
        Ok(pages) => {
            if let Err(refusal) = ledger.admit_len::<WirePage>(pages.len()) {
                return failed(refusal.seal_error(SealStage::InputValidation));
            }
            let pages = pages
                .into_iter()
                .map(|page| WirePage {
                    crop: page.crop,
                    rotation: page.rotation,
                    user_unit: page.user_unit,
                })
                .collect::<Vec<_>>();
            report(
                &InspectReply::Inspected { pages },
                &operation.observed,
                &memory,
            )
        }
        Err(err) => failed(err.seal_error(SealStage::InputValidation)),
    }
}

fn prepare(call: &CallContext<'_>, began: Instant) -> Result<Answer, OrganError> {
    let _ = began;
    if call.schema != PREPARE_SCHEMA {
        return Err(bad("seal.prepare is schema 1"));
    }
    let memory = ReplyMemory(call.asker());
    let args: PrepareArgs = memory.args(call.args, "prepare args")?;
    let (pdf, raster_blob) = match call.inputs {
        [pdf, rasters] if pdf.media_type == PDF && rasters.media_type == REVISIONS => {
            (&pdf[..], &rasters[..])
        }
        _ => return Err(bad("an application/pdf input, then the rasters")),
    };
    let asker = call.asker();
    let (operation, ledger) = pdf_work_operation(asker.clone())?;
    let limits = work_limits(&asker, &operation.observed, &ledger);
    let failed = |err: SealError| -> Result<Answer, OrganError> {
        let failure = PrepareReply::Failed(Failure::of(err, Some(pdf), &memory)?);
        report(&failure, &operation.observed, &memory)
    };
    // A ledger refusal as the seal's error, at the write-phase stage, like
    // the pipeline's own.
    let admit = |result: Result<(), SealMemoryRefusal>| -> Result<(), SealError> {
        result.map_err(|refusal| refusal.seal_error(SealStage::PdfIncrementalUpdate))
    };
    // The wire scalars projected onto the port's lent request: borrowed
    // where the args already own the bytes, cloned and admitted where the
    // port owns them. One map entry's share plus the cloned key's heap
    // bytes each (pattern `work_burn.rs:465-467`).
    let entry_share = |key: usize, value: usize| {
        (11 * (key + value) + 12 * std::mem::size_of::<usize>() + 64).div_ceil(5)
    };
    let value_share = entry_share(
        std::mem::size_of::<String>(),
        std::mem::size_of::<BurnValue>(),
    );
    let mut values = std::collections::BTreeMap::new();
    for (id, value) in &args.values {
        let heap = match value {
            WireValue::Text(text) => text.len(),
            WireValue::Checked(_) => 0,
            WireValue::Signature { image_ref } => image_ref.len(),
        };
        if let Err(err) =
            admit(ledger.admit_len::<u8>(value_share.saturating_add(id.len()).saturating_add(heap)))
        {
            return failed(err);
        }
        let burned = match value {
            WireValue::Text(text) => BurnValue::Text(text.clone()),
            WireValue::Checked(checked) => BurnValue::Checked(*checked),
            WireValue::Signature { image_ref } => BurnValue::Signature {
                image_ref: image_ref.clone(),
            },
        };
        values.insert(id.clone(), burned);
    }
    let raster_share = entry_share(
        std::mem::size_of::<String>(),
        std::mem::size_of::<WorkRaster>(),
    );
    let mut rasters = std::collections::BTreeMap::new();
    for entry in &args.raster_index {
        let start = usize::try_from(entry.offset).ok();
        let len = usize::try_from(entry.len).ok();
        let rgba = start
            .zip(len)
            .and_then(|(start, len)| raster_blob.get(start..start.checked_add(len)?))
            .ok_or_else(|| bad("a raster outside its input"))?;
        if let Err(err) =
            admit(ledger.admit_len::<u8>(raster_share.saturating_add(entry.image_ref.len())))
        {
            return failed(err);
        }
        rasters.insert(
            entry.image_ref.clone(),
            WorkRaster {
                width: entry.width,
                height: entry.height,
                rgba,
            },
        );
    }
    if let Err(err) = admit(ledger.admit_len::<BurnField>(args.fields.len())) {
        return failed(err);
    }
    let mut fields = Vec::with_capacity(args.fields.len());
    for field in &args.fields {
        if let Err(err) = admit(ledger.admit_len::<u8>(field.id.len())) {
            return failed(err);
        }
        fields.push(BurnField {
            id: field.id.clone(),
            geometry: FieldGeometry {
                page: field.geometry.page,
                x_percent: field.geometry.x_percent,
                y_percent: field.geometry.y_percent,
                width_percent: field.geometry.width_percent,
                height_percent: field.geometry.height_percent,
            },
        });
    }
    if let Err(err) = admit(ledger.admit_len::<WorkRecipient>(args.recipients.len())) {
        return failed(err);
    }
    let recipients: Vec<WorkRecipient<'_>> = args
        .recipients
        .iter()
        .map(|recipient| WorkRecipient {
            id: &recipient.id,
            name: &recipient.name,
            email: &recipient.email,
            natural_person: recipient.natural_person.as_deref(),
        })
        .collect();
    if let Err(err) = admit(ledger.admit_len::<WorkSignature>(args.signatures.len())) {
        return failed(err);
    }
    let signatures: Vec<WorkSignature<'_>> = args
        .signatures
        .iter()
        .map(|signature| WorkSignature {
            field: &signature.field,
            recipient: &signature.recipient,
            at: signature.at,
        })
        .collect();
    let chain: [u8; 32] = args
        .chain
        .as_slice()
        .try_into()
        .map_err(|_| bad("a 32-byte prepare chain"))?;
    let request = WorkPrepareRequest {
        document_ref: &args.document_ref,
        item: args.item,
        canonical_url: &args.canonical_url,
        artifact_ref: &args.artifact_ref,
        original_version: args.original_version,
        title: &args.title,
        audit_rows: args.audit_rows,
        rejection: args.rejection.as_deref(),
        recipients: &recipients,
        signatures: &signatures,
        fields: &fields,
        values: &values,
        rasters: &rasters,
        chain,
        trail: &args.trail,
    };
    match prepare_in(pdf, &request, &limits) {
        Ok(prepared) => {
            memory.reserve(prepared.bytes.len() as u64)?;
            let mut answer = report(
                &PrepareReply::Prepared {
                    original_sha256: ByteBuf::from(prepared.original_sha256.to_vec()),
                    audit_chain_sha256: ByteBuf::from(prepared.audit_chain_sha256.to_vec()),
                    original_pages: prepared.original_pages,
                    appendix_pages: prepared.appendix_pages,
                },
                &operation.observed,
                &memory,
            )?;
            answer.outputs.push(OutputBytes {
                name: "prepared.pdf".to_owned(),
                media_type: PDF.to_owned(),
                bytes: prepared.bytes,
            });
            Ok(answer)
        }
        Err(err) => {
            let stage = match err {
                WorkError::Invalid(_) => SealStage::InputValidation,
                WorkError::Memory(_) => SealStage::PdfIncrementalUpdate,
            };
            failed(err.seal_error(stage))
        }
    }
}

/// The call's memory for what it allocates beside its decodes (FIX 6195):
/// its args' decoded copy, its report's JSON and encoded value, each
/// reserved by `memory.grow` before it is made. A host that reserves
/// nothing for this organ leaves them as they were; the machine's floor and
/// the call's deadline refuse them, retryable.
struct ReplyMemory(Asker);

impl ReplyMemory {
    fn reserve(&self, bytes: u64) -> Result<(), OrganError> {
        if bytes == 0 {
            return Ok(());
        }
        let memory = AskedMemory {
            asks: Arc::new(CallAsks {
                asker: self.0.clone(),
            }),
        };
        match memory.grow(bytes) {
            Ok(()) | Err(SealMemoryRefusal::Unavailable) => Ok(()),
            Err(SealMemoryRefusal::Cancelled) => {
                Err(OrganError::new(ErrorCode::Cancelled, "cancelled"))
            }
            Err(refusal) => Err(OrganError::new(
                ErrorCode::Budget,
                format!("the call's memory: {refusal}"),
            )),
        }
    }

    /// `value` read as `T`, its encoded copy and the most it decodes into
    /// (the codec's own count, [`read_cost`]) reserved first.
    fn args<T: DeserializeOwned>(&self, value: &Value, what: &str) -> Result<T, OrganError> {
        let cost = read_cost(value).map_err(|err| bad(format!("{what}: {err}")))?;
        self.reserve(cost)?;
        from_value(value, what)
    }
}

/// The call's one input, a PDF.
fn the_pdf<'a>(call: &'a CallContext<'_>) -> Result<&'a [u8], OrganError> {
    match call.inputs {
        [input] if input.media_type == PDF => Ok(&input[..]),
        _ => Err(bad("one application/pdf input")),
    }
}

/// The native engine over this call's asks, and where it counts. The outer
/// error is the args; the inner one is the seal's own, which the reply
/// carries. Its memory is the engine host's: every decode reserves its
/// bytes by ask first.
fn engine(
    config: ConfigArgs,
    now_ms: u64,
    began: Instant,
    asker: Asker,
) -> Result<(SealObservations, Result<NativeSealEngine, SealError>), OrganError> {
    let mut config = seal_config(config)?;
    let observed = config.resource_limits.observed.clone();
    let asks = Arc::new(CallAsks { asker });
    let memory = SealMemoryProvider::new(Arc::new(AskedMemory {
        asks: Arc::clone(&asks),
    }));
    config.resource_limits.memory = memory.clone();
    let engine = NativeSealEngine::new(
        config,
        Arc::new(AskedBackend {
            asks: Arc::clone(&asks),
            algorithm: Mutex::new(None),
        }),
        Arc::new(AskedFetcher { asks, memory }),
        Arc::new(CallClock { now_ms, began }),
    );
    Ok((observed, engine))
}

/// This call's asks, shared by the signer and the fetcher. The engine
/// spends no budget on them: it counts each against its `[limits]` rows and
/// answers it (Rule 5), so no ask here is held back for an earlier one.
struct CallAsks {
    asker: Asker,
}

impl CallAsks {
    fn ask(&self, verb: &str, value: Value) -> Result<AskReply, AskRefusal> {
        self.asker.ask(verb, value)
    }
}

fn seal_config(args: ConfigArgs) -> Result<SealConfig, OrganError> {
    let timestamp_authorities = args
        .timestamp_authorities
        .into_iter()
        .map(|tsa| -> Result<TsaEndpoint, OrganError> {
            Ok(TsaEndpoint {
                url: url::Url::parse(&tsa.url).map_err(|err| bad(format!("tsa url: {err}")))?,
                expected_policy_oid: tsa.policy_oid,
            })
        })
        .collect::<Result<_, _>>()?;
    // A fresh set of counts for this call alone, under the format bounds.
    let resource_limits = SealResourceLimits::default();
    Ok(SealConfig {
        trust_anchors_der: args
            .trust_anchors
            .into_iter()
            .map(ByteBuf::into_vec)
            .collect(),
        timestamp_authorities,
        // The engine owns the fetch policy: its allowlist is the grant's.
        fetch_policy: FetchPolicy::default(),
        resource_limits,
    })
}

/// The call's memory, as asks (`memory.grow`): the engine's host leases each
/// reservation from the machine's memory floor and holds it until the call
/// ends, so nothing here gives memory back.
struct AskedMemory {
    asks: Arc<CallAsks>,
}

impl AskedMemory {
    /// Reserves `bytes` with the engine's host, before they are allocated.
    fn grow(&self, bytes: u64) -> Result<(), SealMemoryRefusal> {
        let value = to_value(&MemoryAsk { bytes }).map_err(|_| SealMemoryRefusal::Failed)?;
        let reply =
            self.asks
                .ask(ASK_MEMORY_GROW, value)
                .map_err(|refusal| match refusal.code {
                    // The call ended while the ask waited: its deadline passed,
                    // or its grant was revoked.
                    AskCode::Cancelled => SealMemoryRefusal::Cancelled,
                    // No host here reserves memory: not granted, no handler, no
                    // room, or a 1.0 engine.
                    AskCode::NotGranted | AskCode::Unsupported | AskCode::BadRequest => {
                        SealMemoryRefusal::Unavailable
                    }
                    _ => SealMemoryRefusal::Failed,
                })?;
        match from_value::<MemoryAnswer>(&reply.value, "memory") {
            Ok(MemoryAnswer::Granted) => Ok(()),
            Ok(MemoryAnswer::Floor { needed, available }) => {
                Err(SealMemoryRefusal::Floor { needed, available })
            }
            Ok(MemoryAnswer::Deadline) => Err(SealMemoryRefusal::Deadline),
            Err(_) => Err(SealMemoryRefusal::Failed),
        }
    }
}

impl SealMemory for AskedMemory {
    fn reserve(&self, bytes: u64) -> Result<Box<dyn Send>, SealMemoryRefusal> {
        self.grow(bytes)?;
        // The host holds the bytes until the call ends: nothing to hold here.
        Ok(Box::new(()))
    }
}

/// The signer, as asks: the key never leaves the engine.
struct AskedBackend {
    asks: Arc<CallAsks>,
    /// Assembly owns the identity; signing retries need only its algorithm.
    algorithm: Mutex<Option<SignatureAlgorithm>>,
}

#[derive(Deserialize)]
struct IdentityAnswer {
    algorithm: SignatureAlgorithm,
    signer_certificate: ByteBuf,
    #[serde(default)]
    chain: Vec<ByteBuf>,
}

#[derive(Serialize)]
struct SignAsk {
    operation_id: String,
    revision_id: u32,
    byte_range: [u64; 4],
    signed_attributes_der: ByteBuf,
}

#[derive(Deserialize)]
struct SignAnswer {
    signature: ByteBuf,
}

/// A refusal as the seal's backend error: worth a retry, or rejected.
fn backend_error(refusal: &AskRefusal, rejected: BackendRejectCode) -> BackendError {
    if refusal.retryable || refusal.code == AskCode::Cancelled {
        BackendError::Unavailable {
            retry_after_ms: None,
        }
    } else {
        BackendError::Rejected { code: rejected }
    }
}

#[async_trait]
impl SealBackend for AskedBackend {
    fn signing_identity(&self) -> Result<SigningIdentity, BackendError> {
        let mut held = lock(&self.algorithm);
        let reply = self
            .asks
            .ask(ASK_IDENTITY, Value::Map(Vec::new()))
            .map_err(|refusal| backend_error(&refusal, BackendRejectCode::IdentityUnavailable))?;
        let answer: IdentityAnswer =
            from_value(&reply.value, "identity").map_err(|_| BackendError::Rejected {
                code: BackendRejectCode::InvalidResponse,
            })?;
        let identity = SigningIdentity {
            algorithm: answer.algorithm,
            signer_certificate_der: answer.signer_certificate.into_vec(),
            certificate_chain_der: answer.chain.into_iter().map(ByteBuf::into_vec).collect(),
        };
        *held = Some(identity.algorithm);
        Ok(identity)
    }

    /// The engine signs no bare prehash: only a revision it wrote.
    async fn sign_digest(
        &self,
        _request: SignDigestRequest,
    ) -> Result<BackendSignature, BackendError> {
        Err(BackendError::Rejected {
            code: BackendRejectCode::Unauthorized,
        })
    }

    async fn sign_revision(
        &self,
        request: SignRevisionRequest,
    ) -> Result<BackendSignature, BackendError> {
        let cached_algorithm = {
            let algorithm = lock(&self.algorithm);
            *algorithm
        };
        let algorithm = match cached_algorithm {
            Some(algorithm) => algorithm,
            None => self.signing_identity()?.algorithm,
        };
        let revision_id = request.revision_id.ok_or(BackendError::Rejected {
            code: BackendRejectCode::Unauthorized,
        })?;
        let ask = SignAsk {
            operation_id: request.operation_id,
            revision_id,
            byte_range: request.byte_range,
            signed_attributes_der: ByteBuf::from(request.signed_attributes_der),
        };
        let value = to_value(&ask).map_err(|_| BackendError::Rejected {
            code: BackendRejectCode::InvalidResponse,
        })?;
        let reply = self
            .asks
            .ask(ASK_SIGN, value)
            .map_err(|refusal| backend_error(&refusal, BackendRejectCode::Unauthorized))?;
        let answer: SignAnswer =
            from_value(&reply.value, "signature").map_err(|_| BackendError::MalformedSignature)?;
        let bytes = answer.signature.into_vec();
        // The seal checks the signature against the leaf before it embeds it.
        Ok(match algorithm {
            SignatureAlgorithm::RsaPkcs1v15Sha256 => BackendSignature::RsaPkcs1v15 { bytes },
            SignatureAlgorithm::EcdsaP256Sha256 => BackendSignature::EcdsaP256Der { bytes },
        })
    }
}

/// Every fetch, as an ask: the engine's guarded fetch, inside the grant's
/// allowlist. The seal fetches timestamps, CRLs and OCSP replies. A body comes back
/// whole: the engine measures its size against its `[limits]` rows, and the
/// seal's own copy of it is reserved before it is made (`memory.grow`), as
/// admitted bytes.
struct AskedFetcher {
    asks: Arc<CallAsks>,
    /// The call's memory, the provider the engine's decodes reserve from.
    memory: SealMemoryProvider,
}

#[async_trait]
impl SealFetcher for AskedFetcher {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let purpose = match request.purpose {
            FetchPurpose::Timestamp => "tsa",
            FetchPurpose::Crl => "crl",
            FetchPurpose::Ocsp => "ocsp",
            FetchPurpose::AuthorityInformationAccess => {
                return Err(FetchError::Denied);
            }
        };
        let post = request.method == FetchMethod::Post;
        let ask = FetchAsk {
            purpose: purpose.to_owned(),
            method: if post {
                oneiron_organ_protocol::FetchMethod::Post
            } else {
                oneiron_organ_protocol::FetchMethod::Get
            },
            url: request.url.to_string(),
            content_type: request.content_type.filter(|_| post),
            body: post.then(|| ByteBuf::from(request.request_body)),
        };
        let value = to_value(&ask).map_err(|_| FetchError::InvalidResponse)?;
        let reply = self
            .asks
            .ask(ASK_NET_FETCH, value)
            .map_err(|refusal| match refusal.code {
                AskCode::NotGranted | AskCode::BadRequest => FetchError::Denied,
                AskCode::TooLarge => FetchError::ResponseTooLarge,
                AskCode::Cancelled => FetchError::Timeout,
                _ => FetchError::Unavailable,
            })?;
        let answer: FetchAnswer =
            from_value(&reply.value, "fetch").map_err(|_| FetchError::InvalidResponse)?;
        if !(200..300).contains(&answer.status) {
            return Err(FetchError::InvalidResponse);
        }
        let body = match reply.data {
            // A region's bytes came reserved before the runtime copied them
            // (FIX 8454): that copy is adopted whole with what holds it, and
            // nothing copies it again. Inline bytes take a lease of their own.
            Some(data) => {
                let (bytes, memory) = data.into_parts();
                let held = matches!(memory, AnswerMemory::Reserved { .. })
                    .then(|| Box::new(memory) as Box<dyn Send>);
                AdmittedBytes::adopt(&self.memory, bytes, held).map_err(FetchError::Memory)?
            }
            None => AdmittedBytes::shared_empty(&self.memory).map_err(FetchError::Memory)?,
        };
        // The answer's text is admitted before it is copied, and shared
        // (FIX 8455): the reservation is the copy's own.
        let content_type = match answer.content_type {
            None => None,
            Some(text) => Some(Arc::new(
                AdmittedStr::copy_from(&self.memory, &text).map_err(FetchError::Memory)?,
            )),
        };
        Ok(FetchResponse {
            body: Arc::new(body),
            content_type,
        })
    }
}

/// The engine's clock at the call, moved on by this process's own.
struct CallClock {
    now_ms: u64,
    began: Instant,
}

impl SealClock for CallClock {
    fn unix_time_ms(&self) -> u64 {
        let since = u64::try_from(self.began.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.now_ms.saturating_add(since)
    }
}

/// Runs a seal future on this thread. Asks block rather than pend, so it
/// never waits on anything but itself.
fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(out) = future.as_mut().poll(&mut context) {
            return out;
        }
        thread::park();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn bad(detail: impl Into<String>) -> OrganError {
    OrganError::new(ErrorCode::BadRequest, detail)
}

/// The outcome as the report's one tagged entry, and the call's counts
/// beside it as `observed`. Its encoded copy and the most the value it
/// becomes takes ([`read_cost`]) are reserved before either is made
/// (FIX 6195, 10576).
fn report<T: Serialize>(
    report: &T,
    observed: &SealObservations,
    memory: &ReplyMemory,
) -> Result<Answer, OrganError> {
    let cost = read_cost(report)
        .map_err(|err| OrganError::new(ErrorCode::Internal, format!("encode: {err}")))?;
    memory.reserve(cost)?;
    let mut value = to_value(report)?;
    if let Value::Map(entries) = &mut value {
        entries.push((Value::from("observed"), to_value(&observed.observed())?));
    }
    Ok(Answer {
        report: value,
        ..Answer::default()
    })
}

/// MessagePack with named fields, so any reader can follow it, in the
/// protocol's codec, which does not recurse over a value's depth.
fn to_value<T: Serialize>(value: &T) -> Result<Value, OrganError> {
    oneiron_organ_protocol::to_value(value)
        .map_err(|err| OrganError::new(ErrorCode::Internal, format!("encode: {err}")))
}

fn from_value<T: DeserializeOwned>(value: &Value, what: &str) -> Result<T, OrganError> {
    oneiron_organ_protocol::from_value(value).map_err(|err| bad(format!("{what}: {err}")))
}
