//! The seal organ: `seal.pdf` (schema 2) and `seal.verify` (schema 1), run
//! as its own process behind the organ host (ARCH-0064 section 7, ARCH-0075
//! `#organ-host-design-seal-move` and `#organ-host-design-seal-binding`).
//!
//! The engine prepares the PDF, writes its ordinary signature revision for
//! each contents capacity, and lends both; it keeps the signing key. The
//! organ builds only the CMS for one of those revisions, then any validation
//! data and document timestamp after it. It asks the engine back, protocol
//! 1.1, for the signing identity (`seal.identity`), for the signature over
//! the revision's signed attributes (`seal.sign`), and for every timestamp
//! and CRL fetch (`net.fetch`, inside the allowlist the install grant
//! names). Its clock is the engine's `now_ms` plus the time since the call
//! began.
//!
//! Args, MessagePack with named fields:
//! - `seal.pdf`: `{operation_id, profile, now_ms, config,
//!   signature_revisions: [{id, suffix_offset, suffix_len, byte_range}]}`,
//!   two inputs: the `application/pdf` prepared PDF, then the revisions'
//!   suffixes one after another as `application/octet-stream`. Revision
//!   `id` is the PDF followed by its suffix.
//! - `seal.verify`: `{now_ms, config}`, one `application/pdf` input. It
//!   never asks.
//! - `config`: `{trust_anchors: [bin], timestamp_authorities: [{url,
//!   policy_oid?}]}`. The seal's only size limits are format bounds, its
//!   own (`SealResourceLimits::default`); nothing on size is configured.
//!
//! Reports: `{sealed: {evidence_sha256, requested, achieved, degraded,
//! self_verify}}` with the output `sealed.pdf`, `{verified: verdict}`, or
//! `{failed: <seal error>}`. A verdict is `{verdict, reasons, achieved,
//! self_verify_ok, report}`; the error names the seal's own stage and code.
//! Beside the outcome every report carries `observed`, what the native
//! analysis counted (`SealObserved`), on a failure too: the engine measures
//! each count against its `[limits]` row before it reads the outcome.

use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::Instant;

use async_trait::async_trait;
use oneiron_organ_protocol::{
    ASK_NET_FETCH, Answer, AskCode, AskRefusal, AskReply, Asker, ByteBuf, CallContext, ErrorCode,
    FetchAnswer, FetchAsk, Organ, OrganError, OrganIdentity, OutputBytes, VerbSpec,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::api::{
    BackendError, BackendRejectCode, BackendSignature, FetchError, FetchMethod, FetchPolicy,
    FetchPurpose, FetchRequest, FetchResponse, PadesProfile, PdfSealEngine, PreparedRevision,
    ProfileDegradeReason, SealBackend, SealClock, SealConfig, SealFetcher, SealObservations,
    SealRequest, SealResourceLimits, SealWarning, SignDigestRequest, SignRevisionRequest,
    SignatureAlgorithm, SigningIdentity, TsaEndpoint, VerifyFindingCode, VerifyReport,
    VerifyVerdict,
};
use crate::error::{FatalCode, InputInvalidCode, RetryableCode, SealError, SealStage};
use crate::native::NativeSealEngine;

pub const VERB_SEAL: &str = "seal.pdf";
pub const VERB_VERIFY: &str = "seal.verify";
/// `seal.pdf`'s schema: the engine's revisions, lent beside the PDF.
pub const SEAL_SCHEMA: u32 = 2;
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
/// The most report JSON a verdict carries. A larger report is left out,
/// as `{"omitted_over_bytes": MAX_REPORT_JSON_BYTES}`, so its verdict
/// still fits the reply frame: a small PDF can name thousands of
/// signatures with long field names.
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
        [(VERB_SEAL, SEAL_SCHEMA), (VERB_VERIFY, 1)]
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
struct Degrade {
    requested: PadesProfile,
    achieved: PadesProfile,
    reason: ProfileDegradeReason,
}

/// A verdict, with the full report as JSON bytes: one value in the reply
/// frame however many signatures the PDF holds, at most
/// [`MAX_REPORT_JSON_BYTES`], and never parsed by the engine.
#[derive(Serialize)]
struct Verdict {
    verdict: VerifyVerdict,
    reasons: Vec<VerifyFindingCode>,
    achieved: Option<PadesProfile>,
    self_verify_ok: bool,
    report_json: ByteBuf,
}

impl Verdict {
    fn of(report: &VerifyReport) -> Result<Self, OrganError> {
        let failed =
            |err: serde_json::Error| OrganError::new(ErrorCode::Internal, format!("report: {err}"));
        let mut capped = CappedJson(Vec::new());
        let json = match serde_json::to_writer(&mut capped, report) {
            Ok(()) => capped.0,
            Err(err) if err.is_io() => serde_json::to_vec(&OmittedReport {
                omitted_over_bytes: MAX_REPORT_JSON_BYTES,
            })
            .map_err(failed)?,
            Err(err) => return Err(failed(err)),
        };
        Ok(Self {
            verdict: report.verdict(),
            reasons: report.reasons(),
            achieved: report.achieved_profile(),
            self_verify_ok: report.passes_self_verify(),
            report_json: ByteBuf::from(json),
        })
    }
}

/// What stands in for a report over [`MAX_REPORT_JSON_BYTES`].
#[derive(Serialize)]
struct OmittedReport {
    omitted_over_bytes: usize,
}

/// JSON that stops at [`MAX_REPORT_JSON_BYTES`] rather than grow past it.
struct CappedJson(Vec<u8>);

impl std::io::Write for CappedJson {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.0.len() + buf.len() > MAX_REPORT_JSON_BYTES {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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
}

impl Failure {
    fn of(err: SealError) -> Result<Self, OrganError> {
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
                verdict: Box::new(Verdict::of(&report)?),
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
    let args: SealArgs = from_value(call.args, "seal args")?;
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
    let engine = match engine {
        Ok(engine) => engine,
        Err(err) => return report(&SealReport::Failed(Failure::of(err)?), &observed),
    };
    let request = SealRequest {
        operation_id: args.operation_id,
        target_profile: args.profile,
    };
    let sealed = match block_on(engine.seal_pdf_in_revisions(pdf, &request, &revisions)) {
        Ok(sealed) => sealed,
        Err(err) => return report(&SealReport::Failed(Failure::of(err)?), &observed),
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
    let mut answer = report(
        &SealReport::Sealed {
            evidence_sha256: ByteBuf::from(sealed.evidence_sha256.to_vec()),
            requested: sealed.requested_profile,
            achieved: sealed.achieved_profile,
            degraded,
            self_verify: Verdict::of(&sealed.self_verify_report)?,
        },
        &observed,
    )?;
    answer.outputs.push(OutputBytes {
        name: SEALED_OUTPUT.to_owned(),
        media_type: PDF.to_owned(),
        bytes: sealed.bytes,
    });
    Ok(answer)
}

fn verify(call: &CallContext<'_>, began: Instant) -> Result<Answer, OrganError> {
    let args: VerifyArgs = from_value(call.args, "verify args")?;
    let pdf = the_pdf(call)?;
    // Verification never signs or fetches: an asker with no engine.
    let (observed, engine) = engine(args.config, args.now_ms, began, Asker::default())?;
    let checked = engine.and_then(|engine| engine.verify_sealed_pdf(pdf));
    match checked {
        Ok(checked) => report(&VerifyReply::Verified(Verdict::of(&checked)?), &observed),
        Err(err) => report(&VerifyReply::Failed(Failure::of(err)?), &observed),
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
/// carries.
fn engine(
    config: ConfigArgs,
    now_ms: u64,
    began: Instant,
    asker: Asker,
) -> Result<(SealObservations, Result<NativeSealEngine, SealError>), OrganError> {
    let config = seal_config(config)?;
    let observed = config.resource_limits.observed.clone();
    let asks = Arc::new(CallAsks {
        asker,
        spent: AtomicBool::new(false),
    });
    let engine = NativeSealEngine::new(
        config,
        Arc::new(AskedBackend {
            asks: Arc::clone(&asks),
            identity: Mutex::new(None),
        }),
        Arc::new(AskedFetcher { asks }),
        Arc::new(CallClock { now_ms, began }),
    );
    Ok((observed, engine))
}

/// This call's asks, shared by the signer and the fetcher. After one
/// `budget` refusal the engine ends the call at the next ask, so none is
/// sent: each later ask fails here, and the seal degrades (no timestamp, no
/// validation material) or fails, as it chooses.
struct CallAsks {
    asker: Asker,
    spent: AtomicBool,
}

impl CallAsks {
    fn ask(&self, verb: &str, value: rmpv::Value) -> Result<AskReply, AskRefusal> {
        if self.spent.load(Ordering::SeqCst) {
            return Err(AskRefusal::new(
                AskCode::Budget,
                "this call's asks are spent",
            ));
        }
        let answer = self.asker.ask(verb, value);
        if let Err(refusal) = &answer
            && refusal.code == AskCode::Budget
        {
            self.spent.store(true, Ordering::SeqCst);
        }
        answer
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

/// The signer, as asks: the key never leaves the engine.
struct AskedBackend {
    asks: Arc<CallAsks>,
    /// The identity the engine gave, asked once per call.
    identity: Mutex<Option<SigningIdentity>>,
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
        let mut held = lock(&self.identity);
        if let Some(identity) = held.as_ref() {
            return Ok(identity.clone());
        }
        let reply = self
            .asks
            .ask(ASK_IDENTITY, rmpv::Value::Map(Vec::new()))
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
        *held = Some(identity.clone());
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
        let algorithm = self.signing_identity()?.algorithm;
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
/// allowlist. The seal fetches only timestamps and CRLs.
struct AskedFetcher {
    asks: Arc<CallAsks>,
}

#[async_trait]
impl SealFetcher for AskedFetcher {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let caps = FetchPolicy::default();
        let (purpose, cap) = match request.purpose {
            FetchPurpose::Timestamp => ("tsa", caps.max_tsa_bytes),
            FetchPurpose::Crl => ("crl", caps.max_crl_bytes),
            FetchPurpose::Ocsp | FetchPurpose::AuthorityInformationAccess => {
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
        let body = reply.data.map(|data| data.to_vec()).unwrap_or_default();
        if body.len() > cap {
            return Err(FetchError::ResponseTooLarge);
        }
        Ok(FetchResponse {
            body,
            content_type: answer.content_type,
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
/// beside it as `observed`.
fn report<T: Serialize>(report: &T, observed: &SealObservations) -> Result<Answer, OrganError> {
    let mut value = to_value(report)?;
    if let rmpv::Value::Map(entries) = &mut value {
        entries.push((
            rmpv::Value::from("observed"),
            to_value(&observed.observed())?,
        ));
    }
    Ok(Answer {
        report: value,
        ..Answer::default()
    })
}

/// MessagePack with named fields, so any reader can follow it.
fn to_value<T: Serialize>(value: &T) -> Result<rmpv::Value, OrganError> {
    let internal = |err: &dyn std::fmt::Display| {
        OrganError::new(ErrorCode::Internal, format!("encode: {err}"))
    };
    let bytes = rmp_serde::to_vec_named(value).map_err(|err| internal(&err))?;
    rmpv::decode::read_value(&mut bytes.as_slice()).map_err(|err| internal(&err))
}

fn from_value<T: DeserializeOwned>(value: &rmpv::Value, what: &str) -> Result<T, OrganError> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|err| bad(format!("{what}: {err}")))?;
    rmp_serde::from_slice(&bytes).map_err(|err| bad(format!("{what}: {err}")))
}
