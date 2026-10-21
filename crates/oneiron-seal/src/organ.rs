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
//! names). Both verbs ask it for the memory their PDF decodes and their
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
//! - `config`: `{trust_anchors: [bin], timestamp_authorities: [{url,
//!   policy_oid?}]}`. The seal's only size limits are format bounds, its
//!   own (`SealResourceLimits::default`); nothing on size is configured.
//!
//! Reports: `{sealed: {evidence_sha256, requested, achieved, degraded,
//! self_verify}}` with the output `sealed.pdf`, `{verified: verdict}`, or
//! `{failed: <seal error>}`. A verdict is `{verdict, reasons, achieved,
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
    ASK_MEMORY_GROW, ASK_NET_FETCH, Answer, AskCode, AskRefusal, AskReply, Asker, ByteBuf,
    CallContext, ErrorCode, FetchAnswer, FetchAsk, MemoryAnswer, MemoryAsk, Organ, OrganError,
    OrganIdentity, OutputBytes, VerbSpec,
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
use crate::memory::{SealMemory, SealMemoryProvider, SealMemoryRefusal};
use crate::native::NativeSealEngine;

mod report;

use self::report::Verdict;

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
/// The report JSON a verdict carries past which the engine's `[limits]`
/// row asks (`seal_report_json_bytes`). Every report is carried whole,
/// however many signatures it names (Rule 5), inside the reply frame's own
/// `u32` length.
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
    /// The seal's error; a failed verification's verdict is of `pdf`, when
    /// this side holds the bytes it verified.
    fn of(err: SealError, pdf: Option<&[u8]>) -> Result<Self, OrganError> {
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
                verdict: Box::new(Verdict::of(&report, pdf)?),
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
        Err(err) => return report(&SealReport::Failed(Failure::of(err, None)?), &observed),
    };
    let request = SealRequest {
        operation_id: args.operation_id,
        target_profile: args.profile,
    };
    let sealed = match block_on(engine.seal_pdf_in_revisions(pdf, &request, &revisions)) {
        Ok(sealed) => sealed,
        Err(err) => return report(&SealReport::Failed(Failure::of(err, None)?), &observed),
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
            self_verify: Verdict::of(&sealed.self_verify_report, Some(&sealed.bytes))?,
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
    // Verification asks only for memory: its host gives it no signing or
    // fetch handler.
    let (observed, engine) = engine(args.config, args.now_ms, began, call.asker())?;
    let checked = engine.and_then(|engine| engine.verify_sealed_pdf(pdf));
    match checked {
        Ok(checked) => report(
            &VerifyReply::Verified(Verdict::of(&checked, Some(pdf))?),
            &observed,
        ),
        Err(err) => report(
            &VerifyReply::Failed(Failure::of(err, Some(pdf))?),
            &observed,
        ),
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
    let memory = Arc::new(AskedMemory {
        asks: Arc::clone(&asks),
    });
    let service: Arc<dyn SealMemory> = memory.clone();
    config.resource_limits.memory = SealMemoryProvider::new(service);
    let engine = NativeSealEngine::new(
        config,
        Arc::new(AskedBackend {
            asks: Arc::clone(&asks),
            identity: Mutex::new(None),
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
    fn ask(&self, verb: &str, value: rmpv::Value) -> Result<AskReply, AskRefusal> {
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
/// allowlist. The seal fetches only timestamps and CRLs. A body comes back
/// whole: the engine measures its size against its `[limits]` rows, and the
/// seal's own copy of it is reserved before it is made.
struct AskedFetcher {
    asks: Arc<CallAsks>,
    memory: Arc<AskedMemory>,
}

#[async_trait]
impl SealFetcher for AskedFetcher {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let purpose = match request.purpose {
            FetchPurpose::Timestamp => "tsa",
            FetchPurpose::Crl => "crl",
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
        let body = match reply.data {
            Some(data) => {
                let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
                self.memory.grow(len).map_err(FetchError::Memory)?;
                data.to_vec()
            }
            None => Vec::new(),
        };
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
