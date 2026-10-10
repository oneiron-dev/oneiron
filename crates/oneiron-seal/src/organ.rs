//! The seal organ: `seal.pdf` and `seal.verify`, schema 1, run as its own
//! process behind the organ host (ARCH-0064 section 7, ARCH-0075
//! `#organ-host-design-seal-move`).
//!
//! The engine prepares the PDF and lends it; it keeps the signing key. The
//! organ asks it back, protocol 1.1, for the signing identity
//! (`seal.identity`), for each signature over a SHA-256 prehash
//! (`seal.sign`), and for every timestamp and CRL fetch (`net.fetch`, inside
//! the allowlist the install grant names). Its clock is the engine's
//! `now_ms` plus the time since the call began.
//!
//! Args, MessagePack with named fields:
//! - `seal.pdf`: `{operation_id, profile, now_ms, config}`, one
//!   `application/pdf` input.
//! - `seal.verify`: `{now_ms, config}`, one `application/pdf` input. It
//!   never asks.
//! - `config`: `{trust_anchors: [bin], timestamp_authorities: [{url,
//!   policy_oid?}], limits?: {max_input_bytes, max_output_growth_bytes,
//!   max_pdf_objects}}`.
//!
//! Reports: `{sealed: {evidence_sha256, requested, achieved, degraded,
//! self_verify}}` with the output `sealed.pdf`, `{verified: verdict}`, or
//! `{failed: <seal error>}`. A verdict is `{verdict, reasons, achieved,
//! self_verify_ok, report}`; the error names the seal's own stage and code.

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::Instant;

use async_trait::async_trait;
use oneiron_organ_protocol::{
    ASK_NET_FETCH, Answer, AskCode, AskRefusal, Asker, ByteBuf, CallContext, ErrorCode,
    FetchAnswer, FetchAsk, Organ, OrganError, OrganIdentity, OutputBytes, VerbSpec,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::api::{
    BackendError, BackendRejectCode, BackendSignature, DigestAlgorithm, FetchError, FetchMethod,
    FetchPolicy, FetchPurpose, FetchRequest, FetchResponse, PadesProfile, PdfSealEngine,
    ProfileDegradeReason, SealBackend, SealClock, SealConfig, SealFetcher, SealRequest,
    SealResourceLimits, SealWarning, SignDigestRequest, SignatureAlgorithm, SigningIdentity,
    TsaEndpoint, VerifyFindingCode, VerifyReport, VerifyVerdict,
};
use crate::error::{FatalCode, InputInvalidCode, RetryableCode, SealError, SealStage};
use crate::native::NativeSealEngine;

pub const VERB_SEAL: &str = "seal.pdf";
pub const VERB_VERIFY: &str = "seal.verify";
/// Ask: the signing identity, `{}` → `{algorithm, signer_certificate,
/// chain}`.
pub const ASK_IDENTITY: &str = "seal.identity";
/// Ask: one signature, `{operation_id, digest_algorithm, digest}` →
/// `{signature}`.
pub const ASK_SIGN: &str = "seal.sign";
/// The name of the sealed output.
pub const SEALED_OUTPUT: &str = "sealed.pdf";
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
        [VERB_SEAL, VERB_VERIFY]
            .into_iter()
            .map(|name| VerbSpec {
                name: name.to_owned(),
                schema: 1,
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
    #[serde(default)]
    limits: Option<LimitArgs>,
}

#[derive(Deserialize)]
struct TsaArgs {
    url: String,
    #[serde(default)]
    policy_oid: Option<String>,
}

#[derive(Deserialize)]
struct LimitArgs {
    max_input_bytes: u64,
    max_output_growth_bytes: u64,
    max_pdf_objects: u64,
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

#[derive(Serialize)]
struct Verdict {
    verdict: VerifyVerdict,
    reasons: Vec<VerifyFindingCode>,
    achieved: Option<PadesProfile>,
    self_verify_ok: bool,
    report: VerifyReport,
}

impl Verdict {
    fn of(report: VerifyReport) -> Self {
        Self {
            verdict: report.verdict(),
            reasons: report.reasons(),
            achieved: report.achieved_profile(),
            self_verify_ok: report.passes_self_verify(),
            report,
        }
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

impl From<SealError> for Failure {
    fn from(err: SealError) -> Self {
        match err {
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
                verdict: Box::new(Verdict::of(*report)),
            },
            SealError::BackendUnavailable { retry_after_ms } => {
                Self::BackendUnavailable { retry_after_ms }
            }
            SealError::InputInvalid { code } => Self::InputInvalid { code },
        }
    }
}

fn seal(call: &CallContext<'_>, began: Instant) -> Result<Answer, OrganError> {
    let args: SealArgs = from_value(call.args, "seal args")?;
    let pdf = the_pdf(call)?;
    let engine = match engine(args.config, args.now_ms, began, call.asker())? {
        Ok(engine) => engine,
        Err(err) => return report(&SealReport::Failed(err.into())),
    };
    let request = SealRequest {
        operation_id: args.operation_id,
        target_profile: args.profile,
    };
    let sealed = match block_on(engine.seal_pdf(pdf, &request)) {
        Ok(sealed) => sealed,
        Err(err) => return report(&SealReport::Failed(err.into())),
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
    let mut answer = report(&SealReport::Sealed {
        evidence_sha256: ByteBuf::from(sealed.evidence_sha256.to_vec()),
        requested: sealed.requested_profile,
        achieved: sealed.achieved_profile,
        degraded,
        self_verify: Verdict::of(sealed.self_verify_report),
    })?;
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
    let checked = engine(args.config, args.now_ms, began, Asker::default())?
        .and_then(|engine| engine.verify_sealed_pdf(pdf));
    match checked {
        Ok(checked) => report(&VerifyReply::Verified(Verdict::of(checked))),
        Err(err) => report(&VerifyReply::Failed(err.into())),
    }
}

/// The call's one input, a PDF.
fn the_pdf<'a>(call: &'a CallContext<'_>) -> Result<&'a [u8], OrganError> {
    match call.inputs {
        [input] if input.media_type == PDF => Ok(&input[..]),
        _ => Err(bad("one application/pdf input")),
    }
}

/// The native engine over this call's asks. The outer error is the args;
/// the inner one is the seal's own, which the reply carries.
fn engine(
    config: ConfigArgs,
    now_ms: u64,
    began: Instant,
    asker: Asker,
) -> Result<Result<NativeSealEngine, SealError>, OrganError> {
    let config = seal_config(config)?;
    Ok(NativeSealEngine::new(
        config,
        Arc::new(AskedBackend {
            asker: asker.clone(),
            identity: Mutex::new(None),
        }),
        Arc::new(AskedFetcher { asker }),
        Arc::new(CallClock { now_ms, began }),
    ))
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
    let size = |value: u64| usize::try_from(value).map_err(|_| bad("a limit is too large"));
    let resource_limits = match args.limits {
        None => SealResourceLimits::default(),
        Some(limits) => SealResourceLimits {
            max_input_bytes: size(limits.max_input_bytes)?,
            max_output_growth_bytes: size(limits.max_output_growth_bytes)?,
            max_pdf_objects: size(limits.max_pdf_objects)?,
        },
    };
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
    asker: Asker,
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
    digest_algorithm: DigestAlgorithm,
    digest: ByteBuf,
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
            .asker
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

    async fn sign_digest(
        &self,
        request: SignDigestRequest,
    ) -> Result<BackendSignature, BackendError> {
        let algorithm = self.signing_identity()?.algorithm;
        let ask = SignAsk {
            operation_id: request.operation_id,
            digest_algorithm: request.digest_algorithm,
            digest: ByteBuf::from(request.digest.to_vec()),
        };
        let value = to_value(&ask).map_err(|_| BackendError::Rejected {
            code: BackendRejectCode::InvalidResponse,
        })?;
        let reply = self
            .asker
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
    asker: Asker,
}

#[async_trait]
impl SealFetcher for AskedFetcher {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let caps = FetchPolicy::default();
        let (purpose, cap) = match request.purpose {
            FetchPurpose::Timestamp => ("tsa", caps.max_tsa_bytes),
            FetchPurpose::Crl => ("crl", caps.max_crl_bytes),
            FetchPurpose::Ocsp => ("ocsp", caps.max_ocsp_bytes),
            FetchPurpose::AuthorityInformationAccess => ("aia", caps.max_aia_bytes),
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
            .asker
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

fn report<T: Serialize>(report: &T) -> Result<Answer, OrganError> {
    Ok(Answer {
        report: to_value(report)?,
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
