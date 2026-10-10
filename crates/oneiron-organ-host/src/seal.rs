//! The seal port's host adapter (ARCH-0064 section 7): [`HostedSealer`]
//! implements the engine's [`EsignSealer`] by calling the seal organ.
//!
//! Each seal is one `seal.pdf` call. The prepared PDF is lent, and the
//! call's handlers are built for that call alone: the signing identity
//! once, at most three signatures, each under the call's own operation,
//! and fetches only inside the install grant's allowlist, each bounded by
//! the fetch timeout. The key stays here, behind [`SealKeys`]; the organ
//! sends prehashes and gets signatures back. Each verification is one
//! `seal.verify` call, with no handlers.
//!
//! Calls block, as every host call does: run them off any async runtime.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::blob_artifact::esign::{
    EsignSealRequest, EsignSealed, EsignSealer, EsignSealerError, EsignVerdict, SealDegrade,
    SealProfile, SealVerdict,
};
use oneiron_organ_protocol::{ASK_NET_FETCH, AskCode, AskRefusal, ByteBuf, FrameError};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::asks::{Answered, AskHandler, AskHandlers, AskRequest};
use crate::error::{HostError, Unavailable};
use crate::fetch::GuardedFetch;
use crate::host::OrganHost;
use crate::spec::{AskGrant, CallClass, FetchGrant, LentInput, OrganCall, OrganSpec};

/// The name the seal organ is installed under.
pub const SEAL_ORGAN: &str = "seal";
pub const VERB_SEAL: &str = "seal.pdf";
pub const VERB_VERIFY: &str = "seal.verify";
/// Ask: the signing identity.
pub const ASK_IDENTITY: &str = "seal.identity";
/// Ask: one signature over a SHA-256 prehash.
pub const ASK_SIGN: &str = "seal.sign";

const SEALED_OUTPUT: &str = "sealed.pdf";
const PDF: &str = "application/pdf";
/// The contents ladder: 64, 128 and 256 KiB.
const MAX_SIGNS: u32 = 3;
const MAX_FETCHES: u32 = 32;
const MIB: u64 = 1024 * 1024;
/// The seal's own response caps: a CRL, and a timestamp.
const MAX_CRL_BYTES: u64 = 8 * MIB;
const MAX_TSA_BYTES: u64 = MIB;
/// The engine's 64 MiB prepared limit plus the seal's 32 MiB growth limit.
const MAX_SEALED_BYTES: u64 = 96 * MIB;

/// The signing key's custody, a local signer or a KMS. The key never
/// crosses the socket. Both run on the caller's thread inside its call, so
/// each must return by `deadline`, the call's: a KMS bounds its whole
/// request by it.
pub trait SealKeys: Send + Sync {
    /// The key's certificate and chain.
    ///
    /// # Errors
    /// The key store's.
    fn identity(&self, deadline: Instant) -> Result<SealIdentity, SealKeyError>;

    /// Signs a SHA-256 prehash with the key [`Self::identity`] names: an
    /// RSA PKCS#1 v1.5 signature, or an ECDSA P-256 one in DER.
    ///
    /// # Errors
    /// The key store's.
    fn sign_prehash(
        &self,
        operation_id: &str,
        digest: &[u8; 32],
        deadline: Instant,
    ) -> Result<Vec<u8>, SealKeyError>;
}

/// The signature algorithm of a seal key. The serde names are the seal
/// organ's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SealAlgorithm {
    RsaPkcs1v15Sha256,
    EcdsaP256Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealIdentity {
    pub algorithm: SealAlgorithm,
    /// DER.
    pub signer_certificate: Vec<u8>,
    /// DER, leaf first, without the leaf.
    pub chain: Vec<Vec<u8>>,
}

/// A key store that could not answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct SealKeyError {
    pub detail: String,
    /// Whether trying again may help.
    pub retryable: bool,
}

/// A timestamp authority. Its URL crosses to the organ, so it carries no
/// user, password, query or fragment; a seal with one is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SealTsa {
    pub url: String,
    pub policy_oid: Option<String>,
}

/// The seal's resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SealLimits {
    pub max_input_bytes: u64,
    pub max_output_growth_bytes: u64,
    pub max_pdf_objects: u64,
}

impl Default for SealLimits {
    /// The seal's own defaults.
    fn default() -> Self {
        Self {
            max_input_bytes: 256 * MIB,
            max_output_growth_bytes: 32 * MIB,
            max_pdf_objects: 1_000_000,
        }
    }
}

/// What the engine configures for its seals.
#[derive(Debug, Clone)]
pub struct SealSettings {
    /// DER certificates.
    pub trust_anchors: Vec<Vec<u8>>,
    /// In order of preference. Their origins belong on the install grant's
    /// fetch allowlist, with the CRL origins.
    pub timestamp_authorities: Vec<SealTsa>,
    pub limits: SealLimits,
    /// The organ's installed name and the grant its calls run under.
    pub organ: String,
    pub grant: String,
    pub class: CallClass,
    pub deadline: Duration,
    /// One fetch's time, inside the call's: a slow authority costs that
    /// fetch, and the seal degrades, rather than the call's deadline.
    pub fetch_timeout: Duration,
}

impl SealSettings {
    /// Background calls of one minute, five seconds a fetch, the seal's
    /// default limits, no timestamp authority.
    #[must_use]
    pub fn new(trust_anchors: Vec<Vec<u8>>, grant: impl Into<String>) -> Self {
        Self {
            trust_anchors,
            timestamp_authorities: Vec::new(),
            limits: SealLimits::default(),
            organ: SEAL_ORGAN.to_owned(),
            grant: grant.into(),
            class: CallClass::Background,
            deadline: Duration::from_secs(60),
            fetch_timeout: Duration::from_secs(5),
        }
    }
}

/// The seal organ's install grant: both verbs over PDFs, the identity
/// once, at most three signatures and 32 fetches a call, fetches only
/// inside `fetch`, and room for the sealed PDF.
#[must_use]
pub fn seal_spec(program: impl Into<PathBuf>, fetch: FetchGrant) -> OrganSpec {
    let mut spec = OrganSpec::first_party(SEAL_ORGAN, program);
    spec.verbs = vec![VERB_SEAL.to_owned(), VERB_VERIFY.to_owned()];
    spec.media_types = vec![PDF.to_owned()];
    spec.asks = vec![
        AskGrant::new(ASK_IDENTITY, 1),
        AskGrant::new(ASK_SIGN, MAX_SIGNS),
        AskGrant::new(ASK_NET_FETCH, MAX_FETCHES),
    ];
    spec.max_asks = 1 + MAX_SIGNS + MAX_FETCHES;
    // Room for several CRLs for B-LT, inside the call's booking beside the
    // sealed output.
    spec.max_ask_bytes = 64 * MIB;
    spec.memory_bytes = 1024 * MIB;
    spec.call_memory_bytes = 256 * MIB;
    spec.max_output_bytes = MAX_SEALED_BYTES;
    if cfg!(target_os = "macos") {
        // Outputs ride inline on macOS; one more MiB carries the report.
        spec.max_reply_frame = u32::try_from(MAX_SEALED_BYTES + MIB).unwrap_or(u32::MAX);
    }
    spec.fetch = fetch;
    spec
}

/// [`EsignSealer`] over the seal organ.
pub struct HostedSealer<'a> {
    host: &'a OrganHost,
    /// Inputs are lent, but a call runs against a vault.
    vault: &'a Vault,
    keys: &'a dyn SealKeys,
    settings: SealSettings,
}

impl<'a> HostedSealer<'a> {
    #[must_use]
    pub fn new(
        host: &'a OrganHost,
        vault: &'a Vault,
        keys: &'a dyn SealKeys,
        settings: SealSettings,
    ) -> Self {
        Self {
            host,
            vault,
            keys,
            settings,
        }
    }
}

impl std::fmt::Debug for HostedSealer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedSealer")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct SealArgs {
    operation_id: String,
    profile: SealProfile,
    now_ms: u64,
    config: ConfigArgs,
}

#[derive(Serialize)]
struct VerifyArgs {
    now_ms: u64,
    config: ConfigArgs,
}

#[derive(Serialize)]
struct ConfigArgs {
    trust_anchors: Vec<ByteBuf>,
    timestamp_authorities: Vec<SealTsa>,
    limits: SealLimits,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SealReply {
    Sealed {
        evidence_sha256: ByteBuf,
        requested: SealProfile,
        achieved: SealProfile,
        degraded: Vec<SealDegrade>,
        self_verify: VerdictReply,
    },
    Failed(FailureReply),
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum VerifyReply {
    Verified(VerdictReply),
    Failed(FailureReply),
}

#[derive(Deserialize)]
struct VerdictReply {
    verdict: SealVerdict,
    reasons: Vec<String>,
    achieved: Option<SealProfile>,
    self_verify_ok: bool,
    report_json: ByteBuf,
}

/// The seal's own error, by its stage and code names.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureReply {
    Retryable {
        stage: String,
        code: String,
        retry_after_ms: Option<u64>,
    },
    Fatal {
        stage: String,
        code: String,
    },
    VerifyFailed {
        verdict: Box<VerdictReply>,
    },
    BackendUnavailable {
        retry_after_ms: Option<u64>,
    },
    InputInvalid {
        code: String,
    },
}

impl VerdictReply {
    fn into_verdict(self) -> EsignVerdict {
        EsignVerdict {
            verdict: self.verdict,
            reasons: self.reasons,
            achieved: self.achieved,
            self_verify_ok: self.self_verify_ok,
            report_json: self.report_json.into_vec(),
        }
    }
}

impl FailureReply {
    fn into_error(self) -> EsignSealerError {
        match self {
            Self::Retryable {
                stage,
                code,
                retry_after_ms,
            } => EsignSealerError::Retryable {
                stage,
                code,
                retry_after_ms,
            },
            Self::Fatal { stage, code } => EsignSealerError::Fatal { stage, code },
            Self::VerifyFailed { verdict } => EsignSealerError::VerifyFailed {
                verdict: Box::new(verdict.into_verdict()),
            },
            Self::BackendUnavailable { retry_after_ms } => {
                EsignSealerError::Unavailable { retry_after_ms }
            }
            Self::InputInvalid { code } => EsignSealerError::InputInvalid { code },
        }
    }
}

impl HostedSealer<'_> {
    /// The engine's clock: the vault's own, which a host may inject.
    fn now_ms(&self) -> u64 {
        self.vault.now_recorded_at().saturating_mul(1000)
    }

    /// The seal's configuration as the organ reads it. Verification gets
    /// no timestamp authorities: it never fetches. A TSA URL with a user,
    /// a password, a query or a fragment is refused here: the URL crosses
    /// the socket, and the seal cannot tell a credential in a query from a
    /// harmless parameter.
    fn config(&self, timestamps: bool) -> Result<ConfigArgs, EsignSealerError> {
        let timestamp_authorities = if timestamps {
            for tsa in &self.settings.timestamp_authorities {
                let url = reqwest::Url::parse(&tsa.url).map_err(|_| invalid_configuration())?;
                if !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                {
                    return Err(invalid_configuration());
                }
            }
            self.settings.timestamp_authorities.clone()
        } else {
            Vec::new()
        };
        Ok(ConfigArgs {
            trust_anchors: self
                .settings
                .trust_anchors
                .iter()
                .map(|anchor| ByteBuf::from(anchor.clone()))
                .collect(),
            timestamp_authorities,
            limits: self.settings.limits,
        })
    }

    fn call(&self, verb: &str, args: rmpv::Value) -> OrganCall {
        OrganCall {
            organ: self.settings.organ.clone(),
            verb: verb.to_owned(),
            schema: 1,
            args,
            body: None,
            inputs: Vec::new(),
            class: self.settings.class,
            deadline: self.settings.deadline,
            grant: self.settings.grant.clone(),
        }
    }
}

impl EsignSealer for HostedSealer<'_> {
    fn seal(
        &self,
        pdf: &[u8],
        request: &EsignSealRequest,
    ) -> Result<EsignSealed, EsignSealerError> {
        let identity = Identity { keys: self.keys };
        let sign = Sign {
            keys: self.keys,
            operation: format!("{}:", request.operation_id),
        };
        let fetch = TimedFetch {
            timeout: self.settings.fetch_timeout,
        };
        let handlers = AskHandlers::none()
            .with(ASK_IDENTITY, &identity)
            .with(ASK_SIGN, &sign)
            .with(ASK_NET_FETCH, &fetch);
        let args = to_value(&SealArgs {
            operation_id: request.operation_id.clone(),
            profile: request.profile,
            now_ms: self.now_ms(),
            config: self.config(true)?,
        })
        .map_err(|_| reply_invalid())?;
        let lent = vec![LentInput {
            media_type: PDF.to_owned(),
            bytes: pdf.to_vec(),
        }];
        let outcome = self
            .host
            .call_with(self.vault, self.call(VERB_SEAL, args), lent, &handlers)
            .map_err(host_failure)?;
        let (evidence_sha256, requested, achieved, degraded, self_verify) =
            match from_value(&outcome.report)? {
                SealReply::Failed(failure) => return Err(failure.into_error()),
                SealReply::Sealed {
                    evidence_sha256,
                    requested,
                    achieved,
                    degraded,
                    self_verify,
                } => (evidence_sha256, requested, achieved, degraded, self_verify),
            };
        let sealed = outcome
            .outputs
            .iter()
            .find(|output| output.name == SEALED_OUTPUT && output.media_type == PDF)
            .ok_or_else(reply_invalid)?;
        Ok(EsignSealed {
            bytes: sealed.to_vec(),
            evidence_sha256: evidence_sha256
                .as_slice()
                .try_into()
                .map_err(|_| reply_invalid())?,
            requested,
            achieved,
            degraded,
            self_verify: self_verify.into_verdict(),
        })
    }

    fn verify(&self, pdf: &[u8]) -> Result<EsignVerdict, EsignSealerError> {
        let args = to_value(&VerifyArgs {
            now_ms: self.now_ms(),
            config: self.config(false)?,
        })
        .map_err(|_| reply_invalid())?;
        let lent = vec![LentInput {
            media_type: PDF.to_owned(),
            bytes: pdf.to_vec(),
        }];
        let outcome = self
            .host
            .call_with(
                self.vault,
                self.call(VERB_VERIFY, args),
                lent,
                &AskHandlers::none(),
            )
            .map_err(host_failure)?;
        match from_value(&outcome.report)? {
            VerifyReply::Verified(verdict) => Ok(verdict.into_verdict()),
            VerifyReply::Failed(failure) => Err(failure.into_error()),
        }
    }
}

/// `seal.identity`: the key's certificate and chain.
struct Identity<'k> {
    keys: &'k dyn SealKeys,
}

#[derive(Serialize)]
struct IdentityAnswer {
    algorithm: SealAlgorithm,
    signer_certificate: ByteBuf,
    chain: Vec<ByteBuf>,
}

impl AskHandler for Identity<'_> {
    fn answer(&self, ask: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        let identity = self.keys.identity(ask.deadline).map_err(key_refusal)?;
        let value = to_value(&IdentityAnswer {
            algorithm: identity.algorithm,
            signer_certificate: ByteBuf::from(identity.signer_certificate),
            chain: identity.chain.into_iter().map(ByteBuf::from).collect(),
        })?;
        Ok(Answered {
            value,
            ..Answered::default()
        })
    }
}

/// `seal.sign`: one signature, only under this call's operation.
struct Sign<'k> {
    keys: &'k dyn SealKeys,
    /// The call's operation id and a colon: every signature's operation
    /// starts with it.
    operation: String,
}

#[derive(Deserialize)]
struct SignAsk {
    operation_id: String,
    digest_algorithm: String,
    digest: ByteBuf,
}

#[derive(Serialize)]
struct SignAnswer {
    signature: ByteBuf,
}

impl AskHandler for Sign<'_> {
    fn answer(&self, ask: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        let request: SignAsk = from_value(ask.value)
            .map_err(|_| AskRefusal::new(AskCode::BadRequest, "not a signature ask"))?;
        if request.digest_algorithm != "sha256" {
            return Err(AskRefusal::new(AskCode::BadRequest, "only sha256"));
        }
        let digest: [u8; 32] = request
            .digest
            .as_slice()
            .try_into()
            .map_err(|_| AskRefusal::new(AskCode::BadRequest, "a digest is 32 bytes"))?;
        if !request.operation_id.starts_with(&self.operation) {
            return Err(AskRefusal::new(
                AskCode::BadRequest,
                "the operation is not this call's",
            ));
        }
        let signature = self
            .keys
            .sign_prehash(&request.operation_id, &digest, ask.deadline)
            .map_err(key_refusal)?;
        Ok(Answered {
            value: to_value(&SignAnswer {
                signature: ByteBuf::from(signature),
            })?,
            ..Answered::default()
        })
    }
}

/// `net.fetch`: the host's guarded fetch, for a timestamp or a CRL only,
/// each fetch inside the fetch timeout as well as the call's deadline, and
/// inside the seal's own cap for its purpose, so an oversized timestamp
/// reply is cut off before it spends the call's answer bytes.
struct TimedFetch {
    timeout: Duration,
}

impl AskHandler for TimedFetch {
    fn answer(&self, ask: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        let deadline = ask.deadline.min(Instant::now() + self.timeout);
        let purpose = ask.value.as_map().and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some("purpose"))
                .and_then(|(_, value)| value.as_str())
        });
        // The seal's caps: a CRL may be 8 MiB, a timestamp 1 MiB.
        let cap = match purpose {
            Some("crl") => MAX_CRL_BYTES,
            Some("tsa") => MAX_TSA_BYTES,
            _ => {
                return Err(AskRefusal::new(
                    AskCode::NotGranted,
                    "the seal fetches only timestamps and CRLs",
                ));
            }
        };
        GuardedFetch.answer(&AskRequest {
            deadline,
            max_bytes: ask.max_bytes.min(cap),
            ..*ask
        })
    }
}

fn key_refusal(err: SealKeyError) -> AskRefusal {
    let refusal = AskRefusal::new(AskCode::Failed, err.detail);
    if err.retryable {
        refusal.retryable()
    } else {
        refusal
    }
}

/// The seal's own name for a configuration it cannot use.
fn invalid_configuration() -> EsignSealerError {
    EsignSealerError::Fatal {
        stage: "input_validation".to_owned(),
        code: "invalid_configuration".to_owned(),
    }
}

fn reply_invalid() -> EsignSealerError {
    EsignSealerError::Fatal {
        stage: "organ".to_owned(),
        code: "reply_invalid".to_owned(),
    }
}

/// A host failure as the port's error: crash, backoff and a full budget
/// may pass; a missed deadline or a revoked grant may succeed next time;
/// the rest are fatal until something changes.
fn host_failure(err: HostError) -> EsignSealerError {
    let organ = |code: &str| EsignSealerError::Fatal {
        stage: "organ".to_owned(),
        code: code.to_owned(),
    };
    let retryable = |code: &str| EsignSealerError::Retryable {
        stage: "organ".to_owned(),
        code: code.to_owned(),
        retry_after_ms: None,
    };
    match err {
        HostError::Backoff { retry_after, .. } => EsignSealerError::Unavailable {
            retry_after_ms: Some(u64::try_from(retry_after.as_millis()).unwrap_or(u64::MAX)),
        },
        // A binary that cannot run stays that way until it is reinstalled.
        HostError::Io(err) if not_runnable(&err) => organ("not_runnable"),
        // The organ died or the host had no room: it may pass. A frame the
        // socket could not carry means the process was gone.
        HostError::Crashed(_)
        | HostError::StartFailed { .. }
        | HostError::BudgetTimeout
        | HostError::Io(_)
        | HostError::Frame(FrameError::Closed | FrameError::Io(_) | FrameError::TimedOut)
        | HostError::Unavailable {
            reason: Unavailable::Reinstalled | Unavailable::Quarantined,
            ..
        } => EsignSealerError::Unavailable {
            retry_after_ms: None,
        },
        HostError::DeadlineExceeded => retryable("deadline_exceeded"),
        HostError::Revoked
        | HostError::Unavailable {
            reason: Unavailable::Revoked,
            ..
        } => retryable("revoked"),
        HostError::Organ(err) if err.retryable => retryable(&name(&err.code)),
        HostError::Organ(err) => organ(&name(&err.code)),
        HostError::AskBudget => organ("ask_budget"),
        HostError::ReplyInvalid(_) => organ("reply_invalid"),
        HostError::NotInstalled(_) => organ("not_installed"),
        HostError::Unavailable { .. } => organ("unavailable"),
        _ => organ("host"),
    }
}

/// Whether starting the organ failed on its binary: missing, not
/// executable, or not a format the kernel runs. Told by errno, not by
/// kind: the sandbox's steps before exec never fail with these, and a
/// limit they are refused (EPERM) may pass.
fn not_runnable(err: &std::io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOENT | libc::EACCES | libc::ENOEXEC | libc::ENOTDIR)
    )
}

/// A unit enum's wire name.
fn name<T: Serialize>(value: &T) -> String {
    to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// MessagePack with named fields, so the organ reads it by name.
fn to_value<T: Serialize>(value: &T) -> Result<rmpv::Value, AskRefusal> {
    let failed =
        |err: &dyn std::fmt::Display| AskRefusal::new(AskCode::Failed, format!("encode: {err}"));
    let bytes = rmp_serde::to_vec_named(value).map_err(|err| failed(&err))?;
    rmpv::decode::read_value(&mut bytes.as_slice()).map_err(|err| failed(&err))
}

fn from_value<T: DeserializeOwned>(value: &rmpv::Value) -> Result<T, EsignSealerError> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| reply_invalid())?;
    rmp_serde::from_slice(&bytes).map_err(|_| reply_invalid())
}
