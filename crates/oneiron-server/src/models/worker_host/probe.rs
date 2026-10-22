//! The probes for the house llama.cpp and EXL3 workers (INFERENCE R1 rules,
//! R2 qualification): one actual chat answer, one token long, and the
//! identity it carries, checked against the worker's pins.
//!
//! EXL3: the answer's own inference receipt names the worker's kind, its
//! identity and how its build is known; a managed launch's answer must also
//! echo the digest of the launch manifest this supervisor gave it. A
//! version-string runtime is reported, never verified, so an EXL3 worker
//! started without a launch manifest is unverified. A launch with a native
//! socket is qualified there (DESIGN-V2 R1): its `hello`, then the same one
//! input, sent once per incarnation with the epoch the hello named; the hello
//! must name the answer's epoch, the wire model and this launch's manifest.
//!
//! llama.cpp: health is liveness only. The answer's `model` must be a launch
//! alias (one parse, `parse_llama_alias`), for a managed worker the one this
//! launch was given; the alias's manifest is fetched from the same origin
//! and kept only when its bytes hash to the alias's digest and it names the
//! alias's epoch and the configured wire id. This is the awaitable startup
//! check: the serving resolver (FIX 7895) stays nonblocking and is not used
//! here.
//!
//! A pinned value the answer contradicts is `Failed`; a pin or a piece of
//! evidence that is missing is `Unverified`; no answer is `Unreachable`.
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::PoisonError;

use oneiron::llm::{
    CacheDigest, CacheEpoch, CacheIdentity, INFERENCE_CALLS_KEY, WorkerBuildEvidence,
    WorkerDescriptor, WorkerFailure, WorkerKind, WorkerReadiness, parse_llama_alias,
};
use oneiron_driver::{WorkerProbe, WorkerProbeFuture, WorkerSpec};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use super::super::http::{KeyStyle, MAX_REPLY_BYTES, ProviderHttp};
use super::bundle::sha256_hex;
use super::launch_manifest::{LaunchRecord, LaunchSlot};
use crate::config::models::ProviderConfig;

/// The usage key an EXL3 answer echoes its launch manifest's digest under.
const LAUNCH_MANIFEST_KEY: &str = "launch_manifest";

/// The llama.cpp identity manifest schema this probe reads.
const LLAMA_SCHEMA_VERSION: u64 = 1;
const LLAMA_BACKEND: &str = "llama_cpp";

/// The one qualification input: a one-token answer to a fixed prompt, with
/// thinking off.
fn qualification_request(wire_model: &str) -> JsonValue {
    json!({
        "model": wire_model,
        "messages": [{"role": "user", "content": "Reply with one word."}],
        "max_tokens": 1,
        "temperature": 0,
        "stream": false,
        "chat_template_kwargs": {"enable_thinking": false},
    })
}

/// One house worker's probe, on its provider's route.
pub(super) struct HouseProbe {
    http: Result<ProviderHttp, String>,
    wire_model: String,
    /// A managed worker's current launch; `None` for an external worker.
    slot: Option<Arc<LaunchSlot>>,
}

impl HouseProbe {
    /// The probe of `wire_model` on `provider`, at `endpoint` in place of
    /// its base URL when an external row names one. A client that cannot be
    /// built (its key variable unset, say) leaves every answer unverified.
    pub(super) fn new(
        provider: &ProviderConfig,
        endpoint: Option<&str>,
        wire_model: &str,
        slot: Option<Arc<LaunchSlot>>,
    ) -> Self {
        let mut provider = provider.clone();
        if let Some(endpoint) = endpoint {
            endpoint.clone_into(&mut provider.base_url);
        }
        let http = ProviderHttp::direct(&provider, KeyStyle::Bearer).map_err(|error| {
            tracing::warn!(model = %wire_model, %error, "model worker probe unavailable");
            error.to_string()
        });
        Self {
            http,
            wire_model: wire_model.to_owned(),
            slot,
        }
    }

    fn launch(&self) -> Option<LaunchRecord> {
        self.slot
            .as_ref()
            .and_then(|slot| slot.lock().unwrap_or_else(PoisonError::into_inner).clone())
    }

    /// Sends the qualification input; the answer's body, or how it failed.
    async fn answer(&self, http: &ProviderHttp) -> Result<JsonValue, WorkerReadiness> {
        let reply = http
            .post_json(
                "/v1/chat/completions",
                &BTreeMap::new(),
                &qualification_request(&self.wire_model),
            )
            .await
            .map_err(|_| failed(WorkerFailure::Unreachable, None))?;
        let answered = reply
            .body
            .pointer("/choices/0")
            .is_some_and(JsonValue::is_object);
        if !(200..300).contains(&reply.status) || !answered {
            return Err(failed(WorkerFailure::InvalidReply, None));
        }
        Ok(reply.body)
    }

    /// The qualification answer: over the launch's native socket when it
    /// has one, with the worker's `hello` beside it, else over HTTP.
    async fn exl3_answer(
        &self,
        http: &ProviderHttp,
        launch: Option<&LaunchRecord>,
    ) -> Result<(JsonValue, Option<JsonValue>), WorkerReadiness> {
        match launch.and_then(|launch| launch.native_socket.as_deref()) {
            Some(socket) => native_answer(socket, &qualification_request(&self.wire_model))
                .await
                .map(|(hello, body)| (body, Some(hello)))
                .map_err(|failure| failed(failure, None)),
            None => self.answer(http).await.map(|body| (body, None)),
        }
    }

    async fn exl3(&self, http: &ProviderHttp, expected: &WorkerSpec) -> WorkerReadiness {
        let launch = self.launch();
        let (body, hello) = match self.exl3_answer(http, launch.as_ref()).await {
            Ok(answer) => answer,
            Err(readiness) => return readiness,
        };
        let worker = body
            .pointer("/usage")
            .and_then(|usage| usage.get(INFERENCE_CALLS_KEY))
            .and_then(|calls| calls.get(0))
            .and_then(|call| call.get("worker"))
            .and_then(|worker| WorkerDescriptor::deserialize(worker).ok());
        let Some(observed) = worker else {
            return WorkerReadiness::Unverified { observed: None };
        };
        if observed.kind != WorkerKind::Exl3 {
            return failed(WorkerFailure::KindMismatch, Some(observed));
        }
        if body.get("model").and_then(JsonValue::as_str) != Some(self.wire_model.as_str()) {
            return failed(WorkerFailure::ModelMismatch, Some(observed));
        }
        if let Some(launch) = &launch {
            let echoed = body
                .pointer("/usage")
                .and_then(|usage| usage.get(LAUNCH_MANIFEST_KEY))
                .and_then(JsonValue::as_str);
            match echoed {
                None => {
                    return WorkerReadiness::Unverified {
                        observed: Some(observed),
                    };
                }
                Some(echoed) if echoed != launch.manifest_sha256 => {
                    return failed(WorkerFailure::BuildMismatch, Some(observed));
                }
                Some(_) => {}
            }
        }
        if let Some(hello) = &hello
            && !hello_agrees(hello, &observed, &self.wire_model, launch.as_ref())
        {
            return failed(WorkerFailure::BuildMismatch, Some(observed));
        }
        judge(observed, &expected.expected, launch.as_ref())
    }

    async fn llama(&self, http: &ProviderHttp, expected: &WorkerSpec) -> WorkerReadiness {
        let body = match self.answer(http).await {
            Ok(body) => body,
            Err(readiness) => return readiness,
        };
        let returned = body.get("model").and_then(JsonValue::as_str);
        let Some(alias) = returned.and_then(parse_llama_alias) else {
            return WorkerReadiness::Unverified { observed: None };
        };
        let launch = self.launch();
        if let Some(launch) = &launch
            && launch.llama_alias.as_deref() != returned
        {
            let observed = epoch_only(alias.epoch);
            return failed(WorkerFailure::BuildMismatch, Some(observed));
        }
        let path = format!("/{}.json", alias.manifest.as_str());
        let manifest = match http.get_native_within(&path, MAX_REPLY_BYTES).await {
            Ok(reply) if (200..300).contains(&reply.status) => verify_llama(
                &reply.body,
                alias.manifest.as_str(),
                &alias.epoch,
                &self.wire_model,
            ),
            _ => None,
        };
        let Some(identity) = manifest else {
            return WorkerReadiness::Unverified {
                observed: Some(epoch_only(alias.epoch)),
            };
        };
        let build_evidence = if identity.runtime.is_some() {
            WorkerBuildEvidence::VerifiedArtifacts
        } else {
            WorkerBuildEvidence::Unknown
        };
        let observed = WorkerDescriptor {
            kind: WorkerKind::LlamaCpp,
            identity: CacheIdentity {
                execution_mode: None,
                backend_epoch: Some(alias.epoch),
                ..identity
            },
            build_evidence,
        };
        judge(observed, &expected.expected, launch.as_ref())
    }
}

impl WorkerProbe for HouseProbe {
    fn probe<'a>(&'a self, expected: &'a WorkerSpec) -> WorkerProbeFuture<'a> {
        Box::pin(async move {
            let http = match &self.http {
                Ok(http) => http,
                Err(_) => return WorkerReadiness::Unverified { observed: None },
            };
            match expected.kind {
                WorkerKind::Exl3 => self.exl3(http, expected).await,
                WorkerKind::LlamaCpp => self.llama(http, expected).await,
                _ => WorkerReadiness::Unverified { observed: None },
            }
        })
    }
}

/// A llama.cpp answer whose manifest did not resolve: its epoch alone.
fn epoch_only(epoch: CacheEpoch) -> WorkerDescriptor {
    WorkerDescriptor {
        kind: WorkerKind::LlamaCpp,
        identity: CacheIdentity {
            backend_epoch: Some(epoch),
            ..CacheIdentity::default()
        },
        build_evidence: WorkerBuildEvidence::Unknown,
    }
}

/// One qualification over the worker's native socket
/// (`models/native_exl3`): its `hello`, and its answer in the HTTP reply's
/// shape.
#[cfg(unix)]
async fn native_answer(
    socket: &Path,
    request: &JsonValue,
) -> Result<(JsonValue, JsonValue), WorkerFailure> {
    super::super::native_exl3::qualify(socket, request).await
}

#[cfg(not(unix))]
async fn native_answer(
    socket: &Path,
    request: &JsonValue,
) -> Result<(JsonValue, JsonValue), WorkerFailure> {
    let _ = (socket, request);
    Err(WorkerFailure::Unreachable)
}

/// Whether a native `hello` names the worker its answer did: an EXL3
/// worker, the answer's epoch, the configured wire model, and this launch's
/// manifest when the supervisor gave one. A worker whose channel and answer
/// disagree is not the launch this host started.
fn hello_agrees(
    hello: &JsonValue,
    observed: &WorkerDescriptor,
    wire_model: &str,
    launch: Option<&LaunchRecord>,
) -> bool {
    let kind = hello
        .pointer("/worker/kind")
        .and_then(|kind| WorkerKind::deserialize(kind).ok());
    let epoch = hello.get("epoch").and_then(JsonValue::as_str);
    let answered = observed.identity.backend_epoch.as_ref();
    let manifest = hello.get(LAUNCH_MANIFEST_KEY).and_then(JsonValue::as_str);
    kind == Some(WorkerKind::Exl3)
        && epoch.is_some()
        && epoch == answered.map(CacheEpoch::as_str)
        && hello.get("model").and_then(JsonValue::as_str) == Some(wire_model)
        && launch.is_none_or(|launch| manifest == Some(launch.manifest_sha256.as_str()))
}

fn failed(failure: WorkerFailure, observed: Option<WorkerDescriptor>) -> WorkerReadiness {
    WorkerReadiness::Failed { failure, observed }
}

/// The fields of a llama.cpp identity manifest this probe checks.
#[derive(Deserialize)]
struct LlamaManifest {
    schema_version: u64,
    backend: String,
    backend_epoch: CacheEpoch,
    configured_wire_id: String,
    identity: CacheIdentity,
}

/// The manifest's identity, when its exact bytes hash to `digest` and it
/// names `epoch`, the llama.cpp backend and `wire_model`.
fn verify_llama(
    bytes: &[u8],
    digest: &str,
    epoch: &CacheEpoch,
    wire_model: &str,
) -> Option<CacheIdentity> {
    if sha256_hex(bytes) != digest {
        return None;
    }
    let manifest: LlamaManifest = serde_json::from_slice(bytes).ok()?;
    (manifest.schema_version == LLAMA_SCHEMA_VERSION
        && manifest.backend == LLAMA_BACKEND
        && manifest.backend_epoch == *epoch
        && manifest.configured_wire_id == wire_model)
        .then_some(manifest.identity)
}

/// One pinned field of an identity.
type Field = fn(&CacheIdentity) -> &Option<CacheDigest>;

fn model(identity: &CacheIdentity) -> &Option<CacheDigest> {
    &identity.model
}

fn tokenizer(identity: &CacheIdentity) -> &Option<CacheDigest> {
    &identity.tokenizer
}

fn runtime(identity: &CacheIdentity) -> &Option<CacheDigest> {
    &identity.runtime
}

fn template(identity: &CacheIdentity) -> &Option<CacheDigest> {
    &identity.template
}

/// Whether `observed` serves as pinned: a contradiction of any pin, from the
/// config or this launch's verified bytes, is `Failed`; with no
/// contradiction, `Ready` needs model, runtime and template pinned and
/// observed (the tokenizer too when it is pinned), an epoch, and verified
/// artifacts; anything less is `Unverified`.
fn judge(
    observed: WorkerDescriptor,
    config: &CacheIdentity,
    launch: Option<&LaunchRecord>,
) -> WorkerReadiness {
    let pins: Vec<&CacheIdentity> = std::iter::once(config)
        .chain(launch.map(|launch| &launch.pins))
        .collect();
    let seen = &observed.identity;
    let checks: [(Field, WorkerFailure); 4] = [
        (model, WorkerFailure::ModelMismatch),
        (tokenizer, WorkerFailure::ModelMismatch),
        (runtime, WorkerFailure::BuildMismatch),
        (template, WorkerFailure::TemplateMismatch),
    ];
    for (field, failure) in checks {
        let contradicted = pins
            .iter()
            .filter_map(|pin| field(pin).as_ref())
            .any(|want| field(seen).as_ref().is_some_and(|got| got != want));
        if contradicted {
            return failed(failure, Some(observed));
        }
    }
    let pinned = |field: Field| pins.iter().any(|pin| field(pin).is_some());
    let required: [Field; 3] = [model, runtime, template];
    let complete = required
        .into_iter()
        .all(|field| pinned(field) && field(seen).is_some())
        && (!pinned(tokenizer) || seen.tokenizer.is_some())
        && seen.backend_epoch.is_some()
        && observed.build_evidence == WorkerBuildEvidence::VerifiedArtifacts;
    if complete {
        WorkerReadiness::Ready { observed }
    } else {
        WorkerReadiness::Unverified {
            observed: Some(observed),
        }
    }
}
