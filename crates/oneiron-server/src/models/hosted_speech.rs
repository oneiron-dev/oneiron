//! The hosts of the hosted speech wires that are not OpenAI-compatible:
//! ARCH-0061 §5's hosted realtime tier, Cartesia Sonic and its break-glass
//! fallback, ElevenLabs Flash. Their requests and replies are
//! `oneiron_speech::tts::hosted`'s. Each is a `[models.media.speech]` rung
//! like any other: one request per call, sent through the run's media gate
//! on its own permit and settled on the characters it spoke. Each provider
//! also clones: [`HostedCloner`] makes the provider voice a banked identity
//! renders as, asks whether one its vendor holds for verification is
//! verified, and deletes it, each call on its own paid permit, with the
//! requests and replies of `oneiron_speech::design`.
use std::collections::BTreeMap;

use oneiron::llm::media::{
    InterruptedMediaCall, MediaBackend, MediaFuture, MediaProgressFuture, MediaRequest,
    MediaResponse,
};
use oneiron::llm::run_admission::{CallOutcome, PaidConnector, RunAdmission};
use oneiron::voice_identity::ref_bank::VoiceRegisterClip;
use oneiron::{BudgetLease, FatalLlmError, LlmResult, ModelId, ModelLocality};
use oneiron_speech::design;
use oneiron_speech::design::hosted::{CloneForm, VendorVoice};
use oneiron_speech::tts::hosted::{HostedWire, build, parse};
use reqwest::multipart::{Form, Part};
use serde_json::Value as JsonValue;

use super::host_budgets::ModelHostBudgets;
use super::http::{HttpReleaseError, MediaSend, ProviderHttp, holding_replies};
use super::rerank::transport;

/// One hosted speech provider's media client, serving the models the speech
/// seat names on it.
pub(super) struct HostedSpeech {
    pub(super) http: ProviderHttp,
    pub(super) wire: HostedWire,
    /// Engine model id -> the provider's model id.
    pub(super) models: BTreeMap<ModelId, String>,
}

impl HostedSpeech {
    async fn speak(
        &self,
        mut request: MediaRequest,
        dispatch: Option<(oneiron::llm::DispatchRelease<'_>, &BudgetLease)>,
    ) -> LlmResult<MediaResponse> {
        let (text, path, body) = build(self.wire, &self.models, &mut request)?;
        let reply = match dispatch {
            Some((release, lease)) => self
                .http
                .send_json_released(&path, body, release, lease)
                .await
                .map_err(|error| match error {
                    HttpReleaseError::Transport(error) => transport(error),
                    HttpReleaseError::Release(error) => error,
                })?,
            None => self
                .http
                .send_media(&path, MediaSend::Json(body))
                .await
                .map_err(transport)?,
        };
        parse(
            reply.status,
            &reply.headers,
            &reply.body,
            request.model,
            &text,
        )
    }
}

impl MediaBackend for HostedSpeech {
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(self.speak(request, None))
    }

    fn run_progress_released<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
        release: Option<oneiron::llm::DispatchRelease<'a>>,
    ) -> MediaProgressFuture<'a> {
        Box::pin(async move {
            self.speak(request, release.map(|release| (release, lease)))
                .await
                .map_err(InterruptedMediaCall::nothing)
        })
    }
}

/// A hosted provider's clone wire: it makes a provider voice from a banked
/// identity's refs, and deletes one. The provider's id is a disposable
/// locator, never the identity; the bank records it only while the refs it
/// was made from, and the render consent that let them leave, stay current
/// (ARCH-0061 §5).
pub struct HostedCloner {
    pub(super) http: ProviderHttp,
    pub(super) wire: HostedWire,
    pub(super) locality: ModelLocality,
    /// What each clone call is admitted as on its caller's run (FIX 3009).
    pub(super) connector: PaidConnector,
    /// The vault's budgets its replies hold their bytes on (FIX 9321).
    pub(super) budgets: ModelHostBudgets,
}

impl HostedCloner {
    /// Where the provider runs: how far the voice's render consent must
    /// reach for its refs to go there.
    #[must_use]
    pub fn locality(&self) -> ModelLocality {
        self.locality
    }

    /// Whether a clone must name the language its clip is spoken in.
    #[must_use]
    pub fn needs_language(&self) -> bool {
        self.wire == HostedWire::Cartesia
    }

    /// Makes a provider voice named `name` from `clips`, on `run`. Cartesia
    /// takes one clip, made of every clip that joins into one (FIX 1567),
    /// and must be told its `language`; ElevenLabs takes them all, and may
    /// hold the voice until it is verified there.
    pub async fn create(
        &self,
        run: &RunAdmission,
        name: &str,
        clips: &[VoiceRegisterClip],
        language: Option<&str>,
    ) -> LlmResult<VendorVoice> {
        let request = design::hosted::clone_form(self.wire, name, clips, language)?;
        let path = request.path;
        let form = multipart(request)?;
        let http = &self.http;
        let body = self
            .paid(run, async move {
                let reply = http
                    .send_media(path, MediaSend::Multipart(form))
                    .await
                    .map_err(transport)?;
                let body = serde_json::from_slice(&reply.body).unwrap_or(JsonValue::Null);
                if !(200..300).contains(&reply.status) {
                    return Err(oneiron_llm::openai_compat::classify_openai_status(
                        reply.status,
                        &reply.headers,
                        &body,
                    ));
                }
                Ok(body)
            })
            .await?;
        design::hosted::cloned_voice(self.wire, &body)
    }

    /// Whether the provider voice `vendor_voice_id`, held for verification,
    /// is verified there now, on `run` (FIX 1567). ElevenLabs is asked for
    /// the voice's `voice_verification`; Cartesia holds none, so says yes
    /// without a call.
    pub async fn verified(&self, run: &RunAdmission, vendor_voice_id: &str) -> LlmResult<bool> {
        if self.wire == HostedWire::Cartesia {
            return Ok(true);
        }
        let path = design::hosted::voice_path(self.wire, vendor_voice_id)?;
        let http = &self.http;
        let body = self
            .paid(run, async move {
                let reply = http
                    .send_media(&path, MediaSend::Get)
                    .await
                    .map_err(transport)?;
                let body = serde_json::from_slice(&reply.body).unwrap_or(JsonValue::Null);
                if !(200..300).contains(&reply.status) {
                    return Err(oneiron_llm::openai_compat::classify_openai_status(
                        reply.status,
                        &reply.headers,
                        &body,
                    ));
                }
                Ok(body)
            })
            .await?;
        Ok(design::elevenlabs::is_verified(&body))
    }

    /// Deletes the provider voice `vendor_voice_id`, on `run`; one already
    /// gone counts as deleted.
    pub async fn delete(&self, run: &RunAdmission, vendor_voice_id: &str) -> LlmResult<()> {
        let path = design::hosted::voice_path(self.wire, vendor_voice_id)?;
        let http = &self.http;
        self.paid(run, async move {
            let reply = http
                .send_media(&path, MediaSend::Delete)
                .await
                .map_err(transport)?;
            if (200..300).contains(&reply.status) || reply.status == 404 {
                return Ok(());
            }
            let body = serde_json::from_slice(&reply.body).unwrap_or(JsonValue::Null);
            Err(oneiron_llm::openai_compat::classify_openai_status(
                reply.status,
                &reply.headers,
                &body,
            ))
        })
        .await
    }

    /// One clone call, `send`, on `run` (FIX 3009): admitted as this
    /// provider's clone connector before it goes out, its permit started
    /// just before the send and settled after, one unit an answered call. A
    /// refused call sends nothing.
    async fn paid<T>(
        &self,
        run: &RunAdmission,
        send: impl std::future::Future<Output = LlmResult<T>>,
    ) -> LlmResult<T> {
        let permit = run.admit_paid(&self.connector, 1)?;
        run.dispatch_paid(permit.lease(), &self.connector)?;
        // Its replies hold their bytes on the vault's line until it ends.
        let sent = holding_replies(&self.budgets, send).await;
        // The request went out: a failed one keeps its reservation as spend.
        let outcome = match &sent {
            Ok(_) => CallOutcome::UsedCounted(1),
            Err(_) => CallOutcome::Failed,
        };
        if let Err(denied) = permit.settle(outcome) {
            tracing::error!(%denied, "a voice clone call's settlement was refused");
        }
        sent
    }
}

/// A clone call's form as the multipart form it goes as; refused when a
/// clip's media type is not one.
fn multipart(request: CloneForm) -> LlmResult<Form> {
    let mut form = Form::new();
    for (name, value) in request.texts {
        form = form.text(name, value);
    }
    for file in request.files {
        let part = Part::bytes(file.bytes)
            .file_name(file.file_name)
            .mime_str(&file.media_type)
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        form = form.part(file.field, part);
    }
    Ok(form)
}
