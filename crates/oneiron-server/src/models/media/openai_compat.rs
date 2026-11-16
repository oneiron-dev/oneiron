//! An OpenAI-compatible provider's media backend (ARCH-0036 `#adapters`,
//! MED-1 = A). Each family crate speaks its own calls over the provider's one
//! shared client: images and video jobs `oneiron_gen::openai_compat`, speech
//! and transcription `oneiron_speech::{tts, asr}::openai_compat`, embeddings
//! `oneiron_llm::openai_compat`. The seats' ladders name providers, so one
//! router per provider serves its rungs and hands each call to the family
//! backend that speaks it.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::media::{
    AiOperation, MediaBackend, MediaFuture, MediaJobState, MediaProgressFuture, MediaRequest,
    MediaResponse, ReferenceCompatibility,
};
use oneiron::llm::{BrokerIsolation, DispatchRelease};
use oneiron::{BudgetLease, LlmResult, ModelId};
use oneiron_gen::openai_compat::OpenAiGenBackend;
use oneiron_llm::openai_compat::{
    EmbedShape, OpenAiEmbedBackend, OpenAiMediaClient, OpenAiMediaTransport,
};
use oneiron_speech::asr::openai_compat::OpenAiAsrBackend;
use oneiron_speech::tts::openai_compat::OpenAiTtsBackend;

/// The media backend of the OpenAI-compatible provider at `endpoint` (its
/// base URL), sending over `transport`: each engine model in `wire_models`
/// by its provider name, its embeddings in `embed_shape` (FIX 866).
pub(in crate::models) fn openai_compat_media<T: OpenAiMediaTransport + 'static>(
    transport: T,
    wire_models: BTreeMap<ModelId, String>,
    endpoint: String,
    embed_shape: EmbedShape,
) -> Arc<dyn MediaBackend> {
    let client = Arc::new(OpenAiMediaClient::new(transport, wire_models, endpoint));
    Arc::new(OpenAiCompatMedia {
        generation: OpenAiGenBackend::new(Arc::clone(&client)),
        speech: OpenAiTtsBackend::new(Arc::clone(&client)),
        transcription: OpenAiAsrBackend::new(Arc::clone(&client)),
        embedding: OpenAiEmbedBackend::new(client).with_embed_shape(embed_shape),
    })
}

/// One provider's family backends over its one client. Each refuses every
/// call it does not speak, so a call reaches the one that does.
struct OpenAiCompatMedia<T> {
    generation: OpenAiGenBackend<T>,
    speech: OpenAiTtsBackend<T>,
    transcription: OpenAiAsrBackend<T>,
    embedding: OpenAiEmbedBackend<T>,
}

impl<T: OpenAiMediaTransport> OpenAiCompatMedia<T> {
    /// The family backend that speaks `operation`. A text call rides the
    /// chat wire, so the embedding backend, the text family's, refuses it.
    fn family(&self, operation: AiOperation) -> &dyn MediaBackend {
        match operation {
            AiOperation::Image | AiOperation::Video => &self.generation,
            AiOperation::Speech => &self.speech,
            AiOperation::Transcribe => &self.transcription,
            AiOperation::Embed | AiOperation::Text => &self.embedding,
        }
    }
}

impl<T: OpenAiMediaTransport> MediaBackend for OpenAiCompatMedia<T> {
    /// An image edit sends its mask; no other family's call carries one.
    fn supports_mask(&self) -> bool {
        self.generation.supports_mask()
    }

    fn run<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        self.family(request.operation).run(request, lease)
    }

    fn run_progress<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaProgressFuture<'a> {
        self.family(request.operation).run_progress(request, lease)
    }

    fn run_progress_released<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
        release: Option<DispatchRelease<'a>>,
    ) -> MediaProgressFuture<'a> {
        self.family(request.operation)
            .run_progress_released(request, lease, release)
    }

    /// A job is a video's, so its submit, poll and cancel are the
    /// generation family's.
    fn submit<'a>(
        &'a self,
        request: MediaRequest,
        key: Option<&'a str>,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, String> {
        self.generation.submit(request, key, lease)
    }

    fn submit_dedupes(&self) -> bool {
        self.generation.submit_dedupes()
    }

    fn poll<'a>(
        &'a self,
        model: &'a ModelId,
        job: &'a str,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaJobState> {
        self.generation.poll(model, job, lease)
    }

    fn cancel<'a>(
        &'a self,
        model: &'a ModelId,
        job: &'a str,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, ()> {
        self.generation.cancel(model, job, lease)
    }

    fn reference_compatibility(&self, request: &MediaRequest) -> ReferenceCompatibility {
        self.family(request.operation)
            .reference_compatibility(request)
    }

    fn preflight(&self, request: &MediaRequest) -> LlmResult<()> {
        self.family(request.operation).preflight(request)
    }

    /// Every family sends over the one client's transport, so each answers
    /// alike.
    fn broker_isolation(&self) -> Option<BrokerIsolation> {
        self.embedding.broker_isolation()
    }
}
