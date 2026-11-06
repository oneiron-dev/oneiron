//! One exact generation keeps its request owner while a rung is bound.

use oneiron::code_run::{CACHE_BOUNDARIES_KEY, CacheBoundary, HOST_PROVIDER_OPTIONS};
use serde::Deserialize;

use super::*;

pub(super) struct RetainedBinding<'a> {
    request: &'a mut LlmRequest,
    model: ModelId,
    locality: ModelLocality,
    manifest: Option<Arc<SegmentManifest>>,
    cache: Option<JsonValue>,
    prompt: Option<LlmMessage>,
    prompted: bool,
    bound: bool,
}

impl<'a> RetainedBinding<'a> {
    pub(super) fn new(rung: &LadderRung, request: &'a mut LlmRequest) -> Self {
        let model = std::mem::replace(&mut request.model, rung.model.clone());
        let locality =
            std::mem::replace(&mut request.envelope.locality, rung.offer.binding.locality);
        let mut manifest = None;
        let mut cache = None;
        if let Some(prompt) = &rung.prompt {
            request.messages.insert(
                0,
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: prompt.clone(),
                    }],
                },
            );
            if let Some(value) = request
                .provider_options
                .get_mut(HOST_PROVIDER_OPTIONS)
                .and_then(JsonValue::as_object_mut)
                .and_then(|options| options.get_mut(CACHE_BOUNDARIES_KEY))
                && let Ok(boundaries) = Vec::<CacheBoundary>::deserialize(&*value)
            {
                let shifted: Vec<_> = boundaries
                    .into_iter()
                    .map(|boundary| match boundary {
                        CacheBoundary::Message { message, part } => CacheBoundary::Message {
                            message: message.saturating_add(1),
                            part,
                        },
                        tool @ CacheBoundary::Tool { .. } => tool,
                    })
                    .collect();
                if let Ok(shifted) = serde_json::to_value(&shifted) {
                    cache = Some(std::mem::replace(value, shifted));
                }
            }
            manifest = request.host_segments.take();
            if let Some(original) = &manifest {
                let mut shifted = Vec::with_capacity(original.segments().len() + 1);
                shifted.push(Segment::whole(SegmentKind::System, SegmentClock::Epoch, 0));
                shifted.extend(original.segments().iter().map(|segment| Segment {
                    message: segment.message + 1,
                    ..segment.clone()
                }));
                request.host_segments =
                    Some(Arc::new(original.restamped(shifted, &request.messages)));
            }
        }
        Self {
            request,
            model,
            locality,
            manifest,
            cache,
            prompt: None,
            prompted: rung.prompt.is_some(),
            bound: true,
        }
    }

    pub(super) fn request(&self) -> &LlmRequest {
        self.request
    }

    pub(super) fn set_bound(&mut self, bound: bool) {
        if self.bound == bound {
            return;
        }
        std::mem::swap(&mut self.request.model, &mut self.model);
        std::mem::swap(&mut self.request.envelope.locality, &mut self.locality);
        if self.prompted {
            if bound {
                self.request
                    .messages
                    .insert(0, self.prompt.take().expect("saved rung prompt"));
            } else {
                self.prompt = Some(self.request.messages.remove(0));
            }
            std::mem::swap(&mut self.request.host_segments, &mut self.manifest);
            if let Some(cache) = self.cache.as_mut() {
                let current = self
                    .request
                    .provider_options
                    .get_mut(HOST_PROVIDER_OPTIONS)
                    .and_then(JsonValue::as_object_mut)
                    .and_then(|options| options.get_mut(CACHE_BOUNDARIES_KEY))
                    .expect("bound cache descriptor remains present");
                std::mem::swap(current, cache);
            }
        }
        self.bound = bound;
    }
}

impl Drop for RetainedBinding<'_> {
    fn drop(&mut self) {
        self.set_bound(false);
    }
}

/// The generation walk's immutable metadata, separate from its request borrow.
#[derive(Clone, Copy)]
pub(super) struct GenerationFrame<'a> {
    pub(super) run: &'a RunAdmission,
    pub(super) selector: Option<&'a str>,
    pub(super) routes: &'a WorldModelRoutes,
    pub(super) deadline: CallDeadline,
}

impl<'a> GenerationFrame<'a> {
    pub(super) fn call<'b>(&self, request: &'b LlmRequest) -> Call<'b>
    where
        'a: 'b,
    {
        Call {
            run: self.run,
            request,
            selector: self.selector,
            needs: Needs::Chat {
                request,
                stream: false,
            },
            routes: self.routes,
            deadline: self.deadline,
        }
    }
}

pub(super) enum GenerationInput<'a> {
    Copied(&'a LlmRequest),
    Retained(&'a mut LlmRequest),
}

impl GenerationInput<'_> {
    pub(super) fn original(&self) -> &LlmRequest {
        match self {
            Self::Copied(request) => request,
            Self::Retained(request) => request,
        }
    }

    pub(super) fn prepare(&mut self, rung: &LadderRung) -> PreparedGeneration<'_> {
        match self {
            Self::Copied(request) => PreparedGeneration::Copied {
                original: request,
                bound: Some(rung.bind((*request).clone())),
            },
            Self::Retained(request) => {
                PreparedGeneration::Retained(RetainedBinding::new(rung, request))
            }
        }
    }
}

pub(super) enum PreparedGeneration<'a> {
    Copied {
        original: &'a LlmRequest,
        bound: Option<LlmRequest>,
    },
    Retained(RetainedBinding<'a>),
}

impl PreparedGeneration<'_> {
    pub(super) fn original(&mut self) -> &LlmRequest {
        match self {
            Self::Copied { original, .. } => original,
            Self::Retained(binding) => {
                binding.set_bound(false);
                binding.request()
            }
        }
    }

    pub(super) fn bound(&mut self) -> &LlmRequest {
        match self {
            Self::Copied { bound, .. } => bound.as_ref().expect("unsent rung request"),
            Self::Retained(binding) => {
                binding.set_bound(true);
                binding.request()
            }
        }
    }

    pub(super) fn generate<'a>(
        &'a mut self,
        gate: &'a oneiron::llm::run_admission::GatedBackend,
        lease: &'a oneiron::BudgetLease,
    ) -> oneiron::LlmGenerateFuture<'a> {
        match self {
            Self::Copied { bound, .. } => {
                gate.generate(bound.take().expect("unsent rung request"), lease)
            }
            Self::Retained(binding) => {
                binding.set_bound(true);
                gate.generate_borrowed(binding.request(), lease)
            }
        }
    }
}

impl OfferLadder {
    pub(super) fn generate_retained_from<'a>(
        &'a self,
        run: &'a RunAdmission,
        request: LlmRequest,
        selector: Option<&'a str>,
        may_send: &'a (dyn Fn() -> bool + Sync),
        deadline: CallDeadline,
    ) -> ServedFuture<'a> {
        Box::pin(async move {
            self.walk_generate(
                run, request, selector, may_send, deadline, false, None, true,
            )
            .await
        })
    }
}
