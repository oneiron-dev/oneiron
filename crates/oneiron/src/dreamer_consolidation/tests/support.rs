//! Shared backend fixture for deadline-driven consolidation tests.
use super::*;

/// Advances the wake clock only when the selected provider response arrives.
pub(super) struct ExpiringBackend {
    pub(super) inner: ScriptedBackend,
    pub(super) clock: std::sync::Arc<AtomicU64>,
    pub(super) expire_on_call: usize,
    pub(super) expiry_elapsed_ms: u64,
    pub(super) calls: AtomicUsize,
    pub(super) native_json: bool,
}

impl LlmBackend for ExpiringBackend {
    fn supports(&self, _: &crate::ModelId, capability: crate::LlmCapability) -> bool {
        self.native_json && capability == crate::LlmCapability::JsonResponse
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move {
            let response = self.inner.generate(request, lease).await;
            if call == self.expire_on_call {
                self.clock.store(self.expiry_elapsed_ms, Ordering::SeqCst);
            }
            response
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(crate::LlmError::Fatal(crate::FatalLlmError::InvalidRequest))
    }
}

/// Thread-local capture of the production child-integrity warning, without a
/// process-global subscriber shared by parallel library tests.
#[derive(Clone, Default)]
pub(super) struct IntegrityCapture {
    markers: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl IntegrityCapture {
    pub(super) fn markers(&self) -> Vec<String> {
        self.markers.lock().expect("integrity capture").clone()
    }

    pub(super) fn with_default<T>(&self, f: impl FnOnce() -> T) -> T {
        let _other = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let dispatch = tracing::Dispatch::new(self.clone());
        tracing::dispatcher::with_default(&dispatch, f)
    }
}

impl tracing::Subscriber for IntegrityCapture {
    fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
        meta.level() == &tracing::Level::WARN && meta.target() == "oneiron::dreamer"
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Marker<'a>(&'a mut Vec<String>);
        impl tracing::field::Visit for Marker<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "child_integrity" {
                    self.0.push(format!("{value:?}"));
                }
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "child_integrity" {
                    self.0.push(value.to_owned());
                }
            }
        }
        let mut markers = self.markers.lock().expect("integrity capture");
        event.record(&mut Marker(&mut markers));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
