//! The raw `/v1/llm` routes' models and their own meter. Each call is a run
//! that declares nothing, on that meter, admitted rung by rung through the
//! run's gate.
use std::sync::Arc;

use oneiron::llm::SingleRouteBackend;
use oneiron::llm::run_admission::{
    BudgetLine, HostAccount, KeyCustody, LeaseUnit, OfferBinding, OfferRoute, Payer, PayerPerson,
    RunAdmission, RunDeclaration, RunDenied, RunReceiptSink,
};
use oneiron::{
    BudgetGuard, BudgetLease, FatalLlmError, LlmBackend, LlmCapability, LlmGenerateFuture,
    LlmRequest, LlmStreamResult, ModelId,
};

use super::{ModelRouter, OfferLadder, ServedOffer};

/// The run every raw call is admitted under, one run per call so that a
/// long-lived server keeps no per-call state.
const RAW_RUN: &str = "raw-inference";

#[derive(Clone)]
pub(crate) struct RawInference {
    models: RawModels,
    meter: BudgetGuard,
    host: Option<Arc<HostAccount>>,
    /// Who funds each call, when a room's root spend scope pays for them.
    payer: Option<PayerPerson>,
}

#[derive(Clone)]
enum RawModels {
    /// `[models]`: every configured model and seat by id.
    Configured(Arc<ModelRouter>),
    /// A host-injected backend serving every model a call names, each as
    /// one offer.
    Injected(Arc<dyn SingleRouteBackend>),
}

impl RawInference {
    pub(crate) fn configured(
        router: Arc<ModelRouter>,
        meter: BudgetGuard,
        host: Option<Arc<HostAccount>>,
    ) -> Self {
        Self {
            models: RawModels::Configured(router),
            meter,
            host,
            payer: None,
        }
    }

    pub(crate) fn injected(backend: Arc<dyn SingleRouteBackend>, meter: BudgetGuard) -> Self {
        Self {
            models: RawModels::Injected(backend),
            meter,
            host: None,
            payer: None,
        }
    }

    /// The raw routes' meter.
    pub(crate) fn meter(&self) -> &BudgetGuard {
        &self.meter
    }

    /// The ladder that serves `request`'s model, and the run the call is
    /// admitted under. `None` when no configured model has that id.
    pub(crate) fn call(
        &self,
        request: &LlmRequest,
        receipts: Arc<dyn RunReceiptSink>,
    ) -> Option<(Arc<OfferLadder>, RunAdmission)> {
        let ladder = match &self.models {
            RawModels::Configured(router) => router.served(&request.model)?.1,
            RawModels::Injected(backend) => Arc::new(OfferLadder::injected(ServedOffer {
                binding: injected_offer(request)?,
                backend: Arc::clone(backend),
            })),
        };
        let run = funded_run(
            RAW_RUN,
            self.meter.clone(),
            self.host.clone(),
            receipts,
            self.payer.clone(),
        );
        Some((ladder, run))
    }

    /// Records a raw call refused before admission under the run it would
    /// have been admitted in: one `Denied` row, nothing reserved. It needs no
    /// model backend, so a server with none still writes the row.
    pub(crate) fn refuse(
        request: &LlmRequest,
        reason: RunDenied,
        receipts: Arc<dyn RunReceiptSink>,
    ) {
        // The row names the run, its revision and the denial, and reads no
        // line: the run's own line is empty and reserves nothing.
        let line = BudgetLine {
            limit_units: 0,
            reserve_units: 0,
            unit: LeaseUnit::tokens(),
        };
        RunAdmission::new(RAW_RUN, RunDeclaration::undeclared(line), None, receipts).refuse(
            None,
            request.model.as_str(),
            reason,
        );
    }
}

/// A host-injected backend as a model backend for engine code that calls one
/// itself (code mode's executor): every call is its own undeclared run on the
/// host's meter, sent through the run's gate. The caller's lease carries no
/// spend.
pub(crate) struct InjectedRuns {
    raw: RawInference,
    backend: Arc<dyn SingleRouteBackend>,
    receipts: Arc<dyn RunReceiptSink>,
}

impl InjectedRuns {
    pub(crate) fn new(
        backend: Arc<dyn SingleRouteBackend>,
        meter: BudgetGuard,
        receipts: Arc<dyn RunReceiptSink>,
    ) -> Self {
        Self::funded(backend, meter, receipts, None)
    }

    /// [`Self::new`] for a reader child a room's root spend scope pays for
    /// (OF-531): each call's run binds `payer`.
    pub(crate) fn funded(
        backend: Arc<dyn SingleRouteBackend>,
        meter: BudgetGuard,
        receipts: Arc<dyn RunReceiptSink>,
        payer: Option<PayerPerson>,
    ) -> Self {
        Self {
            raw: RawInference {
                payer,
                ..RawInference::injected(Arc::clone(&backend), meter)
            },
            backend,
            receipts,
        }
    }
}

impl LlmBackend for InjectedRuns {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.backend.supports(model, capability)
    }

    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let (ladder, run) = self
                .raw
                .call(&request, Arc::clone(&self.receipts))
                .ok_or(FatalLlmError::InvalidRequest)?;
            ladder.generate(&run, request, None).await
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        let (ladder, run) = self
            .raw
            .call(&request, Arc::clone(&self.receipts))
            .ok_or(FatalLlmError::InvalidRequest)?;
        ladder.stream(&run, request, None)
    }
}

/// A host-injected backend's offer for one call: the host's own route, at
/// the locality the vault authorized for the model, paid with the host's own
/// key. Never unmetered, whatever the locality.
fn injected_offer(request: &LlmRequest) -> Option<OfferBinding> {
    Some(OfferBinding {
        offer: format!("host-injected:{}", request.model),
        model: request.model.clone(),
        route: OfferRoute::new("host-injected", "host").ok()?,
        locality: request.envelope.locality,
        payer: Payer::CustomerKey,
        credential_binding: None,
        catalog_revision: None,
        custody: KeyCustody::T1,
        rates: Vec::new(),
        payer_person: None,
    })
}

/// A run that declares nothing, on a meter its host built (see
/// [`super::undeclared_run`]), funded by `payer` when a room's root spend
/// scope pays for its calls (OF-531): each permit binds the PERSON and the
/// account the host resolved before the run began. `None` is the vault
/// owner's run.
pub(crate) fn funded_run(
    run: impl Into<String>,
    meter: BudgetGuard,
    host: Option<Arc<HostAccount>>,
    receipts: Arc<dyn RunReceiptSink>,
    payer: Option<PayerPerson>,
) -> RunAdmission {
    let line = BudgetLine {
        limit_units: meter.read().limit_units,
        reserve_units: meter.reserve_units(),
        unit: LeaseUnit::tokens(),
    };
    let declaration = RunDeclaration::undeclared(line);
    RunAdmission::with_payer(run, declaration, meter, host, receipts, payer)
}
