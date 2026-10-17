//! One run admission: each paid call of a run, to a model or to a paid
//! connector, is admitted against the run's own declaration and its lease,
//! and gets a one-use permit bound to the run, the model, the route, the
//! locality and the offer that pays.
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::Serialize;

use super::super::media::{MediaBackend, MediaRequest};
use super::super::{
    BudgetDenied, BudgetExhaustionPolicy, BudgetGuard, BudgetLease, BudgetRead, DispatchBinding,
    DispatchRefused, LlmBackend, LlmError, LlmRequest, LlmResponse, ModelId, RetryableLlmError,
    SingleRouteBackend,
};
use super::declaration::{DeclarationEditor, LeaseUnit, RunDeclaration};
use super::gate::{Dispatch, GatedBackend};
use super::host::{AllocationRefusal, HostAccount, OfferBinding, PaidConnector, PayerPerson};
use super::media::MediaGate;
use super::permit::RunPermit;
use super::receipt::{CalledTeacher, RunEvent, RunReceipt, RunReceiptSink, TeacherReport};
use super::settle::CallOutcome;

/// The subject of the `Denied` row for a selector the run could not resolve:
/// the row keeps none of the selector's bytes.
pub const UNRESOLVED_SELECTOR: &str = "unresolved-selector";

/// Why the run admission refused a call or an edit. Every refusal comes
/// before any byte leaves and leaves no reservation behind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunDenied {
    #[error("the run did not declare teacher {model}")]
    UndeclaredTeacher { model: ModelId },
    /// The selector names no model id and no alias the run froze. A caller
    /// may pass any text there, so the denial keeps only its length.
    #[error("the run knows no model or alias by the {len}-byte selector given")]
    UnknownSelector { len: usize },
    #[error("the offer binds another model than the call names")]
    OfferMismatch,
    #[error("no offer on this host serves {model}")]
    NoOffer { model: ModelId },
    #[error("the call's locality differs from its route's")]
    LocalityMismatch,
    #[error("the call picks its model or route through {key}")]
    RouteOverride { key: String },
    #[error("the route's backend refused the call before sending it")]
    BackendRefused,
    #[error("a declared run keeps its paid keys at T0")]
    KeyAtT1,
    #[error("the run did not declare connector {connector}")]
    UndeclaredConnector { connector: String },
    #[error("no rate converts {from:?} into {to:?}")]
    UnitMismatch { from: LeaseUnit, to: LeaseUnit },
    #[error("budget: {denied}")]
    Budget { denied: BudgetDenied },
    #[error("the host has delivered no allocation")]
    NoAllocation,
    #[error("the allocation is spent")]
    AllocationExhausted,
    #[error("the host refused a fresh allocation: {reason:?}")]
    AllocationRefused { reason: AllocationRefusal },
    #[error("dispatch refused: {refused}")]
    Dispatch { refused: DispatchRefused },
    #[error("a run never edits its own declaration")]
    DeclarationEditRefused,
    /// A fallback to this offer would take the call's work off the device
    /// while its world stays here.
    #[error("the call's world stays on this device")]
    KeptOnDevice,
}

impl From<RunDenied> for LlmError {
    fn from(denied: RunDenied) -> Self {
        match denied {
            RunDenied::Budget { denied } => Self::BudgetDenied(denied),
            RunDenied::NoAllocation
            | RunDenied::AllocationExhausted
            | RunDenied::AllocationRefused { .. } => Self::BudgetDenied(BudgetDenied::Exhausted),
            RunDenied::Dispatch { refused } => Self::BudgetDenied(refused.into()),
            // A privacy hold stays one: never a budget refusal.
            RunDenied::KeptOnDevice => Self::Retryable(RetryableLlmError::KeptOnDevice {
                retry_after: None,
                resets_at: Vec::new(),
            }),
            RunDenied::UndeclaredTeacher { .. }
            | RunDenied::UnknownSelector { .. }
            | RunDenied::OfferMismatch
            | RunDenied::NoOffer { .. }
            | RunDenied::LocalityMismatch
            | RunDenied::RouteOverride { .. }
            | RunDenied::BackendRefused
            | RunDenied::KeyAtT1
            | RunDenied::UndeclaredConnector { .. }
            | RunDenied::UnitMismatch { .. }
            | RunDenied::DeclarationEditRefused => {
                Self::BudgetDenied(BudgetDenied::AdmissionDenied)
            }
        }
    }
}

/// One model call a run asks to make.
#[derive(Debug, Clone, Copy)]
pub struct RunCall<'a> {
    /// What the caller named, an alias or an id, for the receipt.
    pub selector: Option<&'a str>,
    pub request: &'a LlmRequest,
    pub offer: &'a OfferBinding,
}

/// A refused or failed call through [`RunAdmission::call`].
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum RunCallError {
    #[error(transparent)]
    Denied(#[from] RunDenied),
    /// The provider failed. A settlement the meter refused rides along.
    #[error("model call failed: {error}")]
    Failed {
        error: LlmError,
        settlement: Option<RunDenied>,
    },
}

/// One run's admission: its declaration, its budget line, the host's inputs
/// and its receipts. Cloning shares the run.
#[derive(Clone)]
pub struct RunAdmission {
    inner: Arc<RunInner>,
}

pub(super) struct RunInner {
    instance: crate::EntityId,
    run: String,
    declaration: Mutex<Revisioned>,
    pub(super) guard: BudgetGuard,
    pub(super) host: Option<Arc<HostAccount>>,
    /// Who funds the run's calls when a room's root spend scope pays for
    /// them (OF-531), fixed when the run starts.
    pub(super) payer: Option<PayerPerson>,
    receipts: Arc<dyn RunReceiptSink>,
    calls: Mutex<BTreeMap<String, CallFacts>>,
    /// The open paid-connector permits' leases. A model permit's lease is in
    /// `calls`. A meter other runs share issues their leases too, so the
    /// meter alone cannot tell a permit's run.
    paid: Mutex<BTreeSet<String>>,
}

struct Revisioned {
    revision: u32,
    declaration: RunDeclaration,
}

pub(super) struct CallFacts {
    /// The declaration revision the call was admitted under.
    revision: u32,
    model: ModelId,
    request_digest: Option<String>,
    served_model: Option<String>,
    pub(super) settled_units: Option<u64>,
}

impl RunAdmission {
    /// Starts a run at revision 1 of `declaration`, on its own budget line.
    /// `host` is the account whose allocation pays host-paid offers; a
    /// self-hosted vault has none, and its runs admit no host-paid offer.
    #[must_use]
    pub fn new(
        run: impl Into<String>,
        declaration: RunDeclaration,
        host: Option<Arc<HostAccount>>,
        receipts: Arc<dyn RunReceiptSink>,
    ) -> Self {
        let run = run.into();
        let budget = declaration.budget();
        let guard = BudgetGuard::with_reserve_units(
            run.clone(),
            budget.limit_units,
            budget.reserve_units,
            BudgetExhaustionPolicy::Suspend,
        );
        Self::with_meter(run, declaration, guard, host, receipts)
    }

    /// Starts a run at revision 1 of `declaration` on a meter the host built
    /// for its line, such as the vault's budget policy for one actor's calls.
    /// `meter` holds the line `declaration.budget()` names, and each call
    /// reserves that line's `reserve_units` on it. Runs that share a meter
    /// share its line, never their permits: a permit starts only at the gate
    /// of the run that admitted it.
    #[must_use]
    pub fn with_meter(
        run: impl Into<String>,
        declaration: RunDeclaration,
        meter: BudgetGuard,
        host: Option<Arc<HostAccount>>,
        receipts: Arc<dyn RunReceiptSink>,
    ) -> Self {
        Self::with_payer(run, declaration, meter, host, receipts, None)
    }

    /// Starts a run as [`Self::with_meter`] does, funded by `payer`: the
    /// PERSON a room's root spend scope names and the account the host
    /// resolved for it before the run began (OF-531). Every offer the run
    /// admits or gates binds that payer, so its permits, its receipts and its
    /// offer identities carry it. `None` is a run no room pays for.
    #[must_use]
    pub fn with_payer(
        run: impl Into<String>,
        declaration: RunDeclaration,
        meter: BudgetGuard,
        host: Option<Arc<HostAccount>>,
        receipts: Arc<dyn RunReceiptSink>,
        payer: Option<PayerPerson>,
    ) -> Self {
        let run = run.into();
        Self {
            inner: Arc::new(RunInner {
                instance: crate::EntityId::now(),
                run,
                declaration: Mutex::new(Revisioned {
                    revision: 1,
                    declaration,
                }),
                guard: meter,
                host,
                payer,
                receipts,
                calls: Mutex::new(BTreeMap::new()),
                paid: Mutex::new(BTreeSet::new()),
            }),
        }
    }

    #[must_use]
    pub fn run(&self) -> &str {
        &self.inner.run
    }

    /// Who funds this run's calls, when a room's root spend scope does.
    #[must_use]
    pub fn payer(&self) -> Option<&PayerPerson> {
        self.inner.payer.as_ref()
    }

    /// The run's budget line as its meter reads now.
    #[must_use]
    pub fn read(&self) -> BudgetRead {
        self.inner.guard.read()
    }

    #[must_use]
    pub fn revision(&self) -> u32 {
        self.inner.lock_declaration().revision
    }

    #[must_use]
    pub fn declaration(&self) -> RunDeclaration {
        self.inner.lock_declaration().declaration.clone()
    }

    /// The model a caller's selector names: an exact id, or an alias through
    /// the map the run froze at its start.
    pub fn resolve(&self, selector: &str) -> Result<ModelId, RunDenied> {
        let declaration = self.declaration();
        if let Some(model) = declaration
            .teachers()
            .and_then(|teachers| teachers.alias(selector))
        {
            return Ok(model.clone());
        }
        ModelId::new(selector).map_err(|_| RunDenied::UnknownSelector {
            len: selector.len(),
        })
    }

    /// Records a call the host refused before admission, such as one whose
    /// body picks its own route or one naming a model no offer serves: one
    /// `Denied` row, nothing reserved. Returns `reason`.
    pub fn refuse(&self, selector: Option<&str>, subject: &str, reason: RunDenied) -> RunDenied {
        let revision = self.revision();
        self.inner.record(
            revision,
            RunEvent::Denied {
                selector: selector.map(str::to_owned),
                subject: Some(subject.to_owned()),
                lease: None,
                reason: reason.clone(),
            },
        );
        reason
    }

    /// Admits one model call: the declared teachers, the host's offer, the
    /// key's rung, then the run's line and, for a host-paid offer, the
    /// vault's allocation.
    pub fn admit(&self, call: RunCall<'_>) -> Result<RunPermit, RunDenied> {
        self.admit_bound(call, None)
    }

    /// Admits one model call whose offer's backend builds its exact request
    /// bytes before it sends, as a credential broker's adapter does (ARCH-0069
    /// `#broker-run-admission`). The permit binds `request_digest`, the
    /// backend's [`SingleRouteBackend::request_digest`] for the call, so the
    /// gate starts it only for those bytes.
    pub fn admit_request(
        &self,
        call: RunCall<'_>,
        request_digest: &str,
    ) -> Result<RunPermit, RunDenied> {
        self.admit_bound(call, Some(request_digest.to_owned()))
    }

    fn admit_bound(
        &self,
        call: RunCall<'_>,
        request_digest: Option<String>,
    ) -> Result<RunPermit, RunDenied> {
        let offer = self.inner.bound(call.offer);
        let call = RunCall {
            offer: &*offer,
            ..call
        };
        let (revision, declaration) = self.inner.snapshot();
        let admitted = self
            .inner
            .admit_model(&declaration, revision, call, request_digest);
        self.inner.receipt_for(
            revision,
            call.selector,
            call.request.model.as_str(),
            admitted,
            Some(call.request.model.clone()),
        )
    }

    /// Admits one paid call that is not a model call: `quantity` units of the
    /// connector's service, reserved at its pack row's cost.
    pub fn admit_paid(
        &self,
        connector: &PaidConnector,
        quantity: u64,
    ) -> Result<RunPermit, RunDenied> {
        let (revision, declaration) = self.inner.snapshot();
        let admitted = self
            .inner
            .admit_connector(&declaration, revision, connector, quantity);
        self.inner
            .receipt_for(revision, None, &connector.connector, admitted, None)
    }

    /// The only backend a host hands a run for `offer`, over that offer's own
    /// backend and credential: it checks and starts the call's permit before
    /// any byte leaves, on `generate` and `stream`. A permit admitted under
    /// another offer never starts here, whatever route the two share.
    #[must_use]
    pub fn gate(&self, inner: Arc<dyn SingleRouteBackend>, offer: &OfferBinding) -> GatedBackend {
        let offer = self.inner.bound(offer).dispatch_binding();
        GatedBackend::new(Arc::clone(&self.inner), inner, offer)
    }

    /// Admits one media call (`ai.image`, `ai.video`, `ai.speech`,
    /// `ai.transcribe`, `ai.embed`) as the text call its admission request
    /// names: the same teachers, offer, locality and route rules, and one
    /// permit for one physical call.
    pub fn admit_media(
        &self,
        selector: Option<&str>,
        request: &MediaRequest,
        offer: &OfferBinding,
    ) -> Result<RunPermit, RunDenied> {
        let admission = request.admission_request();
        self.admit(RunCall {
            selector,
            request: &admission,
            offer,
        })
    }

    /// Admits one bounded media stream (live `ai.transcribe` partials) as
    /// [`Self::admit_media`] admits one call, on one permit for the whole
    /// stream. The permit reserves `reserve_units`, the stream's bound at its
    /// rung's rate ([`MediaStreamLease::reserve_units`](super::MediaStreamLease::reserve_units)), in place of one
    /// call's reservation; the run's line and the vault's allocation must
    /// hold all of it before any audio leaves.
    pub fn admit_media_stream(
        &self,
        selector: Option<&str>,
        request: &MediaRequest,
        offer: &OfferBinding,
        reserve_units: u64,
    ) -> Result<RunPermit, RunDenied> {
        let admission = request.admission_request();
        let offer = self.inner.bound(offer);
        let call = RunCall {
            selector,
            request: &admission,
            offer: &*offer,
        };
        let (revision, declaration) = self.inner.snapshot();
        let declaration = declaration.with_reserve(reserve_units);
        let admitted = self.inner.admit_model(&declaration, revision, call, None);
        self.inner.receipt_for(
            revision,
            selector,
            admission.model.as_str(),
            admitted,
            Some(admission.model.clone()),
        )
    }

    /// The only media backend a host hands a run for `offer`: it checks and
    /// starts a media call's permit before any byte leaves, as
    /// [`Self::gate`] does for a text call.
    #[must_use]
    pub fn media_gate(&self, inner: Arc<dyn MediaBackend>, offer: &OfferBinding) -> MediaGate {
        let offer = self.inner.bound(offer).dispatch_binding();
        MediaGate::new(Arc::clone(&self.inner), inner, offer)
    }

    /// The dispatch check a paid connector's adapter makes before it sends,
    /// for the connector binding whose credential it is about to use.
    pub fn dispatch_paid(
        &self,
        lease: &BudgetLease,
        connector: &PaidConnector,
    ) -> Result<(), RunDenied> {
        self.inner
            .begin_dispatch(lease, &connector.dispatch_binding())
    }

    /// Admits, sends through `gated` and settles one model call. A call
    /// dropped before it ends settles as failed. A backend that names the
    /// digest of its request bytes gets a permit bound to them.
    pub async fn call(
        &self,
        gated: &GatedBackend,
        call: RunCall<'_>,
    ) -> Result<LlmResponse, RunCallError> {
        // A request the backend cannot build is admitted unbound: the gate's
        // preflight then refuses it with a denial row.
        let permit = match gated.request_digest(call.request) {
            Some(digest) => self.admit_request(call, &digest)?,
            None => self.admit(call)?,
        };
        match gated.generate(call.request.clone(), permit.lease()).await {
            Ok(response) => {
                permit.settle(CallOutcome::Answered(&response.usage))?;
                Ok(response)
            }
            Err(error) => Err(RunCallError::Failed {
                error,
                settlement: permit.settle(CallOutcome::Failed).err(),
            }),
        }
    }

    /// A new revision of the declaration, from its owner or its host. The run
    /// itself is refused, and the refusal is receipted.
    pub fn revise(
        &self,
        editor: DeclarationEditor,
        next: RunDeclaration,
    ) -> Result<u32, RunDenied> {
        let mut current = self.inner.lock_declaration();
        let from = current.revision;
        let refused = if editor == DeclarationEditor::Run {
            Some(RunDenied::DeclarationEditRefused)
        } else if next.budget().unit != current.declaration.budget().unit {
            Some(RunDenied::UnitMismatch {
                from: current.declaration.budget().unit.clone(),
                to: next.budget().unit.clone(),
            })
        } else {
            None
        };
        if let Some(reason) = refused {
            drop(current);
            self.inner.record(
                from,
                RunEvent::Denied {
                    selector: None,
                    subject: None,
                    lease: None,
                    reason: reason.clone(),
                },
            );
            return Err(reason);
        }
        if next.budget() != current.declaration.budget() {
            self.inner
                .guard
                .revise_line(next.budget().limit_units, next.budget().reserve_units);
        }
        current.revision = from.saturating_add(1);
        current.declaration = next;
        let revision = current.revision;
        drop(current);
        self.inner
            .record(revision, RunEvent::Revised { editor, from });
        Ok(revision)
    }

    /// The declared teachers next to the teachers this run called.
    #[must_use]
    pub fn teacher_report(&self) -> TeacherReport {
        let declared = self
            .declaration()
            .teachers()
            .map(|teachers| teachers.models().cloned().collect())
            .unwrap_or_default();
        let called = self
            .inner
            .lock_calls()
            .iter()
            .filter_map(|(lease, facts)| {
                Some(CalledTeacher {
                    model: facts.model.clone(),
                    served_model: facts.served_model.clone(),
                    request_digest: facts.request_digest.clone()?,
                    lease: lease.clone(),
                    settled_units: facts.settled_units,
                })
            })
            .collect();
        TeacherReport { declared, called }
    }
}

impl RunInner {
    /// `offer` as this run binds it: with the run's payer when a room's root
    /// spend scope funds the run (OF-531). Admission and the gate both take
    /// this one binding, so the permit's offer identity is the one the gate
    /// compares.
    fn bound<'a>(&self, offer: &'a OfferBinding) -> Cow<'a, OfferBinding> {
        match &self.payer {
            Some(payer) => Cow::Owned(OfferBinding {
                payer_person: Some(payer.clone()),
                ..offer.clone()
            }),
            None => Cow::Borrowed(offer),
        }
    }

    fn snapshot(&self) -> (u32, RunDeclaration) {
        let current = self.lock_declaration();
        (current.revision, current.declaration.clone())
    }

    pub(super) fn begin_dispatch(
        &self,
        lease: &BudgetLease,
        call: &DispatchBinding,
    ) -> Result<(), RunDenied> {
        let ours = self.lock_calls().contains_key(lease.id());
        let ours = ours || self.lock_paid().contains(lease.id());
        let started = if ours {
            self.guard.begin_dispatch(lease, call)
        } else if self.guard.lease_open(lease) == Some(false) {
            // A settled permit, which its run no longer holds.
            Err(DispatchRefused::Closed)
        } else {
            // Another run's permit, on a meter the two share.
            Err(DispatchRefused::ForeignLease)
        };
        started.map_err(|refused| {
            let reason = RunDenied::Dispatch { refused };
            self.refuse(Some(&call.subject), Some(lease), reason.clone());
            reason
        })
    }

    pub(super) fn refuse(
        &self,
        subject: Option<&str>,
        lease: Option<&BudgetLease>,
        reason: RunDenied,
    ) {
        let revision = self.revision_for(lease);
        self.record(
            revision,
            RunEvent::Denied {
                selector: None,
                subject: subject.map(str::to_owned),
                lease: lease.map(|lease| lease.id().to_owned()),
                reason,
            },
        );
    }

    pub(super) fn dispatched(
        &self,
        dispatch: Dispatch,
        route: &str,
        served_model: Option<String>,
        answered: bool,
    ) {
        let Dispatch {
            lease,
            model,
            digest: request_digest,
            broker_isolation,
        } = dispatch;
        let admitted_under = self.lock_calls().get_mut(lease.id()).map(|facts| {
            facts.request_digest = Some(request_digest.clone());
            facts.served_model.clone_from(&served_model);
            facts.revision
        });
        let revision = admitted_under.unwrap_or_else(|| self.lock_declaration().revision);
        self.record(
            revision,
            RunEvent::Dispatched {
                lease: lease.id().to_owned(),
                subject: model.as_str().to_owned(),
                route: route.to_owned(),
                request_digest,
                served_model,
                broker_isolation,
                answered,
            },
        );
    }

    /// The revision a row about `lease` carries: the one its call was
    /// admitted under, else the current one.
    fn revision_for(&self, lease: Option<&BudgetLease>) -> u32 {
        let admitted_under = lease.and_then(|lease| {
            self.lock_calls()
                .get(lease.id())
                .map(|facts| facts.revision)
        });
        admitted_under.unwrap_or_else(|| self.lock_declaration().revision)
    }

    /// `host.budget.hit` through the run's sink, once `guard` refused.
    pub(super) fn budget_hit(&self, seat: &str, guard: &BudgetGuard, denied: &BudgetDenied) {
        self.receipts.budget_hit(seat, guard, denied);
    }

    fn receipt_for(
        &self,
        revision: u32,
        selector: Option<&str>,
        subject: &str,
        admitted: Result<RunPermit, RunDenied>,
        model: Option<ModelId>,
    ) -> Result<RunPermit, RunDenied> {
        match admitted {
            Ok(permit) => {
                if let Some(model) = model {
                    self.lock_calls().insert(
                        permit.lease.id().to_owned(),
                        CallFacts {
                            revision,
                            model,
                            request_digest: None,
                            served_model: None,
                            settled_units: None,
                        },
                    );
                } else {
                    self.lock_paid().insert(permit.lease.id().to_owned());
                }
                self.record(revision, RunEvent::Admitted(Box::new(permit.facts.clone())));
                Ok(permit)
            }
            Err(reason) => {
                self.record(
                    revision,
                    RunEvent::Denied {
                        selector: selector.map(str::to_owned),
                        subject: Some(subject.to_owned()),
                        lease: None,
                        reason: reason.clone(),
                    },
                );
                if let RunDenied::Budget { denied } = &reason {
                    self.budget_hit(subject, &self.guard, denied);
                }
                Err(reason)
            }
        }
    }

    pub(super) fn record(&self, revision: u32, event: RunEvent) {
        let receipt = RunReceipt {
            instance: self.instance,
            occurred_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs()),
            run: self.run.clone(),
            revision,
            event,
        };
        if !std::thread::panicking() {
            self.receipts.record(receipt);
            return;
        }
        // A permit's or a dispatch's drop during an unwind: a sink that
        // panics again must not abort the host. The meters are settled by now.
        let recorded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.receipts.record(receipt);
        }));
        if recorded.is_err() {
            tracing::error!(run = %self.run, "run receipt sink panicked during an unwind");
        }
    }

    fn lock_declaration(&self) -> MutexGuard<'_, Revisioned> {
        self.declaration
            .lock()
            .expect("run declaration mutex poisoned")
    }

    pub(super) fn lock_calls(&self) -> MutexGuard<'_, BTreeMap<String, CallFacts>> {
        self.calls.lock().expect("run call mutex poisoned")
    }

    pub(super) fn lock_paid(&self) -> MutexGuard<'_, BTreeSet<String>> {
        self.paid.lock().expect("run permit mutex poisoned")
    }
}

impl std::fmt::Debug for RunAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunAdmission")
            .field("run", &self.inner.run)
            .finish_non_exhaustive()
    }
}
