//! One run admission: each paid call of a run, to a model or to a paid
//! connector, is admitted against the run's own declaration and its lease,
//! and gets a one-use permit bound to the run, the model, the route and the
//! locality.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::Serialize;

use super::super::{
    BudgetDenied, BudgetExhaustionPolicy, BudgetGuard, BudgetLease, BudgetRead, DispatchRefused,
    LlmBackend, LlmCapability, LlmError, LlmRequest, LlmResponse, ModelId, SingleRouteBackend,
};
use super::declaration::{DeclarationEditor, LeaseUnit, RunDeclaration};
use super::gate::GatedBackend;
use super::host::{AllocationRefusal, HostAccount, OfferBinding, OfferRoute, PaidConnector};
use super::permit::RunPermit;
use super::receipt::{CalledTeacher, RunEvent, RunReceipt, RunReceiptSink, TeacherReport};
use super::settle::CallOutcome;

/// Why the run admission refused a call or an edit. Every refusal comes
/// before any byte leaves and leaves no reservation behind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunDenied {
    #[error("the run did not declare teacher {model}")]
    UndeclaredTeacher { model: ModelId },
    #[error("the run knows no model or alias named {selector}")]
    UnknownSelector { selector: String },
    #[error("the offer binds another model than the call names")]
    OfferMismatch,
    #[error("the call's locality differs from its route's")]
    LocalityMismatch,
    #[error("the call picks its model or route through {key}")]
    RouteOverride { key: String },
    #[error("the route's backend cannot serve {capability:?}")]
    Unsupported { capability: LlmCapability },
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
}

impl From<RunDenied> for LlmError {
    fn from(denied: RunDenied) -> Self {
        match denied {
            RunDenied::Budget { denied } => Self::BudgetDenied(denied),
            RunDenied::NoAllocation
            | RunDenied::AllocationExhausted
            | RunDenied::AllocationRefused { .. } => Self::BudgetDenied(BudgetDenied::Exhausted),
            RunDenied::Dispatch { refused } => Self::BudgetDenied(refused.into()),
            _ => Self::BudgetDenied(BudgetDenied::AdmissionDenied),
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
    run: String,
    declaration: Mutex<Revisioned>,
    pub(super) guard: BudgetGuard,
    pub(super) host: Option<Arc<HostAccount>>,
    receipts: Arc<dyn RunReceiptSink>,
    calls: Mutex<BTreeMap<String, CallFacts>>,
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
    /// self-hosted vault has none.
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
        Self {
            inner: Arc::new(RunInner {
                run,
                declaration: Mutex::new(Revisioned {
                    revision: 1,
                    declaration,
                }),
                guard,
                host,
                receipts,
                calls: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    #[must_use]
    pub fn run(&self) -> &str {
        &self.inner.run
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
            selector: selector.to_owned(),
        })
    }

    /// Admits one model call: the declared teachers, the host's offer, the
    /// key's rung, then the run's line and, for a host-paid offer, the
    /// vault's allocation.
    pub fn admit(&self, call: RunCall<'_>) -> Result<RunPermit, RunDenied> {
        let (revision, declaration) = self.inner.snapshot();
        let admitted = self.inner.admit_model(&declaration, revision, call);
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

    /// The only backend a host hands a run for `route`: it checks and starts
    /// the call's permit before any byte leaves, on `generate` and `stream`.
    #[must_use]
    pub fn gate(&self, inner: Arc<dyn SingleRouteBackend>, route: &OfferRoute) -> GatedBackend {
        GatedBackend::new(Arc::clone(&self.inner), inner, route.key())
    }

    /// The dispatch check a paid connector's adapter makes before it sends.
    pub fn dispatch_paid(
        &self,
        lease: &BudgetLease,
        connector: &PaidConnector,
    ) -> Result<(), RunDenied> {
        self.inner
            .begin_dispatch(lease, &connector.connector, &connector.route.key())
    }

    /// Admits, sends through `gated` and settles one model call. A call
    /// dropped before it ends settles as failed.
    pub async fn call(
        &self,
        gated: &GatedBackend,
        call: RunCall<'_>,
    ) -> Result<LlmResponse, RunCallError> {
        let permit = self.admit(call)?;
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
    fn snapshot(&self) -> (u32, RunDeclaration) {
        let current = self.lock_declaration();
        (current.revision, current.declaration.clone())
    }

    pub(super) fn begin_dispatch(
        &self,
        lease: &BudgetLease,
        subject: &str,
        route: &str,
    ) -> Result<(), RunDenied> {
        self.guard
            .begin_dispatch(lease, subject, route)
            .map_err(|refused| {
                let reason = RunDenied::Dispatch { refused };
                self.refuse(Some(subject), Some(lease), reason.clone());
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
        lease: &BudgetLease,
        subject: &str,
        route: &str,
        request_digest: String,
        served_model: Option<String>,
        answered: bool,
    ) {
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
                subject: subject.to_owned(),
                route: route.to_owned(),
                request_digest,
                served_model,
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
                Err(reason)
            }
        }
    }

    pub(super) fn record(&self, revision: u32, event: RunEvent) {
        self.receipts.record(RunReceipt {
            run: self.run.clone(),
            revision,
            event,
        });
    }

    fn lock_declaration(&self) -> MutexGuard<'_, Revisioned> {
        self.declaration
            .lock()
            .expect("run declaration mutex poisoned")
    }

    pub(super) fn lock_calls(&self) -> MutexGuard<'_, BTreeMap<String, CallFacts>> {
        self.calls.lock().expect("run call mutex poisoned")
    }
}

impl std::fmt::Debug for RunAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunAdmission")
            .field("run", &self.inner.run)
            .finish_non_exhaustive()
    }
}
