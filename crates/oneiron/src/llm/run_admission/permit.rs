//! Building a run's permits: the declared teachers, the host's offer, the
//! key's rung, the run's line and the vault's allocation, in that order.
use std::sync::Arc;

use super::super::{
    BudgetDenied, BudgetGuard, BudgetLease, BudgetSettlement, DispatchBinding,
    InferenceCallReceipt, ModelLocality, PinnedConfigViolation,
};
use super::admission::{RunCall, RunDenied, RunInner};
use super::declaration::{LeaseUnit, RunDeclaration};
use super::host::{
    AllocationRef, KeyCustody, LiveAllocation, PaidConnector, Payer, UnitRate, Unpriced, convert,
};
use super::receipt::{PermitFacts, RunStreamUsage};
use super::settle::CallOutcome;

/// A one-use admission for one call: the lease to send with it and every fact
/// the admission bound. It is not `Clone`; a cloned lease still dispatches
/// at most once. It settles once, on the run that issued it, through
/// [`RunPermit::settle`]; a permit dropped unsettled, a cancelled call's
/// included, settles as [`CallOutcome::Failed`].
pub struct RunPermit {
    run: Arc<RunInner>,
    pub(super) facts: PermitFacts,
    pub(super) revision: u32,
    pub(super) lease: BudgetLease,
    pub(super) metered: bool,
    pub(super) allocation: Option<AllocationHold>,
    /// The unit a call's own usage comes in: tokens for a model, the pack
    /// row's unit for a paid connector.
    pub(super) native: LeaseUnit,
    /// Native units one reported unit costs: 1 for a model, the pack row's
    /// unit cost for a paid connector.
    pub(super) unit_cost: u64,
    /// The call's reservation in native units: the bounded charge of an
    /// answer that reports no usage.
    pub(super) reserve_native: u128,
    pub(super) rates: Vec<UnitRate>,
    settled: bool,
}

#[derive(Debug)]
pub(super) struct AllocationHold {
    pub(super) meter: BudgetGuard,
    pub(super) lease: BudgetLease,
    pub(super) unit: LeaseUnit,
}

impl RunPermit {
    /// The lease the call carries to the gated backend.
    #[must_use]
    pub fn lease(&self) -> &BudgetLease {
        &self.lease
    }

    #[must_use]
    pub fn facts(&self) -> &PermitFacts {
        &self.facts
    }

    /// The declaration revision the call was admitted under.
    #[must_use]
    pub fn revision(&self) -> u32 {
        self.revision
    }

    /// Whether the call went out: the run's gate started its lease. A call
    /// its backend refused before sending never did.
    #[must_use]
    pub fn dispatched(&self) -> bool {
        self.run.guard.dispatched(&self.lease) == Some(true)
    }

    /// Settles the call. An answer pays its usage, or its reservation when it
    /// reports none, plus a reservation for each rung that failed before it.
    /// A call that started and then failed pays its reservation as unknown
    /// usage; one that never started pays nothing. A settlement the meter
    /// refuses goes on the receipt and is returned.
    pub fn settle(self, outcome: CallOutcome<'_>) -> Result<BudgetSettlement, RunDenied> {
        self.settle_with(outcome, Vec::new())
    }

    /// Settles the call as [`Self::settle`] does, with `provided`, the
    /// inference receipts the call reported outside an answer's usage, on
    /// its receipt (FIX 8314).
    pub(super) fn settle_with(
        mut self,
        outcome: CallOutcome<'_>,
        provided: Vec<InferenceCallReceipt>,
    ) -> Result<BudgetSettlement, RunDenied> {
        self.settled = true;
        let run = Arc::clone(&self.run);
        run.settle(&self, outcome, None, provided)
    }

    /// Settles a metered stream, as [`Self::settle`] settles `Used(units)`,
    /// with the stream's admitted audio and bound on its receipt.
    pub(super) fn settle_stream(
        mut self,
        units: u64,
        stream: RunStreamUsage,
    ) -> Result<BudgetSettlement, RunDenied> {
        self.settled = true;
        let run = Arc::clone(&self.run);
        run.settle(&self, CallOutcome::Used(units), Some(stream), Vec::new())
    }
}

impl Drop for RunPermit {
    fn drop(&mut self) {
        if !self.settled {
            self.settled = true;
            let run = Arc::clone(&self.run);
            // The refusal, if any, is on the Settled receipt.
            run.settle(self, CallOutcome::Failed, None, Vec::new()).ok();
        }
    }
}

impl std::fmt::Debug for RunPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunPermit")
            .field("facts", &self.facts)
            .field("revision", &self.revision)
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

impl RunInner {
    pub(super) fn admit_model(
        self: &Arc<Self>,
        declaration: &RunDeclaration,
        revision: u32,
        call: RunCall<'_>,
        request_digest: Option<String>,
        source_rows: Option<Vec<crate::EntityId>>,
    ) -> Result<RunPermit, RunDenied> {
        let RunCall {
            selector,
            request,
            offer,
        } = call;
        let teacher = match declaration.teachers() {
            Some(teachers) => {
                teachers
                    .pins()
                    .admit(request)
                    .map_err(|violation| match violation {
                        PinnedConfigViolation::ModelNotPinned { model } => {
                            RunDenied::UndeclaredTeacher { model }
                        }
                        PinnedConfigViolation::BackgroundTierDisabled { .. } => {
                            RunDenied::UndeclaredTeacher {
                                model: request.model.clone(),
                            }
                        }
                    })?;
                Some((teachers.target().to_owned(), teachers.purpose().to_owned()))
            }
            None => None,
        };
        if offer.model != request.model {
            return Err(RunDenied::OfferMismatch);
        }
        if offer.locality != request.envelope.locality {
            return Err(RunDenied::LocalityMismatch);
        }
        if let Some(key) = request.route_selector_override() {
            return Err(RunDenied::RouteOverride { key });
        }
        let rules_enforced = custody(declaration, offer.payer, offer.custody, &offer.offer)?;
        let tokens = LeaseUnit::tokens();
        let line = declaration.budget();
        let binding = DispatchBinding {
            request_digest,
            ..offer.dispatch_binding()
        };
        let free = self.free_lease(offer.payer, offer.custody, &binding)?;
        let metered = free.is_none();
        let (lease, reserved_units) = match free {
            Some(lease) => (lease, 0),
            None => {
                let reserve = priced(
                    u128::from(line.reserve_units),
                    &tokens,
                    &line.unit,
                    &offer.rates,
                )?;
                let lease = self
                    .guard
                    .admit_call_bound(reserve, &request.envelope.purpose, binding)
                    .map_err(|denied| RunDenied::Budget { denied })?
                    .lease;
                (lease, reserve)
            }
        };
        let allocation = match self.hold_allocation(
            offer.payer,
            u128::from(line.reserve_units),
            &tokens,
            &offer.rates,
        ) {
            Ok(allocation) => allocation,
            Err(denied) => {
                // Not dispatched, so the abort releases the line's reservation.
                self.guard.abort(&lease).ok();
                return Err(denied);
            }
        };
        Ok(RunPermit {
            run: Arc::clone(self),
            facts: PermitFacts {
                selector: selector.map(str::to_owned),
                subject: request.model.as_str().to_owned(),
                model: Some(request.model.clone()),
                offer: offer.offer.clone(),
                route: offer.route.key(),
                locality: offer.locality,
                payer: offer.payer,
                payer_person: offer.payer_person.clone(),
                catalog_revision: offer.catalog_revision.clone(),
                lease: lease.id().to_owned(),
                reserved_units,
                unit: line.unit.clone(),
                allocation: allocation.as_ref().map(|(reference, _)| reference.clone()),
                allocation_unit: allocation.as_ref().map(|(_, hold)| hold.unit.clone()),
                allocation_reserved_units: allocation
                    .as_ref()
                    .and_then(|(_, hold)| hold.meter.reserved_for(&hold.lease)),
                teacher_target: teacher.as_ref().map(|(target, _)| target.clone()),
                purpose: teacher.map(|(_, purpose)| purpose),
                call_purpose: Some(super::super::routing::purpose_key(
                    &request.envelope.purpose,
                )),
                attribution: self.attribution.clone(),
                seat: request
                    .envelope
                    .tier
                    .metered_seat()
                    .map(|tier| tier.0.clone()),
                rules_enforced,
                source_rows,
                initiator: None,
            },
            revision,
            lease,
            metered,
            allocation: allocation.map(|(_, hold)| hold),
            native: tokens,
            unit_cost: 1,
            reserve_native: u128::from(line.reserve_units),
            rates: offer.rates.clone(),
            settled: false,
        })
    }

    pub(super) fn admit_connector(
        self: &Arc<Self>,
        declaration: &RunDeclaration,
        revision: u32,
        connector: &PaidConnector,
        quantity: u64,
        source_rows: Option<Vec<crate::EntityId>>,
    ) -> Result<RunPermit, RunDenied> {
        if !declaration.admits_connector(&connector.connector) {
            return Err(RunDenied::UndeclaredConnector {
                connector: connector.connector.clone(),
            });
        }
        let rules_enforced = custody(
            declaration,
            connector.payer,
            connector.custody,
            &connector.connector,
        )?;
        let line = declaration.budget();
        let native = u128::from(connector.unit_cost) * u128::from(quantity);
        let binding = connector.dispatch_binding();
        let free = self.free_lease(connector.payer, connector.custody, &binding)?;
        let metered = free.is_none();
        let (lease, reserve) = match free {
            Some(lease) => (lease, 0),
            None => {
                let reserve = priced(native, &connector.cost_unit, &line.unit, &connector.rates)?;
                let lease = self
                    .guard
                    .admit_reserve_bound(reserve, binding)
                    .map_err(|denied| RunDenied::Budget { denied })?
                    .lease;
                (lease, reserve)
            }
        };
        let allocation = match self.hold_allocation(
            connector.payer,
            native,
            &connector.cost_unit,
            &connector.rates,
        ) {
            Ok(allocation) => allocation,
            Err(denied) => {
                self.guard.abort(&lease).ok();
                return Err(denied);
            }
        };
        Ok(RunPermit {
            run: Arc::clone(self),
            facts: PermitFacts {
                selector: None,
                subject: connector.connector.clone(),
                model: None,
                offer: connector.connector.clone(),
                route: connector.route.key(),
                locality: connector.locality,
                payer: connector.payer,
                // A connector call bills whoever funds its run.
                payer_person: self.payer.clone(),
                catalog_revision: connector.catalog_revision.clone(),
                lease: lease.id().to_owned(),
                reserved_units: reserve,
                unit: line.unit.clone(),
                allocation: allocation.as_ref().map(|(reference, _)| reference.clone()),
                allocation_unit: allocation.as_ref().map(|(_, hold)| hold.unit.clone()),
                allocation_reserved_units: allocation
                    .as_ref()
                    .and_then(|(_, hold)| hold.meter.reserved_for(&hold.lease)),
                teacher_target: None,
                purpose: None,
                // A paid connector call carries no envelope: it bills under
                // its bound item's label, when its run has one.
                call_purpose: self
                    .attribution
                    .as_ref()
                    .map(|bound| super::super::routing::purpose_key(&bound.purpose)),
                attribution: self.attribution.clone(),
                seat: None,
                rules_enforced,
                source_rows,
                initiator: None,
            },
            revision,
            lease,
            metered,
            allocation: allocation.map(|(_, hold)| hold),
            native: connector.cost_unit.clone(),
            unit_cost: connector.unit_cost,
            reserve_native: native,
            rates: connector.rates.clone(),
            settled: false,
        })
    }

    /// The unmetered lease of a call that is [`free_work`], taken before any
    /// price, policy row or exhaustion check (FIX 9482): it reserves nothing
    /// and is charged nothing, and still starts only for `binding`, once.
    /// `None` for paid work, which reserves on the line.
    fn free_lease(
        &self,
        payer: Payer,
        custody: KeyCustody,
        binding: &DispatchBinding,
    ) -> Result<Option<BudgetLease>, RunDenied> {
        if !free_work(payer, binding.locality, custody) {
            return Ok(None);
        }
        self.guard
            .admit_free_work(binding.clone(), custody == KeyCustody::Keyless)
            .map(|admission| Some(admission.lease))
            .map_err(|denied| RunDenied::Budget { denied })
    }

    /// Reserves a host-paid call on the vault's live allocation. A refused
    /// fresh allocation only matters once the live one cannot fit the call. A
    /// run with no host account has no allocation to draw on, so it admits no
    /// host-paid call.
    fn hold_allocation(
        &self,
        payer: Payer,
        native_units: u128,
        native: &LeaseUnit,
        rates: &[UnitRate],
    ) -> Result<Option<(AllocationRef, AllocationHold)>, RunDenied> {
        if payer != Payer::Host {
            return Ok(None);
        }
        let Some(host) = self.host.as_ref() else {
            return Err(RunDenied::NoAllocation);
        };
        let (live, refused) = host.live();
        let short = || match refused {
            Some(reason) => RunDenied::AllocationRefused { reason },
            None => RunDenied::AllocationExhausted,
        };
        let Some(LiveAllocation {
            reference,
            unit,
            meter,
        }) = live
        else {
            return Err(match refused {
                Some(reason) => RunDenied::AllocationRefused { reason },
                None => RunDenied::NoAllocation,
            });
        };
        let units = priced(native_units, native, &unit, rates)?;
        let lease = meter
            .admit_reserve(units)
            .inspect_err(|denied| self.budget_hit(&reference.id, &meter, denied))
            .map_err(|denied| match denied {
                BudgetDenied::Exhausted => short(),
                denied => RunDenied::Budget { denied },
            })?;
        Ok(Some((
            reference,
            AllocationHold {
                meter,
                lease: lease.lease,
                unit,
            },
        )))
    }
}

/// Whether a call is free work (FIX 9482): nobody pays per call
/// ([`Payer::Local`]) and the host bound it to this device, or to the owner's
/// own server with no key. Read only from the host-bound offer or connector,
/// never from a caller's request, nor from a missing key, an own server or a
/// zero rate alone; a keyed owner endpoint stays paid.
fn free_work(payer: Payer, locality: ModelLocality, custody: KeyCustody) -> bool {
    let free_route = match locality {
        ModelLocality::OnDevice => true,
        ModelLocality::OwnServer => custody == KeyCustody::Keyless,
        ModelLocality::ThirdParty => false,
    };
    payer == Payer::Local && free_route
}

/// A reservation in a meter's unit. A price no meter can hold never fits.
fn priced(
    units: u128,
    native: &LeaseUnit,
    target: &LeaseUnit,
    rates: &[UnitRate],
) -> Result<u64, RunDenied> {
    convert(units, native, target, rates).map_err(|unpriced| match unpriced {
        Unpriced::NoRate => RunDenied::UnitMismatch {
            from: native.clone(),
            to: target.clone(),
        },
        Unpriced::TooLarge => RunDenied::Budget {
            denied: BudgetDenied::Exhausted,
        },
    })
}

/// The key-rung rule of a declared run: its paid keys stay at T0. A BYO seat
/// stays at T1 and is admitted with the run's rules marked off for it, as is a
/// T1 key the owner allowed for this offer. Returns whether the rules hold.
fn custody(
    declaration: &RunDeclaration,
    payer: Payer,
    custody: KeyCustody,
    offer: &str,
) -> Result<bool, RunDenied> {
    if !declaration.is_declared() {
        return Ok(true);
    }
    if payer == Payer::CustomerSeat {
        return Ok(false);
    }
    let paid = matches!(
        payer,
        Payer::Host | Payer::CustomerKey | Payer::CustomerAccount
    );
    if paid && custody == KeyCustody::T1 {
        return if declaration.overrides_custody(offer) {
            Ok(false)
        } else {
            Err(RunDenied::KeyAtT1)
        };
    }
    Ok(true)
}
