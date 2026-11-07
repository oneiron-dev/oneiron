//! Native role calls with request-scoped accounting and session-private receipts.
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::{
    BudgetLine, CallOutcome, LeaseUnit, MemoryReceipts, RunAdmission, RunCall, RunDeclaration,
    RunReceipt, RunReceiptSink, WorkPhysical,
};
use oneiron::llm::{BudgetDenied, BudgetGuard, WorkClass};
use oneiron::retrieval_depth::{BackendSpend, RetrievalError, RetrievalResult};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, FatalLlmError, LlmBackend, LlmMessage,
    LlmMessageRole, LlmRequest, LlmResponse, ModelTierRef, ResponseFormat, TierPrecedence,
};
use serde_json::Value;

use super::sources::{Pin, Sources};
use super::{Backend, invalid};
use crate::api::call_receipt::{request_principal, session_is_anonymous_for};
use crate::auth::CoreAuth;
use crate::models::{RerankLine, SourceAdmission, SourceOffer, on_line};
use crate::server::SyncServer;

/// A session may become anonymous while a call runs. Neither the durable sink
/// nor a surrounding settlement capture receives a row before the terminal check.
pub(super) struct Receipts {
    server: Arc<SyncServer>,
    auth: CoreAuth,
    anonymous_at_arrival: bool,
    durable: Arc<dyn RunReceiptSink>,
    rows: Mutex<Vec<RunReceipt>>,
    hits: Mutex<Vec<(String, BudgetGuard, BudgetDenied)>>,
}

impl Receipts {
    pub(super) fn new(
        server: &Arc<SyncServer>,
        auth: &CoreAuth,
        anonymous_at_arrival: bool,
    ) -> Self {
        Self {
            server: Arc::clone(server),
            auth: auth.clone(),
            anonymous_at_arrival: anonymous_at_arrival || anonymous(server, auth),
            durable: oneiron::llm::run_admission::captured_sink(server.run_receipts()),
            rows: Mutex::new(Vec::new()),
            hits: Mutex::new(Vec::new()),
        }
    }
}

impl RunReceiptSink for Receipts {
    fn record(&self, receipt: RunReceipt) {
        self.rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(receipt);
    }

    fn budget_hit(&self, seat: &str, guard: &BudgetGuard, denied: &BudgetDenied) {
        self.hits
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((seat.to_owned(), guard.clone(), denied.clone()));
    }
}

impl Drop for Receipts {
    fn drop(&mut self) {
        if self.anonymous_at_arrival || anonymous(&self.server, &self.auth) {
            return;
        }
        for row in self
            .rows
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            self.durable.record(row);
        }
        for (seat, guard, denied) in self
            .hits
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            self.durable.budget_hit(&seat, &guard, &denied);
        }
    }
}

struct Tee {
    kept: Arc<MemoryReceipts>,
    request: Arc<Receipts>,
}

impl RunReceiptSink for Tee {
    fn record(&self, receipt: RunReceipt) {
        self.kept.record(receipt.clone());
        self.request.record(receipt);
    }

    fn budget_hit(&self, seat: &str, guard: &BudgetGuard, denied: &BudgetDenied) {
        self.request.budget_hit(seat, guard, denied);
    }
}

impl Backend {
    pub(super) fn generate_json(
        &self,
        data: Value,
        schema: Value,
        pins: &[Pin],
        budget: Option<u64>,
    ) -> RetrievalResult<BackendSpend<LlmResponse>> {
        let role = ModelRole::GenerativeReasoner;
        let seat = self
            .server
            .ai
            .seat(role)
            .ok_or_else(|| invalid("memory reason has no generative role"))?;
        let purpose = CallPurpose::AnswerGen;
        let request = LlmRequest {
            model: seat.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("answer".into())),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Json { schema },
                locality: seat.locality,
                host_keyless: false,
                host_paid: false,
            },
            messages: vec![LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: data.to_string(),
                }],
            }],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        self.generate(role, request, pins, budget, None)
    }

    pub(super) fn generate(
        &self,
        role: ModelRole,
        request: LlmRequest,
        pins: &[Pin],
        budget: Option<u64>,
        line: Option<Arc<dyn RerankLine>>,
    ) -> RetrievalResult<BackendSpend<LlmResponse>> {
        if budget == Some(0) {
            return Err(invalid("memory reason token budget exhausted").into());
        }
        let call = self
            .server
            .ai
            .admit_role(&self.server.vault, role, request)
            .map_err(|error| invalid(&format!("memory reason model role: {error}")))?;
        let kept = Arc::new(MemoryReceipts::default());
        let sink: Arc<dyn RunReceiptSink> = Arc::new(Tee {
            kept: Arc::clone(&kept),
            request: Arc::clone(&self.receipts),
        });
        let available = self.meter.read();
        let mut reserve_units = self.meter.reserve_units();
        if let Some(budget) = budget {
            reserve_units = reserve_units.min(budget);
        }
        if available.remaining_units > 0 {
            reserve_units = reserve_units.min(available.remaining_units);
        }
        // At zero remaining, keep native paid admission rejecting a positive
        // reservation; a zero reservation would evade the exhausted line.
        let declaration = RunDeclaration::undeclared(BudgetLine {
            limit_units: available.limit_units,
            reserve_units,
            unit: LeaseUnit::tokens(),
        });
        // The capture lives behind the terminal privacy check, not outside it.
        let run = RunAdmission::with_payer(
            self.run_id.clone(),
            declaration,
            self.meter.clone(),
            Some(self.server.host_account()),
            sink,
            None,
        )
        .for_memory_work()
        .sourced(Some(pins.iter().map(|pin| pin.id).collect()))
        .initiated_by(request_principal(&self.auth));
        let run = run.with_work_context({
            let mut context = run.work_context();
            context.class = WorkClass::Background;
            context.physical = if call.ladder.all_keyless_own_server() {
                WorkPhysical::KeylessOwnServer
            } else {
                WorkPhysical::Paid
            };
            context
        });
        let sources = Sources::new(self, pins);
        let answered = crate::server::blocking(|| {
            self.runtime.block_on(async {
                let generate = async {
                    if self.receipts.anonymous_at_arrival || anonymous(&self.server, &self.auth) {
                        let (request, offer, worker) =
                            call.ladder.anonymous_call(call.request, true)?;
                        let destination = offer.destination();
                        let request = match sources.offer(&request, &destination) {
                            SourceOffer::Send(request) => request,
                            SourceOffer::Held(_) => {
                                return Err(FatalLlmError::InvalidRequest.into());
                            }
                        };
                        let _worker = match worker {
                            Some(worker) => {
                                let lease = worker
                                    .acquire()
                                    .await
                                    .map_err(|_| oneiron::RetryableLlmError::StreamCut)?;
                                if worker.admission_stopped() {
                                    return Err(
                                        oneiron::RetryableLlmError::DeviceAdmissionStopped.into()
                                    );
                                }
                                Some(lease)
                            }
                            None => None,
                        };
                        let call = RunCall {
                            selector: None,
                            request: &request,
                            offer: &offer.binding,
                        };
                        let permit = match offer.backend.request_digest(&request, false)? {
                            Some(digest) => run.admit_request(call, &digest)?,
                            None => run.admit(call)?,
                        };
                        if sources.recheck(&destination).is_some() {
                            return Err(FatalLlmError::InvalidRequest.into());
                        }
                        let backend = run.gate(offer.backend, &offer.binding);
                        let response = backend.generate(request, permit.lease()).await?;
                        permit.settle(CallOutcome::Answered(&response.usage))?;
                        Ok(response)
                    } else {
                        call.ladder
                            .generate_admitted(&run, call.request, None, &sources)
                            .await
                    }
                };
                match line {
                    Some(line) => on_line(line, generate).await,
                    None => generate.await,
                }
            })
        });
        let usage = super::usage::reported(&kept.rows(), answered.as_ref().ok());
        if !usage.complete {
            self.complete.store(false, Ordering::Relaxed);
        }
        let value = answered.map_err(|error| RetrievalError {
            error: invalid(&format!("memory reason model call failed: {error}")),
            tokens_used: usage.tokens,
        })?;
        BackendSpend {
            value,
            tokens_used: usage.tokens,
        }
        .enforce_token_budget(budget)
    }
}

fn anonymous(server: &SyncServer, auth: &CoreAuth) -> bool {
    session_is_anonymous_for(server, auth.off_record_session(), request_principal(auth))
}

pub(super) fn text(response: &LlmResponse) -> String {
    response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}
