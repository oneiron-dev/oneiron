//! The arm's model gateway (PR-S1): one strict call of a captured step's
//! request, by the pattern of the contribution forks' exact call, never its
//! code: the whole request as stored, bound to the model and locality that
//! answered it, admitted as a raw call naming that model meets, sent on the
//! one model's own ladder with no fallback, and only while that ladder's
//! route prompt and route pin (route, offer, catalog revision, wire model,
//! prompt digest) are the ones the capture pinned. Each call takes a policy
//! guard of its own, and its receipts are kept for the arm beside the host's
//! own sink. A call with no answer still has its receipt: what it used is
//! never a fictitious zero.

use std::sync::Arc;

use oneiron::code_run::CapsuleRungBinding;
use oneiron::code_run::shadow_runner::{
    PreparedShadowStep, ShadowBodyStore, ShadowMeterContext, ShadowModelPin, ShadowModelReceipt,
    ShadowUnavailable, ShadowUnavailableReason as Reason, ShadowUsage,
};
use oneiron::engine_executor::StepCancellation;
use oneiron::llm::run_admission::{MemoryReceipts, RunEvent, RunReceipt, RunReceiptSink};
use oneiron::llm::{BudgetDenied, BudgetGuard, DEFAULT_BUDGET_RESERVE_UNITS};
use oneiron::{BudgetExhaustionPolicy, EntityId, Error, LlmError, LlmResponse, Vault};

use super::super::CHAT_ROLE;
use crate::models::RoleCall;
use crate::server::SyncServer;

/// One call's receipts, kept for the arm and passed on to the host's own
/// sink, its budget hits too.
struct TeeReceipts {
    kept: Arc<MemoryReceipts>,
    host: Arc<dyn RunReceiptSink>,
}

impl RunReceiptSink for TeeReceipts {
    fn record(&self, receipt: RunReceipt) {
        self.kept.record(receipt.clone());
        self.host.record(receipt);
    }

    fn budget_hit(&self, seat: &str, guard: &BudgetGuard, denied: &BudgetDenied) {
        self.host.budget_hit(seat, guard, denied);
    }
}

/// One model call of an arm: its answer, or why there is none, and its
/// receipt either way.
pub(super) struct ModelCall {
    pub(super) answer: std::result::Result<LlmResponse, ShadowUnavailable>,
    pub(super) receipt: ShadowModelReceipt,
}

/// The gateway one arm's calls go through.
pub(super) struct Gateway<'a> {
    pub(super) server: &'a SyncServer,
    pub(super) vault: &'a Vault,
    pub(super) store: &'a ShadowBodyStore,
    pub(super) cancel: &'a StepCancellation,
}

impl Gateway<'_> {
    /// Call `call_id` of the arm: `prepared`'s captured request, sent
    /// strictly on `pin`, metered under `meter`. Not sent once the arm is
    /// cancelled.
    pub(super) async fn call(
        &self,
        call_id: u32,
        prepared: &PreparedShadowStep,
        pin: &ShadowModelPin,
        meter: &ShadowMeterContext,
    ) -> oneiron::Result<ModelCall> {
        let step = prepared.step().step;
        let mut receipt = ShadowModelReceipt {
            call_id,
            request: None,
            request_digest: prepared.request_digest(),
            expected: pin.clone(),
            served: None,
            response: None,
            receipts: Vec::new(),
            usage: ShadowUsage::NotDispatched,
            unavailable: None,
        };
        let binding = match strict_pins(prepared, pin) {
            Ok(binding) => binding.clone(),
            Err(unavailable) => return Ok(refused(receipt, unavailable)),
        };
        let runtime = self.server.ai.model_runtime();
        let mut request = prepared.request().clone();
        request.model = binding.model.clone();
        request.envelope.locality = binding.locality;
        // The model a raw call naming it meets, never swapped for the role's
        // route, which still clamps it: a model not served here now is no
        // replay, and no other model stands in.
        let Ok(RoleCall { request, ladder }) =
            runtime.admit_seat_bound(self.vault, CHAT_ROLE, request)
        else {
            let unavailable = ShadowUnavailable::new(Reason::ModelUnavailable, "model_not_served");
            return Ok(refused(receipt, unavailable));
        };
        if ladder.exact_prompt() != Some(binding.prompt.as_deref()) {
            let unavailable =
                ShadowUnavailable::new(Reason::RouteUnavailable, "route_prompt_moved");
            return Ok(refused(receipt, unavailable));
        }
        receipt.served = ladder.exact_replay_route_pin();
        let moved = match &receipt.served {
            Some(served) if *served == pin.route => None,
            Some(_) => Some("route_moved"),
            None => Some("no_exact_route"),
        };
        if let Some(cause) = moved {
            let unavailable = ShadowUnavailable::new(Reason::RouteUnavailable, cause);
            return Ok(refused(receipt, unavailable));
        }
        // An arm whose source an erase took sends nothing (FIX 5718).
        if let Some(withheld) = self.store.source_withheld() {
            return Ok(refused(receipt, withheld));
        }
        let sent = serde_json::to_vec(&request)
            .map_err(|error| Error::InvalidConfig(format!("shadow model request: {error}")))?;
        let path = format!("shadow/{step:06}/call-{call_id:03}.request.json");
        receipt.request = Some(self.store.put(path, &sent)?);
        let run_id = format!("{}:shadow-arm:{}", meter.host_run, EntityId::now().to_hex());
        let guard = match self.vault.coach_authority().and_then(|actor| {
            self.vault.policy_budget_guard(
                run_id.clone(),
                meter.call_units,
                DEFAULT_BUDGET_RESERVE_UNITS,
                BudgetExhaustionPolicy::Suspend,
                actor,
            )
        }) {
            Ok(guard) => guard,
            Err(error) => {
                let code = format!("{:?}", error.kind());
                let unavailable =
                    ShadowUnavailable::new(Reason::HostAdmissionRefused { code }, "meter");
                return Ok(refused(receipt, unavailable));
            }
        };
        let kept = Arc::new(MemoryReceipts::default());
        let sink: Arc<dyn RunReceiptSink> = Arc::new(TeeReceipts {
            kept: Arc::clone(&kept),
            host: self.server.run_receipts(),
        });
        let run = crate::models::undeclared_run(run_id, guard, runtime.host_account(), sink);
        let cancel = self.cancel;
        let may_send = move || !cancel.is_cancelled();
        let wait = ladder.exact_replay_wait();
        let answered = ladder
            .generate_exact_within(&run, request, None, &may_send, wait)
            .await;
        let rows = kept.rows();
        let dispatched = rows
            .iter()
            .any(|row| matches!(row.event, RunEvent::Dispatched { .. }));
        receipt.receipts = rows
            .iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<_, _>>()
            .map_err(|error| Error::InvalidConfig(format!("shadow model receipt: {error}")))?;
        match answered {
            Ok(response) => {
                // What the call used is evidence of a call made, kept
                // before its answer is published.
                receipt.usage = ShadowUsage::Answered {
                    usage: response.usage.clone(),
                };
                // An erase that took the source's content during the call
                // leaves its answer unpublished, its receipt kept (FIX 5718).
                if let Some(withheld) = self.store.source_withheld() {
                    return Ok(refused(receipt, withheld));
                }
                let encoded = serde_json::to_vec(&response).map_err(|error| {
                    Error::InvalidConfig(format!("shadow model answer: {error}"))
                })?;
                let path = format!("shadow/{step:06}/call-{call_id:03}.answer.json");
                receipt.response = Some(self.store.put(path, &encoded)?);
                Ok(ModelCall {
                    answer: Ok(response),
                    receipt,
                })
            }
            Err(error) => {
                receipt.usage = if dispatched {
                    ShadowUsage::DispatchedUnknown
                } else {
                    ShadowUsage::NotDispatched
                };
                let unavailable = if self.cancel.is_cancelled() {
                    ShadowUnavailable::new(Reason::Cancelled, "model_call")
                } else {
                    unanswered(&error)
                };
                Ok(refused(receipt, unavailable))
            }
        }
    }
}

/// The pins a strict call goes out on (CALLS "strict pins required on the
/// new path only"): the capture must have pinned both the answering rung
/// and its route, and the caller's pins must be exactly those. Only this
/// new path asks it: live steps and the contribution forks never do.
fn strict_pins<'p>(
    prepared: &'p PreparedShadowStep,
    pin: &ShadowModelPin,
) -> std::result::Result<&'p CapsuleRungBinding, ShadowUnavailable> {
    let (Some(binding), Some(route)) = (prepared.binding(), prepared.route_pin()) else {
        return Err(ShadowUnavailable::new(Reason::RoutePinMissing, "capture"));
    };
    if *binding != pin.captured || *route != pin.route {
        return Err(ShadowUnavailable::new(
            Reason::SourceDigestMismatch,
            "model_pin",
        ));
    }
    Ok(binding)
}

/// A call with no answer, for `unavailable`, its receipt saying so.
fn refused(mut receipt: ShadowModelReceipt, unavailable: ShadowUnavailable) -> ModelCall {
    receipt.unavailable = Some(unavailable.clone());
    ModelCall {
        answer: Err(unavailable),
        receipt,
    }
}

/// Why a sent call has no answer, by the error's kind, never its text: a
/// budget refusal is the host's admission, anything else the model's.
fn unanswered(error: &LlmError) -> ShadowUnavailable {
    match error {
        LlmError::BudgetDenied(_) => ShadowUnavailable::new(
            Reason::HostAdmissionRefused {
                code: "budget_denied".to_owned(),
            },
            "model_call",
        ),
        LlmError::Retryable(_) => ShadowUnavailable::new(Reason::ModelUnavailable, "retryable"),
        LlmError::Fatal(_) => ShadowUnavailable::new(Reason::ModelUnavailable, "fatal"),
    }
}
