//! The house compaction route's call (moved from `compaction.rs`): one
//! pass's request, admitted on the role's live route or as exactly the
//! model the host resolved, held to the admitted model's context, dressed in
//! the room it leaves, sent on the run's meter and booked. A live fork's
//! call (FIX 4465 C) is admitted its own way and sent the same way.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use oneiron::LlmResponse;
use oneiron::agent_dispatch::AgentDispatcher;
use oneiron::compaction::{
    CompactionBackend, CompactionCheck, CompactionOff, CompactionProduct, CompactionRefusal,
    CompactionRequest, CompactionSuppression, CompactionTierClass, compaction_reply_schema,
    compaction_request_input,
};
use oneiron::engine_executor::ENGINE_EXECUTOR_COMPACTION_PURPOSE_NAME;
use oneiron::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, FatalLlmError, LlmCapability, LlmError,
    LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};

use super::{
    BACKEND_KEY, COMPACTION_RUN, CompactionMeter, ServedCompactionBackend, output_tokens, refused,
};
use crate::ai_host::payer_funding::scope_funding;
use crate::models::{RoleCall, RoleRefusal};

impl ServedCompactionBackend {
    pub(super) fn llm_request(
        &self,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> LlmRequest {
        let purpose = CallPurpose::Other {
            name: ENGINE_EXECUTOR_COMPACTION_PURPOSE_NAME.to_owned(),
        };
        let tier = ModelTierRef(BACKEND_KEY.to_owned());
        LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: oneiron::llm::Scope::default(),
                tier: TierPrecedence::for_purpose(&purpose, tier),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Json {
                    schema: compaction_reply_schema(),
                },
                locality: self.locality,
            },
            messages: vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: self.prompt.clone(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text {
                        text: compaction_request_input(request, retry).to_string(),
                    }],
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::from([(
                "max_output_tokens".to_owned(),
                serde_json::json!(output_tokens(request.summary_token_budget)),
            )]),
            provider_options: BTreeMap::new(),
        }
    }
}

/// How a pass's call is admitted: on the role's live route, as the house
/// compaction's calls are, or as exactly the model the host resolved, on its
/// own one-model ladder under the role route's clamp (a self-written call on
/// the agent's own compaction model, FIX 4472).
pub(super) enum Admit {
    Role,
    Exact {
        model: ModelId,
        locality: ModelLocality,
    },
}

/// What one admitted call leaves room for: the admitted model's context,
/// the input it already holds and the reply's reserve.
#[derive(Clone, Copy)]
pub(super) struct CallRoom {
    pub(super) context: u64,
    pub(super) input: u64,
    pub(super) output: u64,
}

/// What a served call answered, and what the host wore it with.
pub(super) struct Served<D> {
    pub(super) response: LlmResponse,
    /// The model the call was admitted on.
    pub(super) model: ModelId,
    /// The admitted request's durable-step identity.
    pub(super) step_hash: Option<[u8; 32]>,
    /// The request as it was sent, as its JSON, when it was admitted as
    /// exactly one model: a self-written call files it as its step (FIX
    /// 4465 B). `None` for the house's calls.
    pub(super) sent: Option<Vec<u8>>,
    pub(super) worn: D,
    pub(super) latency: Duration,
}

impl ServedCompactionBackend {
    /// One pass's call: admitted by `admit`, held to the admitted model's
    /// context, then `dress`ed in the room it leaves (a self-written call's
    /// home; nothing for the house's), sent on the meter and booked.
    pub(super) fn serve<D>(
        &self,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
        admit: &Admit,
        dress: impl FnOnce(&mut LlmRequest, CallRoom) -> Result<D, CompactionRefusal>,
    ) -> Result<Served<D>, CompactionRefusal> {
        let started = Instant::now();
        let mut llm = self.llm_request(request, retry);
        let admitted = match admit {
            Admit::Role => self.models.admit_role(&self.vault, self.role, llm),
            Admit::Exact { model, locality } => {
                llm.model = model.clone();
                llm.envelope.locality = *locality;
                self.models.admit_seat_bound(&self.vault, self.role, llm)
            }
        };
        let call = admitted.map_err(admission_refused)?;
        let exact = matches!(admit, Admit::Exact { .. });
        self.send(started, call, exact, request.summary_token_budget, dress)
    }

    /// One admitted call, `exact` when it was admitted as exactly one model
    /// (sent with no fallback, and its request kept for its step): held to
    /// the admitted model's context, `dress`ed in the room it leaves, sent
    /// on the run's meter with a permit of its own, and booked.
    pub(super) fn send<D>(
        &self,
        started: Instant,
        mut call: RoleCall,
        exact: bool,
        summary_token_budget: u64,
        dress: impl FnOnce(&mut LlmRequest, CallRoom) -> Result<D, CompactionRefusal>,
    ) -> Result<Served<D>, CompactionRefusal> {
        // The admitted model, not the configured ladder, must hold the call.
        let Some(&context) = self.allowances.get(&call.request.model) else {
            return Err(refused(
                CompactionSuppression::TurnScoped { check: None },
                format!("no context is known for {}", call.request.model),
            ));
        };
        let input = request_input_tokens(&call.request);
        let output = output_tokens(summary_token_budget);
        if input.saturating_add(output) > context {
            return Err(refused(
                CompactionSuppression::TurnScoped { check: None },
                format!(
                    "a {input}-token window and its reply exceed {}'s {context}-token context",
                    call.request.model
                ),
            ));
        }
        let worn = dress(
            &mut call.request,
            CallRoom {
                context,
                input,
                output,
            },
        )?;
        // A route that cannot hold a reply to a schema (an Anthropic-style
        // one) is asked in plain text: the prompt asks for the same JSON, and
        // the gate's schema check refuses anything else.
        if !call
            .ladder
            .supports(&call.request.model, &LlmCapability::JsonResponse)
        {
            call.request.envelope.response_format = ResponseFormat::Text;
        }
        let turn =
            |error: String| refused(CompactionSuppression::TurnScoped { check: None }, error);
        // A pass under a room-paid scope bills its root payer's own account
        // (OF-531); a payer this host cannot bill holds the pass for the turn.
        let (guard, payer) = match &self.meter {
            CompactionMeter::CodeMode(guard) => (guard.clone(), None),
            // A chat turn's flight bills the payer its turn resolved, on its
            // own guard on the chat actor's line (FIX 4465 D).
            CompactionMeter::Chat { guard, payer } => (guard.clone(), payer.clone()),
            CompactionMeter::Scope(scope) => {
                let payer = scope_funding(&self.vault, Some(scope), false)
                    .map_err(|fault| turn(fault.to_string()))?;
                let guard = AgentDispatcher::new(&self.vault)
                    .guard_for_scope(scope)
                    .map_err(|error| turn(error.to_string()))?;
                (guard, payer)
            }
        };
        let step_hash = call.request.canonical_hash().ok();
        let sent = if exact {
            serde_json::to_vec(&call.request).ok()
        } else {
            None
        };
        let model = call.request.model.clone();
        let run = self.models.funded_run(COMPACTION_RUN, guard.clone(), payer);
        let reply = if exact {
            self.handle
                .block_on(call.ladder.generate_exact(&run, call.request, None))
        } else {
            self.handle
                .block_on(call.ladder.generate(&run, call.request, None))
        };
        if let CompactionMeter::Scope(scope) = &self.meter
            && let Err(error) =
                AgentDispatcher::new(&self.vault).record_guard_spend(scope, guard.read().used_units)
        {
            tracing::error!(%error, "a compaction call's spend did not book on its run's scope");
        }
        match reply {
            Ok(response) => Ok(Served {
                response,
                model,
                step_hash,
                sent,
                worn,
                latency: started.elapsed(),
            }),
            Err(error) => {
                let suppression = match &error {
                    LlmError::Fatal(FatalLlmError::Auth) => CompactionSuppression::Auth,
                    LlmError::BudgetDenied(_) => CompactionSuppression::NoCredit,
                    _ => CompactionSuppression::TurnScoped { check: None },
                };
                Err(refused(suppression, error.to_string()))
            }
        }
    }

    /// What its context holds beside the reply and the prompt on `model`.
    pub(super) fn input_room(&self, model: &ModelId, summary_token_budget: u64) -> u64 {
        self.allowances
            .get(model)
            .copied()
            .unwrap_or(0)
            .saturating_sub(output_tokens(summary_token_budget))
            .saturating_sub(self.prompt_tokens)
    }

    /// The model the role's live route admits now, else its seat's.
    pub(super) fn house_model(&self) -> Option<ModelId> {
        let seat = self.models.seat(self.role)?;
        Some(
            self.models
                .route_role(&self.vault, self.role, seat)
                .map_or_else(|_| seat.model.clone(), |route| route.model),
        )
    }
}

impl CompactionBackend for ServedCompactionBackend {
    fn backend_key(&self) -> &str {
        &self.key
    }

    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }

    /// Read on the vault's live route, as a pass is admitted: what its
    /// context holds beside the reply and the prompt, as [`Self::compact`]
    /// counts it.
    fn input_token_limit(&self, summary_token_budget: u64) -> Option<u64> {
        let context = self
            .models
            .seat(self.role)
            .and_then(|seat| self.models.route_role(&self.vault, self.role, seat).ok())
            .and_then(|route| self.allowances.get(&route.model).copied())
            .unwrap_or(0);
        Some(
            context
                .saturating_sub(output_tokens(summary_token_budget))
                .saturating_sub(self.prompt_tokens),
        )
    }

    fn compact(
        &self,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> Result<CompactionProduct, CompactionRefusal> {
        let served = self.serve(request, retry, &Admit::Role, |_, _| Ok(()))?;
        Ok(product_of(&served.response, served.latency))
    }
}

/// Why a pass's call was refused before it left: a role no seat serves is
/// off for the run, anything else holds for the turn.
pub(super) fn admission_refused(refusal: RoleRefusal) -> CompactionRefusal {
    let suppression = match refusal {
        RoleRefusal::NoSeat => CompactionSuppression::Sticky {
            why: CompactionOff::NoSeat,
        },
        _ => CompactionSuppression::TurnScoped { check: None },
    };
    refused(suppression, refusal.to_string())
}

/// The text of every text part of a reply, as one string.
pub(super) fn product_of(response: &LlmResponse, latency: Duration) -> CompactionProduct {
    CompactionProduct {
        summary_text: response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect(),
        finish: response.finish_reason.clone(),
        latency,
    }
}

/// Every text token a request sends.
pub(super) fn request_input_tokens(request: &LlmRequest) -> u64 {
    request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .map(|part| match part {
            ContentPart::Text { text } => oneiron::count_context_pack_tokens(text) as u64,
            _ => 0,
        })
        .sum()
}
