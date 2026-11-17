//! One probed Dreamer consolidation pass, for integration tests: like
//! `super::consolidation::consolidate_unbound_turn`, but the scripted reply
//! is a template whose `{{entity:NAME}}` and `{{claim:PREDICATE}}` tokens the
//! backend fills with the labels the outgoing request's own listing gave
//! them, every call's text is recorded, and the attempt's raw outcome is
//! returned (a refused reply parks; it never collapses into a pass error).

use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use crate::dreamer_consolidation::{
    ConsolidationDecisions, ConsolidationExecutor, enqueue_partition_attempts, read_watermark,
    scan_dirty_turns,
};
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::dreamer_runner::{
    AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, DreamerAdmissionOutcome,
    DreamerClaimAuthoringAdmission, DreamerClaimAuthoringBatchTier,
    DreamerConsolidationAdmissionOutcome, DreamerRunnerStore,
};
use crate::dreamer_wake::{
    DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext, WakePassDeadline,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{HostInferenceBinding, HostInferenceContext};
use crate::vault::Vault;
use crate::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ContentPart, DreamerClaimAuthoringStrategy,
    DreamerConsolidationScope, FatalLlmError, FinishReason, LlmBackend, LlmCapability, LlmError,
    LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest,
    LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality, UnsupportedCapability,
};

/// What one probed unbound pass did.
#[derive(Debug)]
pub struct ProbedPass {
    /// The TURN its words were witnessed into.
    pub turn: EntityId,
    /// The consolidation attempt that ran it.
    pub attempt: crate::attempt_queue::AttemptId,
    /// Each model call's text, in call order.
    pub requests: Vec<String>,
    /// What the attempt's execution reported: a completion, a park (a
    /// refused reply parks for a retry), or the pass error.
    pub outcome: Result<DreamerAttemptExecution>,
    /// The claims the pass landed.
    pub landed: Vec<EntityId>,
}

/// The answer to a call whose listing names no label a token asks for: no
/// candidates, so the call contributes nothing.
const NO_CANDIDATES: &str = "{\"candidates\": []}";

/// A scripted model that answers every call from `template`, records each
/// call's text, and resolves the template's label tokens against the call's
/// own listing.
struct ProbeBackend {
    template: String,
    calls: Mutex<Vec<String>>,
}

/// Every message's text of `request`, in order.
fn request_text(request: &LlmRequest) -> String {
    request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The label the listing in `text` gave the entity named `name`, if any.
fn entity_label(text: &str, name: &str) -> Option<String> {
    let want = serde_json::json!(name).to_string();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("entity ") else {
            continue;
        };
        let Some((label, rest)) = rest.split_once(' ') else {
            continue;
        };
        if rest == want {
            return Some(label.to_owned());
        }
    }
    None
}

/// The label the listing in `text` gave a head with `predicate`, if any.
fn claim_label(text: &str, predicate: &str) -> Option<String> {
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("  claim ") else {
            continue;
        };
        let Some((label, rest)) = rest.split_once(' ') else {
            continue;
        };
        let Some((shown, _)) = rest.split_once(' ') else {
            continue;
        };
        if shown == predicate {
            return Some(label.to_owned());
        }
    }
    None
}

/// `template` with each `{{entity:NAME}}` and `{{claim:PREDICATE}}` token
/// replaced by the label the listing in `text` gave it; `None` when a
/// token names no label there, so the call is answered with no candidates.
fn substitute(template: &str, text: &str) -> Option<String> {
    let mut reply = template.to_owned();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let end = after.find("}}")?;
        let token = &after[..end];
        let full = &rest[start..start + 2 + end + 2];
        let (kind, key) = token.split_once(':')?;
        let label = match kind {
            "entity" => entity_label(text, key)?,
            "claim" => claim_label(text, key)?,
            _ => return None,
        };
        reply = reply.replacen(full, &label, 1);
        rest = &after[end + 2..];
    }
    Some(reply)
}

impl LlmBackend for ProbeBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let text = request_text(&request);
        let reply = substitute(&self.template, &text).unwrap_or_else(|| NO_CANDIDATES.to_owned());
        self.calls.lock().expect("call log").push(text);
        let response = LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: reply,
                    signature: None,
                }],
            },
            usage: LlmUsage {
                input: LlmInputUsage {
                    total: 40,
                    cache_read: 0,
                    cache_write: 0,
                },
                output: LlmOutputUsage {
                    total: 10,
                    text: 10,
                    reasoning: 0,
                },
                raw_provider: serde_json::Value::Null,
                call_metadata: None,
            },
            finish_reason: FinishReason::Stop,
            reply_assertions: Default::default(),
            token_scores: None,
        };
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the consolidation pass did not finish in one poll"),
    }
}

fn allow_fixture_extraction(_: &LlmRequest) -> bool {
    true
}

/// Witnesses `words` as one visible user MESSAGE into a fresh TURN, then runs
/// one Micro consolidation pass with no caller scope (an unbound branch),
/// the scripted model answering every call from `template` (see
/// [`substitute`]), and lands what it extracts through the promotion writer.
///
/// # Errors
///
/// The vault's, or a pass that is never admitted.
pub fn probe_unbound_turn(vault: &Vault, words: &str, template: &str) -> Result<ProbedPass> {
    let (turn, _) =
        super::consolidation::witness_user_turn(vault, EntityId::now(), words, None, 10)?;
    let actor = vault.dreamer_authority()?;

    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark(vault, scope)?;
    let dirty = scan_dirty_turns(vault, scope, &watermark, 10)?;
    enqueue_partition_attempts(vault, scope, &dirty, &watermark, "run-1", 20)?;
    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
        admitted,
    )) = DreamerRunnerStore::new(vault).admit_next_consolidation(
        AdmitDreamerConsolidationAttempt {
            scope,
            local_node_id: crate::identity::load_or_mint_client_id(vault)?,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "test-door".to_owned(),
                now: 21,
                budget_id: "wake".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        },
    )?
    else {
        return Err(Error::InvalidConfig(
            "no consolidation attempt was admitted".into(),
        ));
    };

    let backend = ProbeBackend {
        template: template.to_owned(),
        calls: Mutex::new(Vec::new()),
    };
    let guard =
        BudgetGuard::with_reserve_units("wake", 10_000, 100, BudgetExhaustionPolicy::Suspend);
    let mut sink = PromotionWriterSink::new(
        vault,
        DreamerRunContext {
            run_id: "run-1".into(),
            attempt_id: admitted.status.attempt.id,
            agent_actor: actor,
            now_ms: 21_000,
        },
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let outcome = {
        let mut executor = ConsolidationExecutor {
            roles: Default::default(),
            backend: &backend,
            guard: &guard,
            strategy: DreamerClaimAuthoringStrategy::SinglePass,
            actor,
            model: ModelId::new("test/model@r1")
                .map_err(|_| Error::InvalidConfig("model id".into()))?,
            inference: HostInferenceContext {
                binding: HostInferenceBinding::Advertised {
                    model: ModelId::new("test/model@r1")
                        .map_err(|_| Error::InvalidConfig("model id".into()))?,
                    locality: ModelLocality::OwnServer,
                    keyless: false,
                },
                extraction_egress: Some(&allow_fixture_extraction),
            },
            sink: &mut sink,
            scope: None,
            decisions: ConsolidationDecisions::shipped()?,
        };
        ready(executor.execute(
            &admitted,
            &mut WakeAttemptContext {
                vault,
                deadline: &deadline,
                cancel: None,
                device_cancel: None,
                budget_id: "wake",
                now_ms: 21_000,
                prepared_wake: None,
                prepared_attempt: None,
                spend_meter: None,
            },
        ))
    };
    Ok(ProbedPass {
        turn,
        attempt: admitted.status.attempt.id,
        requests: backend.calls.into_inner().expect("call log"),
        outcome,
        landed: std::mem::take(&mut sink.outcome.landed),
    })
}
