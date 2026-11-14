//! The task-brief composer's model on this server (census L8-07): the
//! `[models.roles.local_reasoner]` seat drafts the brief a `tasks.create`
//! one-liner names (RULING L8-07-DOOR = A, 14 Nov 09:11; canon
//! workbench-engine-asks.md:76: "composed by a local model from a one-liner
//! plus lens context").
//!
//! The engine owns the prompt, the reply schema, the reply check and the
//! stamp; this host owns only the call. [`HostTaskBriefModel::install`]
//! puts it on the served vault once the seats are built, whatever the seat's
//! locality: the engine refuses a third-party one before any call, and its
//! refusal names the binding to fix. The call is one admitted request of the
//! role, metered on the caller's own lease, and refused whole when its route
//! or the rung that answered runs at a third party.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use oneiron::llm::manifest::ModelRole;
use oneiron::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult};
use oneiron::task_verb::{TaskBriefDraftRequest, TaskBriefModel, TaskBriefModelBinding};
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage,
    LlmMessageRole, LlmRequest, ModelLocality, ModelTierRef, ResponseFormat, RetryableLlmError,
    TierPrecedence,
};

use crate::models::CallDeadline;
use crate::server::SyncServer;

/// The role whose seat drafts.
const ROLE: ModelRole = ModelRole::LocalReasoner;
/// The purpose each call is budgeted and audited under.
const PURPOSE: &str = "tasks.compose_brief";
/// The longest one draft waits, cooling waits included: the caller's
/// create waits on it.
const DRAFT_TIME_LIMIT: Duration = Duration::from_secs(120);
/// What a refusal of the call tells its caller to do.
const DRAFT_SUGGESTION: &str = "Compose again, or post the brief written out with `brief`.";

/// The `local_reasoner` seat as the vault's task-brief model. It holds its
/// server weakly, as the server's managed-owner check does: the vault holds
/// it.
pub(crate) struct HostTaskBriefModel {
    server: Weak<SyncServer>,
    runtime: tokio::runtime::Handle,
    binding: TaskBriefModelBinding,
}

impl HostTaskBriefModel {
    /// Installs the `[models.roles.local_reasoner]` seat as `server`'s
    /// task-brief model; nothing when no such seat is bound, so a one-liner
    /// create is refused with the binding to add. A call blocks on the
    /// runtime this runs on. A second install does nothing.
    pub(crate) fn install(server: &Arc<SyncServer>) {
        let Some(seat) = server.ai.seat(ROLE) else {
            return;
        };
        let model = Arc::new(Self {
            server: Arc::downgrade(server),
            runtime: tokio::runtime::Handle::current(),
            binding: TaskBriefModelBinding {
                model: seat.model.to_string(),
                locality: seat.locality,
            },
        });
        let _ = server.vault().install_task_brief_model(model);
    }
}

impl TaskBriefModel for HostTaskBriefModel {
    /// The seat's model, and its widest rung's locality.
    fn binding(&self) -> TaskBriefModelBinding {
        self.binding.clone()
    }

    /// Blocks on the server's runtime until the seat answers, so it runs on
    /// a blocking thread, as a task row's call does, never on one of that
    /// runtime's workers.
    fn draft(&self, request: &TaskBriefDraftRequest<'_>) -> MemoryResult<String> {
        let server = self
            .server
            .upgrade()
            .ok_or_else(|| refused("the server that serves this vault has stopped"))?;
        let vault = server.vault();
        let seat = server
            .ai
            .seat(ROLE)
            .ok_or_else(|| refused("no [models.roles.local_reasoner] seat is bound"))?;
        let purpose = CallPurpose::Other {
            name: PURPOSE.to_owned(),
        };
        let call = LlmRequest {
            model: seat.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(PURPOSE.to_owned())),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Json {
                    schema: request.schema.clone(),
                },
                locality: seat.locality,
                host_keyless: false,
                host_paid: false,
            },
            messages: vec![
                message(LlmMessageRole::System, request.instruction),
                message(LlmMessageRole::User, request.input),
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        let admitted = server.ai.admit_role(vault, ROLE, call).map_err(|refusal| {
            refused(&format!("the local reasoner call was refused: {refusal}"))
        })?;
        // The route the vault's policy picked must keep the call local too.
        if admitted.request.envelope.locality == ModelLocality::ThirdParty {
            return Err(refused(
                "the vault routes the local reasoner to a third party; a brief is composed by a local model only",
            ));
        }
        let run_id = format!(
            "{PURPOSE}:{}:{}",
            request.caller.entity_ref().to_hex(),
            vault.now_recorded_at()
        );
        let settings = server.ai.chat_settings();
        let meter = vault
            .policy_budget_guard(
                run_id.clone(),
                settings.turn_budget_units,
                oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(settings.turn_budget_units),
                BudgetExhaustionPolicy::Suspend,
                request.caller,
            )
            .map_err(|error| {
                refused(&format!(
                    "the local reasoner call was not admitted: {error}"
                ))
            })?;
        // It bills the payer the caller's run binds (FIX 3574), else the owner.
        let run = server.ai.model_runtime().funded_run(
            run_id,
            meter,
            crate::decision_verdict::rung_payer(),
        );
        let wait_budget = admitted.ladder.cooling_wait_budget(DRAFT_TIME_LIMIT);
        let answered = self.runtime.block_on(async {
            tokio::time::timeout(
                DRAFT_TIME_LIMIT,
                admitted.ladder.generate_recorded_by(
                    &run,
                    admitted.request,
                    None,
                    &|| true,
                    CallDeadline::waits_within(wait_budget),
                ),
            )
            .await
            .unwrap_or_else(|_| Err(RetryableLlmError::Timeout.into()))
        });
        let (response, binding) = answered
            .map_err(|error| refused(&format!("the local reasoner call failed: {error}")))?;
        // A fallback rung that answered from a third party is not a local
        // draft: its reply is dropped.
        if binding.rung.locality == ModelLocality::ThirdParty {
            return Err(refused(
                "a third-party rung answered the local reasoner call; its draft is dropped",
            ));
        }
        Ok(response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect())
    }
}

fn refused(why: &str) -> MemoryError {
    MemoryError::new(MEMORY_CODE_MODEL_UNAVAILABLE, why, &[DRAFT_SUGGESTION])
}

fn message(role: LlmMessageRole, text: &str) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text {
            text: text.to_owned(),
            signature: None,
        }],
    }
}
