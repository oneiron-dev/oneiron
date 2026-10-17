//! The live weave lens's generate step (OF-499, ARCH-0063 §6):
//! `vault.weave.lens` and `POST /v1/owner/weave/lens` render the caller's
//! live weave report through the shipped weave-report skill, on demand and
//! outside the Dreamer pass, on the Dreamer narrative role's route. The
//! engine reads the report and the skill under the caller's own read before
//! the step, then re-reads the report and composes the lens after it. The
//! host lends the route, a run on the caller's own budget line and the
//! egress decision. Nothing is saved: a digest period's render is the
//! Dreamer's (`dreamer.weave_lens`).
use std::sync::Arc;

use oneiron::claim::{CallerLocality, WeaveLiveLens, WeaveReportRequest};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_consolidation::{DREAMER_NARRATIVE_ROLE, live_weave_lens_request};
use oneiron::lens::GeneratedLens;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::memory::{
    MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE, Memory,
    MemoryError, MemoryResult,
};
use oneiron::{
    BudgetExhaustionPolicy, ContentPart, EdgeActorClass, EntityId, LlmCapability, LlmError,
    ModelLocality, RetryableLlmError, Vault, WriteActor,
};

use crate::auth::CoreAuth;
use crate::server::SyncServer;

const VERB: &str = "vault.weave.lens";

/// Whose live lens renders, and under which proof.
#[derive(Clone)]
pub(crate) enum WeaveLensCaller {
    /// A facade credential reads its own lens: a person the person lens, an
    /// agent its own.
    Credential {
        auth: CoreAuth,
        actor: EntityId,
        class: EdgeActorClass,
    },
    /// The owner route reads the owner lens under a live owner proof.
    Owner {
        owner: AuthenticatedOwner,
        locality: CallerLocality,
    },
}

impl WeaveLensCaller {
    fn locality(&self) -> CallerLocality {
        match self {
            Self::Credential { auth, .. } => auth.locality(),
            Self::Owner { locality, .. } => *locality,
        }
    }

    /// Runs `read` on the caller's own handle, reading at `reads_at`. The
    /// owner proof is revalidated at each read.
    fn read<T>(
        &self,
        vault: &Vault,
        reads_at: CallerLocality,
        read: impl FnOnce(&Memory<'_>, Option<&AuthenticatedOwner>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        match self {
            Self::Credential { auth, actor, class } => read(
                &crate::api::credential_memory(vault, Some(auth), *actor, *class).at(reads_at),
                None,
            ),
            Self::Owner { owner, .. } => {
                let actor = owner.revalidate(vault)?;
                read(
                    &vault.memory(actor, EdgeActorClass::Human).at(reads_at),
                    Some(owner),
                )
            }
        }
    }
}

fn unavailable(message: String) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        message,
        &["Serve a model on the Dreamer's narrative role ([models.dreamer]), or read vault.weave.report."],
    )
}

fn step_failed(error: &LlmError) -> MemoryError {
    let code = match error {
        LlmError::BudgetDenied(_) | LlmError::Retryable(RetryableLlmError::QuotaSpent { .. }) => {
            MEMORY_CODE_BUDGET_SPENT
        }
        _ => MEMORY_CODE_MODEL_UNAVAILABLE,
    };
    MemoryError::new(
        code,
        format!("{VERB}: the model did not answer: {error}"),
        &["Retry later, or read vault.weave.report."],
    )
}

fn joined() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        format!("{VERB} did not finish on this server"),
        &["Report this SDK host-door failure."],
    )
}

/// Renders `caller`'s live weave report into its lens. A server that serves
/// no route for the Dreamer's narrative role, or a skill that does not load,
/// renders nothing and says so; it never passes the data off as a render.
pub(crate) async fn render_live_weave_lens(
    server: &Arc<SyncServer>,
    caller: WeaveLensCaller,
    request: WeaveReportRequest,
) -> MemoryResult<GeneratedLens> {
    let vault = Arc::clone(server.vault());
    let runtime = server.ai.model_runtime();
    let role = DREAMER_NARRATIVE_ROLE;
    let seat = runtime
        .seat(role)
        .ok_or_else(|| unavailable(format!("{VERB}: no model seat serves the Dreamer")))?;
    let route = runtime
        .route_role(&vault, role, seat)
        .map_err(|refusal| unavailable(format!("{VERB}: {refusal}")))?;
    // The report goes to the model and its lens back to the caller: it is
    // read as the farther of the two, on this device only when both are.
    let reads_at = if caller.locality() == CallerLocality::OnDevice
        && route.locality == ModelLocality::OnDevice
    {
        CallerLocality::OnDevice
    } else {
        CallerLocality::OffDevice
    };
    let (live, actor) = {
        let vault = Arc::clone(&vault);
        let (caller, request) = (caller.clone(), request.clone());
        tokio::task::spawn_blocking(move || {
            caller.read(&vault, reads_at, |memory, owner| {
                let live = memory.weave_lens_prepare(owner, &request)?;
                Ok((live, WriteActor::new(memory.actor(), memory.actor_class())))
            })
        })
        .await
        .map_err(|_| joined())??
    };
    let live: WeaveLiveLens = live.ok_or_else(|| {
        unavailable(format!(
            "{VERB}: the weave-report skill is retired, unapproved or missing"
        ))
    })?;
    // The caller's own line pays for the step, as a chat turn's does.
    let settings = server.ai.chat_settings();
    let run_id = format!(
        "weave_lens:{}:{}",
        actor.entity_ref().to_hex(),
        vault.now_recorded_at()
    );
    let meter = vault.policy_budget_guard(
        run_id.clone(),
        settings.turn_budget_units,
        oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(settings.turn_budget_units),
        BudgetExhaustionPolicy::Suspend,
        actor,
    )?;
    let run = server.ai.undeclared_run(run_id, meter);
    let model = route.model.clone();
    let step = live_weave_lens_request(
        &vault,
        &live,
        role,
        model.clone(),
        &HostInferenceContext {
            binding: HostInferenceBinding::Advertised {
                model: model.clone(),
                locality: route.locality,
            },
            extraction_egress: server.extraction_egress.as_deref(),
        },
        route.ladder.supports(&model, &LlmCapability::Reasoning),
    )?;
    let response = route
        .ladder
        .generate(&run, step, None)
        .await
        .map_err(|error| step_failed(&error))?;
    let answer: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    tokio::task::spawn_blocking(move || {
        caller.read(&vault, reads_at, |memory, owner| {
            memory.weave_lens_finish(owner, &request, live, &answer, model.as_str())
        })
    })
    .await
    .map_err(|_| joined())?
}
