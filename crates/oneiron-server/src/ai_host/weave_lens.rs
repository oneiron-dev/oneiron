//! The live weave lens's generate step (OF-499, ARCH-0063 §6):
//! `vault.weave.lens` and `POST /v1/owner/weave/lens` render the caller's
//! live weave report through the shipped weave-report skill, on demand and
//! outside the Dreamer pass, on the Dreamer narrative role's route, else its
//! extraction role's (as a TASK realizes). The engine reads the report and
//! the skill under the caller's own read before the step, then re-reads the
//! report and composes the lens after it. The host lends the route, a run on
//! the caller's own budget line and the egress decision. The engine keeps
//! the caller's newest live render, and the one before it settles on the
//! skill's corrections axis; a digest period's render is the Dreamer's
//! (`dreamer.weave_lens`). The lens answers as a card, lowered once for the
//! whole atom kit, and its frame is held for the caller's events on it
//! before the answer leaves (OF-181, [`crate::lens_frames`]).
use std::sync::Arc;

use oneiron::authority::AuthenticatedWeaveAdmin;
use oneiron::claim::{
    CallerLocality, WEAVE_LENS_PLAN_REPAIRS, WEAVE_LIVE_LENS_REREADS, WeaveLiveLens,
    WeaveReportRequest,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_consolidation::{
    DREAMER_EXTRACTION_ROLE, DREAMER_NARRATIVE_ROLE, live_weave_lens_request,
};
use oneiron::lens::{GeneratedUiSurfaceCapabilities, HostedLensRender, LensFrameCard};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::memory::{
    MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult, ProducerRows,
};
use oneiron::{
    BudgetExhaustionPolicy, ContentPart, EdgeActorClass, EntityId, LlmCapability, LlmError,
    LlmMessage, LlmMessageRole, ModelLocality, RetryableLlmError, Vault, WriteActor,
};

use crate::auth::CoreAuth;
use crate::lens_frames::CardOwner;
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
        auth: CoreAuth,
    },
    /// A weave Admin reads the Admin lens under its current Admin proof
    /// (OF-499 A3), on its own person's handle (`actor`). Only an explicit
    /// Admin request builds one, never a credential's membership; the
    /// engine revalidates the proof in each read's own transaction.
    #[expect(
        dead_code,
        reason = "L13's Admin step-up ingress (FIX 9431) is its first constructor"
    )]
    Admin {
        admin: AuthenticatedWeaveAdmin,
        auth: CoreAuth,
        actor: EntityId,
    },
    /// A pumped run reads its own agent's lens (FIX 2086): on the agent's
    /// own lane on this device, its step spending on the run's own `line`
    /// when one binds the entry, and its card held for the run, whose end
    /// closes it. The run holds no credential and borrows none.
    Run {
        actor: EntityId,
        class: EdgeActorClass,
        run: EntityId,
        line: Option<RunAdmission>,
    },
}

/// Which engine lens a caller's handle reads: the bound actor's own (the
/// owner lens under an Owner proof), or the Admin lens under an Admin proof.
#[derive(Clone, Copy)]
enum LensReader<'a> {
    Bound(Option<&'a AuthenticatedOwner>),
    Admin(&'a AuthenticatedWeaveAdmin),
}

impl LensReader<'_> {
    /// The live report keyed for the skill, before the generate step.
    fn prepare(
        self,
        memory: &Memory<'_>,
        request: &WeaveReportRequest,
    ) -> MemoryResult<Option<WeaveLiveLens>> {
        match self {
            Self::Bound(owner) => memory.weave_lens_prepare(owner, request),
            Self::Admin(admin) => memory.weave_admin_lens_prepare(admin, request),
        }
    }

    /// The re-read and the composed lens, after the generate step.
    fn finish(
        self,
        memory: &Memory<'_>,
        request: &WeaveReportRequest,
        live: WeaveLiveLens,
        answer: &str,
        model: &str,
    ) -> MemoryResult<Option<HostedLensRender>> {
        match self {
            Self::Bound(owner) => {
                memory.weave_lens_finish_framed(owner, request, live, answer, model)
            }
            Self::Admin(admin) => {
                memory.weave_admin_lens_finish_framed(admin, request, live, answer, model)
            }
        }
    }
}

impl WeaveLensCaller {
    /// The credential that asked, under which its card's frame is held;
    /// `None` for a run, which holds its card itself.
    fn auth(&self) -> Option<&CoreAuth> {
        match self {
            Self::Credential { auth, .. } | Self::Owner { auth, .. } | Self::Admin { auth, .. } => {
                Some(auth)
            }
            Self::Run { .. } => None,
        }
    }

    /// Where the caller reads from: a credential's locality; a run's own
    /// door is on this device.
    fn locality(&self) -> CallerLocality {
        self.auth()
            .map_or(CallerLocality::OnDevice, CoreAuth::locality)
    }

    /// Runs `read` on the caller's own handle, reading at `reads_at` and
    /// listing in `producers` the rows its reads derive the lens from. The
    /// owner proof is revalidated at each read, as is an Admin's, in each
    /// engine read's own transaction.
    fn read<T>(
        &self,
        vault: &Vault,
        reads_at: CallerLocality,
        producers: &ProducerRows,
        read: impl FnOnce(&Memory<'_>, LensReader<'_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        match self {
            Self::Credential { auth, actor, class } => read(
                &crate::api::credential_memory(vault, Some(auth), *actor, *class)
                    .at(reads_at)
                    .listing_producers(producers),
                LensReader::Bound(None),
            ),
            Self::Owner { owner, .. } => {
                let actor = owner.revalidate(vault)?;
                read(
                    &vault
                        .memory(actor, EdgeActorClass::Human)
                        .at(reads_at)
                        .listing_producers(producers),
                    LensReader::Bound(Some(owner)),
                )
            }
            Self::Admin { admin, auth, actor } => read(
                &crate::api::credential_memory(vault, Some(auth), *actor, EdgeActorClass::Human)
                    .at(reads_at)
                    .listing_producers(producers),
                LensReader::Admin(admin),
            ),
            Self::Run { actor, class, .. } => read(
                &vault
                    .memory(*actor, *class)
                    .at(reads_at)
                    .listing_producers(producers),
                LensReader::Bound(None),
            ),
        }
    }
}

fn unavailable(message: String) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        message,
        &[
            "Serve a model on the Dreamer's narrative or extraction role ([models.dreamer]), or read vault.weave.report.",
        ],
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
/// no route for the Dreamer's narrative or extraction role, or a skill that
/// does not load, renders nothing and says so; it never passes the data off
/// as a render.
pub(crate) async fn render_live_weave_lens(
    server: &Arc<SyncServer>,
    caller: WeaveLensCaller,
    request: WeaveReportRequest,
) -> MemoryResult<LensFrameCard> {
    render_live_weave_lens_listing(server, caller, request, None)
        .await
        .0
}

/// [`render_live_weave_lens`], beside the rows its report reads listed:
/// every read the lens rendered from, a reread's with them. The card is
/// lowered for `surface` when the caller names one (FIX 7969), else for the
/// whole atom kit.
pub(crate) async fn render_live_weave_lens_listing(
    server: &Arc<SyncServer>,
    caller: WeaveLensCaller,
    request: WeaveReportRequest,
    surface: Option<GeneratedUiSurfaceCapabilities>,
) -> (MemoryResult<LensFrameCard>, Vec<EntityId>) {
    let producers = Arc::new(ProducerRows::default());
    let answer = render_listing(server, caller, request, &producers, None, surface).await;
    (answer, producers.take())
}

/// [`render_live_weave_lens_listing`] for a run's re-render of a live
/// subscription (OF-181, FIX 2612): the run that rendered the card owns it,
/// so a successful render replaces the card the same run rendered for the
/// same subscription, a failed one keeps the last good card, and the run's
/// end closes them all.
pub(crate) async fn render_live_weave_lens_for_run(
    server: &Arc<SyncServer>,
    caller: WeaveLensCaller,
    request: WeaveReportRequest,
    owner: crate::lens_frames::CardOwner,
    surface: Option<GeneratedUiSurfaceCapabilities>,
) -> (MemoryResult<LensFrameCard>, Vec<EntityId>) {
    let producers = Arc::new(ProducerRows::default());
    let answer = render_listing(server, caller, request, &producers, Some(owner), surface).await;
    (answer, producers.take())
}

async fn render_listing(
    server: &Arc<SyncServer>,
    caller: WeaveLensCaller,
    request: WeaveReportRequest,
    producers: &Arc<ProducerRows>,
    owner: Option<crate::lens_frames::CardOwner>,
    surface: Option<GeneratedUiSurfaceCapabilities>,
) -> MemoryResult<LensFrameCard> {
    let surface = surface.unwrap_or_default();
    let vault = Arc::clone(server.vault());
    let runtime = server.ai.model_runtime();
    // An agent that dreams on its own model reads its own lens on that
    // model (OF-490); anyone else on the narrative role's route, else the
    // extraction role's.
    let own = match &caller {
        WeaveLensCaller::Credential {
            actor,
            class: EdgeActorClass::Agent,
            ..
        }
        | WeaveLensCaller::Run {
            actor,
            class: EdgeActorClass::Agent,
            ..
        } => match super::dreamer::own_dreaming_slot(&vault, *actor)? {
            Some(slot) => super::dreamer::served_slot_model(&vault, runtime, &slot)?,
            None => None,
        },
        _ => None,
    };
    let (role, model, locality, ladder) = match own {
        Some((model, locality, ladder)) => (None, model, locality, ladder),
        None => {
            let mut refused = None;
            let mut chosen = None;
            for role in [DREAMER_NARRATIVE_ROLE, DREAMER_EXTRACTION_ROLE] {
                let Some(seat) = runtime.seat(role) else {
                    continue;
                };
                match runtime.route_role(&vault, role, seat) {
                    Ok(route) => {
                        chosen = Some((role, route));
                        break;
                    }
                    Err(refusal) => {
                        refused.get_or_insert_with(|| refusal.to_string());
                    }
                }
            }
            let (role, route) = chosen.ok_or_else(|| {
                unavailable(match refused {
                    Some(refusal) => format!("{VERB}: {refusal}"),
                    None => format!("{VERB}: no model seat serves the Dreamer"),
                })
            })?;
            (Some(role), route.model, route.locality, route.ladder)
        }
    };
    // The report goes to the model and its lens back to the caller: it is
    // read as the farther of the two, on this device only when both are.
    let reads_at =
        if caller.locality() == CallerLocality::OnDevice && locality == ModelLocality::OnDevice {
            CallerLocality::OnDevice
        } else {
            CallerLocality::OffDevice
        };
    let (first, actor) = prepare_live(&vault, &caller, &request, reads_at, producers).await?;
    // The caller's own line pays for every step, as a chat turn's does: a
    // run's, the line its entry spends on (FIX 2086).
    let run = match &caller {
        WeaveLensCaller::Run {
            line: Some(line), ..
        } => line.clone(),
        _ => {
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
            server.ai.undeclared_run(run_id, meter)
        }
    };
    let auth = caller.auth().cloned();
    let mut next = Some(first);
    for _ in 0..=WEAVE_LIVE_LENS_REREADS {
        let live = match next.take() {
            Some(live) => live,
            None => {
                prepare_live(&vault, &caller, &request, reads_at, producers)
                    .await?
                    .0
            }
        };
        let mut step = live_weave_lens_request(
            &vault,
            &live,
            role,
            model.clone(),
            &HostInferenceContext {
                binding: HostInferenceBinding::Advertised {
                    model: model.clone(),
                    locality,
                },
                extraction_egress: server.extraction_egress.as_deref(),
            },
            ladder.supports(&model, &LlmCapability::Reasoning),
        )?;
        let mut repairs = 0;
        let answer = loop {
            let response = ladder
                .generate(&run, step.clone(), None)
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
            // A refused plan goes back to the model with why, while it has
            // repairs left; the last answer is checked again as it closes.
            match live.plan_refusal(&answer) {
                Some(reason) if repairs < WEAVE_LENS_PLAN_REPAIRS => {
                    repairs += 1;
                    step.messages.push(response.message);
                    step.messages.push(LlmMessage {
                        role: LlmMessageRole::User,
                        content: vec![ContentPart::Text {
                            text: live.repair_text(&reason),
                        }],
                    });
                }
                _ => break answer,
            }
        };
        let hosted = {
            let (vault, caller, request, model, producers) = (
                Arc::clone(&vault),
                caller.clone(),
                request.clone(),
                model.clone(),
                Arc::clone(producers),
            );
            tokio::task::spawn_blocking(move || {
                caller.read(&vault, reads_at, &producers, |memory, reader| {
                    reader.finish(memory, &request, live, &answer, model.as_str())
                })
            })
            .await
            .map_err(|_| joined())??
        };
        // The report moved between the reads: the lens renders again from a
        // fresh read, while rereads are left.
        let Some(hosted) = hosted else {
            continue;
        };
        let (frame, card) = hosted.lower(&surface)?;
        match (&caller, &auth, owner) {
            // A run holds its card itself, and its end closes it (FIX 2086).
            (WeaveLensCaller::Run { run, .. }, _, owner) => {
                let owner = owner.unwrap_or_else(|| CardOwner {
                    creator_run: run.to_hex(),
                    subscription: None,
                });
                server
                    .lens_frames
                    .replace_for_run(*run, frame, card.render.clone(), owner)?;
            }
            (_, Some(auth), Some(owner)) => {
                server.lens_frames.replace_for_subscription(
                    auth,
                    frame,
                    card.render.clone(),
                    owner,
                )?;
            }
            (_, Some(auth), None) => server
                .lens_frames
                .record(auth, frame, card.render.clone())?,
            (_, None, _) => return Err(joined()),
        }
        return Ok(card);
    }
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{VERB}: the weave report changed while its lens rendered"),
        &["Ask for the lens again."],
    ))
}

/// The caller's live report keyed for the skill, read at `reads_at`, and
/// the caller as the step's actor.
async fn prepare_live(
    vault: &Arc<Vault>,
    caller: &WeaveLensCaller,
    request: &WeaveReportRequest,
    reads_at: CallerLocality,
    producers: &Arc<ProducerRows>,
) -> MemoryResult<(WeaveLiveLens, WriteActor)> {
    let (live, actor) = {
        let vault = Arc::clone(vault);
        let (caller, request, producers) = (caller.clone(), request.clone(), Arc::clone(producers));
        tokio::task::spawn_blocking(move || {
            caller.read(&vault, reads_at, &producers, |memory, reader| {
                let live = reader.prepare(memory, &request)?;
                Ok((live, WriteActor::new(memory.actor(), memory.actor_class())))
            })
        })
        .await
        .map_err(|_| joined())??
    };
    let live = live.ok_or_else(|| {
        unavailable(format!(
            "{VERB}: the weave-report skill is retired, unapproved or missing"
        ))
    })?;
    Ok((live, actor))
}
