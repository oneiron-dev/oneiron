//! The host doors of the verb-table rows only a server's own state answers:
//! the owner's `vault.packs.put`, `vault.hooks.replay` and
//! `vault.authority.audit`, the `ai.*` model calls past text, and
//! `ai.verdict` through the host's decision ladder. The
//! generated HTTP facade handler and the MCP dispatcher both call these, so
//! a tool call, a code-mode call and an SDK call meet one admission.
//!
//! The owner's pack, subscription, setup, audit, mesh and lens doors list
//! their rows (`host_door_lists`): each lists the rows its answer is read
//! from, and none for the state that lives in side tables or the authority
//! log, which hold no row.
//!
//! The `ai.*` doors admit as `/v1/ai/<operation>` does (api/ai/media.rs):
//! the call is the owner's, the vault's inference policy admits its model,
//! then its seat's ladder admits, sends and settles each rung it reaches.
use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::llm::media::{AiOperation, MediaPart, MediaRequest, Modality};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult,
    ProducerRows,
};
use oneiron::runtime_hooks::HookVerdict;
use oneiron::task_verb::sdk::{
    AiAnswer, AiCallRequest, AiOptions, AiOptionsRequest, AiVerdict, AiVerdictRequest,
    AiVideoCancelled, AiVideoJob, AiVideoJobRequest, AiVideoTicket, AiVoice, HookReplayRow,
    HooksReplayRequest, PackPutReceipt, PackPutRequest,
};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, EdgeActorClass, EntityId, FatalLlmError, LlmError,
    ModelId, ModelTierRef, ResponseFormat, RetryableLlmError, TierPrecedence,
};

use oneiron::lens::{LensActivateRequest, LensDeactivateRequest};
use oneiron::receipt::LensActivationReceipt;
use oneiron::task_verb::sdk::{
    ChannelSubscriptionRequest, ChannelSubscriptionRevokeRequest, ChannelSubscriptionRevoked,
    ChannelSubscriptions, ChannelSubscriptionsRequest, PackRemoveRequest, PackSetupAnswerRequest,
    PackSetupReceipt, PackSetupRequest, PackSetupVerifyRequest,
};

use crate::api::ai::{VoiceRefusal, bind_voice, caller_options};
use crate::auth::CoreAuth;
use crate::builtin_host::HostConnectionChecks;
use crate::models::RungVoices;
use crate::server::SyncServer;

// The signed authority history doors, under the audit door's owner proof.
pub(crate) use super::artifact_hosting_doors::*;
pub(crate) use super::authority_history_doors::*;
pub(crate) use super::booking_doors::*;
pub(crate) use super::browser_doors::*;
pub(crate) use super::calendar_doors::*;
pub(crate) use super::campaign_doors::*;
pub(crate) use super::compliance_doors::*;
pub(crate) use super::credential_doors::*;
pub(crate) use crate::api::anonymous_chat::ai_anonymous_chat;

// The shared-vault doors live beside these; the generated callers name them here.
pub(crate) use super::agent_definition_doors::*;
pub(crate) use super::shared_act_doors::*;
// The shared-vault invitation doors (OF-531) too.
pub(crate) use super::shared_member_doors::*;
// The shared-act policy doors (DOOR-129) too.
pub(crate) use super::shared_policy_doors::*;
// The trusted-contact doors (DOOR-140, OF-527) too.
pub(crate) use super::trusted_contact_doors::*;
// The owner's voice-bank doors (DOOR-143) too.
pub(crate) use super::voice_bank_doors::*;
// The owner's legal-hold doors (OF-470) too.
pub(crate) use super::asr_doors::*;
pub(crate) use super::cleanup_doors::*;
pub(crate) use super::extraction_doors::*;
pub(crate) use super::legal_hold_doors::*;
pub(crate) use super::linear_doors::*;
pub(crate) use super::live_run_doors::*;
pub(crate) use super::live_voice_doors::*;
pub(crate) use super::model_step_doors::*;
// The owner's committed-run reads (DOOR-141 A/B), likewise.
pub(crate) use super::run_read_doors::*;
pub(crate) use super::run_review_doors::*;
pub(crate) use super::skill_execution_doors::*;
pub(crate) use super::sieve_observation_doors::*;
// The owner's courtesy delete doors (OF-273) too.
pub(crate) use super::courtesy_delete_doors::*;
// The owner's guest revoke door (OF-232) too.
pub(crate) use super::coreference_doors::*;
// The owner's subject-bound feedback and report doors, likewise.
pub(crate) use super::federation_connect_doors::*;
pub(crate) use super::feedback_doors::*;
pub(crate) use super::goal_optimize_doors::*;
pub(crate) use super::guest_document_doors::*;
pub(crate) use super::guest_doors::*;
pub(crate) use super::hub_doors::*;
pub(crate) use super::skill_doors::*;
// The owner's support grant doors (OF-606), as the guest ones are.
pub(crate) use super::support_grant_doors::*;
// The owner's residence doors (OF-534), likewise.
pub(crate) use super::fold_doors::*;
pub(crate) use super::foreign_code_doors::*;
pub(crate) use super::note_doors::*;
pub(crate) use super::off_record_doors::*;
pub(crate) use super::persona_doors::*;
pub(crate) use super::residence_doors::*;
pub(crate) use super::summary_doors::*;
// The weave lens's human doors, likewise.
pub(crate) use super::weave_doors::*;
pub(crate) use super::web_fetch_doors::*;
// The graph ask and standing-question doors (OF-506), likewise.
pub(crate) use super::graph_ask_doors::*;
// The share doors past create (OF-491), likewise.
pub(crate) use super::share_doors::*;
// The role-holder decision-ask doors (OF-493), likewise.
pub(crate) use super::decision_ask_doors::*;
pub(crate) use super::decision_band_doors::*;
// The vault shape's apply door (ARCH-0070), likewise.
pub(crate) use super::vault_shape_doors::*;
// The owner's embedding-space doors (OF-370), likewise.
pub(crate) use super::embedding_space_doors::*;
// The owner's fan-out ruling doors (OF-393), likewise.
pub(crate) use super::budget_doors::*;
pub(crate) use super::fanout_doors::*;
// The owner's learned-setting doors, likewise.
pub(crate) use super::learning_doors::*;
pub(crate) use super::seal_doors::*;
pub(crate) use super::setting_doors::*;
pub(crate) use super::slim_doors::*;
// The owner's historical secret lift sweep door (OF-067), likewise.
pub(crate) use super::secret_lift_doors::*;
// The owner's root wave door (OF-427), likewise.
pub(crate) use super::wave_doors::*;
// The owner's context-widen proposal doors (OF-568), likewise.
pub(crate) use super::widen_proposal_doors::*;
// The owner's craft-candidate review doors (OF-490), likewise.
pub(crate) use super::craft_candidate_doors::*;
// The app's policy-action doors (OF-181), likewise.
pub(crate) use super::channel_doors::*;
pub(crate) use super::consent_doors::*;
pub(crate) use super::content_policy_doors::*;
pub(crate) use super::gate_policy_doors::*;
pub(crate) use super::graduation_doors::*;
pub(crate) use super::policy_doors::*;
// The owner's origin and checkout doors (DOOR-139), likewise.
pub(crate) use super::checkout_doors::*;
pub(crate) use super::origin_doors::*;
// The owner's code snapshot doors (DOOR-118), likewise.
pub(crate) use super::codebase_doors::*;
// The owner's task-type tree doors (DOOR-111) and run doors (DOOR-100),
// likewise.
pub(crate) use super::coordination_doors::*;
// The generic connector call's door (ONE-2510), likewise.
pub(crate) use super::connector_call_doors::*;
pub(crate) use super::connector_pack_doors::*;
// The secret use door, whose connector.call sends (OF-560), likewise.
pub(crate) use super::secret_use_doors::*;
// An agent run's secret grant doors (DOOR-124), likewise.
pub(crate) use super::secret_grant_doors::*;
// The message reaction door (OF-181), likewise.
pub(crate) use super::reaction_doors::*;
pub(crate) use super::reply_doors::*;
pub(crate) use super::result_doors::*;
// The core write doors (OF-181), likewise.
pub(crate) use super::core_write_doors::*;
// The critic review door (OF-352), likewise.
pub(crate) use super::critic_review_doors::*;
// The owner's campaign split evaluation door (FIX 655), likewise.
pub(crate) use super::affect_doors::*;
pub(crate) use super::aging_doors::*;
pub(crate) use super::campaign_split_doors::*;
pub(crate) use super::coach_offer_doors::*;
pub(crate) use super::eval_doors::*;
pub(crate) use super::research_doors::*;
pub(crate) use super::retrieval_doors::*;
pub(crate) use super::hyde_doors::*;
// The owner's project-card tap door (OF-501), likewise.
pub(crate) use super::project_card_doors::*;
// The owner's proposed-claim review and settle doors (DOOR-115), likewise.
pub(crate) use super::claim_settle_doors::*;
pub(crate) use super::consolidation_doors::*;
// The owner's sieve interest-queue, policy and lease doors (DOOR-130), likewise.
pub(crate) use super::sieve_doors::*;
// The owner's standing-block and dreaming-choice doors (DOOR-134), likewise.
pub(crate) use super::standing_doors::*;
// The owner's symbol lease, proposal submit and oplog doors (DOOR-137), likewise.
pub(crate) use super::code_doors::*;
// The owner's per-model code-run heal count door (DOOR-093), likewise.
pub(crate) use super::code_run_doors::*;
// The owner's code consent wait answer and receipt doors (DOOR-079), likewise.
pub(crate) use super::code_wait_doors::*;
// The owner's hook regeneration due, record and adopt doors (DOOR-077), likewise.
pub(crate) use super::hook_regen_doors::*;
pub(crate) use super::host_trigger_doors::*;
// The owner's speculative merge queue doors (DOOR-132), likewise.
pub(crate) use super::merge_queue_doors::*;
// The default lens's door, which holds its card's frame (OF-181), likewise.
pub(crate) use super::lens_selection_doors::*;
pub(crate) use super::ui_action_routes::vault_lenses_default;
// The explain receipts' doors (OF-278), beside their HTTP routes, likewise.
pub(crate) use crate::api::context_board::{vault_explain_gate, vault_explain_memory};

/// `vault.packs.put`: the owner installs a pack folder, or replaces the one
/// installed under its name, under the proof `/v1/owner` takes from the
/// request. The put is the consent for the pack's hooks.
async fn vault_packs_put_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackPutRequest,
) -> MemoryResult<PackPutReceipt> {
    let owner = owner_proof(auth, server, "vault.packs.put")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::put_pack_as_owner(server.vault(), &owner, input)
    })
    .await
    .map_err(|_| internal("vault.packs.put"))?
}

/// [`vault_packs_put_answer`], listing the pack's source row its receipt names, when it installed
/// one (`host_door_lists`).
pub(crate) async fn vault_packs_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackPutRequest,
) -> Listed<PackPutReceipt> {
    naming(vault_packs_put_answer(server, auth, input).await, |put| {
        put.receipt
            .as_deref()
            .and_then(pack_source)
            .into_iter()
            .collect()
    })
}

/// `vault.packs.remove`: the owner removes an installed pack, under the
/// proof `/v1/owner/packs/remove` takes. Answers the removed receipt.
async fn vault_packs_remove_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackRemoveRequest,
) -> MemoryResult<oneiron::skill_hub::pack_catalog::PackInstallReceipt> {
    let owner = owner_proof(auth, server, "vault.packs.remove")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::remove_pack_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.packs.remove"))?
}

/// [`vault_packs_remove_answer`], listing the removed pack's source row (`host_door_lists`).
pub(crate) async fn vault_packs_remove(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackRemoveRequest,
) -> Listed<oneiron::skill_hub::pack_catalog::PackInstallReceipt> {
    naming(
        vault_packs_remove_answer(server, auth, input).await,
        |removed| pack_source(removed).into_iter().collect(),
    )
}

/// `vault.connectors.subscriptions.put`: the owner subscribes an agent to
/// the messages a built-in channel's pack routes to it (OF-519), as
/// `POST /v1/owner/connectors/subscriptions` does.
async fn vault_connectors_subscriptions_put_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionRequest,
) -> MemoryResult<oneiron::connector_key::ChannelMessageSubscription> {
    let owner = owner_proof(auth, server, "vault.connectors.subscriptions.put")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::subscribe_channel_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.connectors.subscriptions.put"))?
}

/// [`vault_connectors_subscriptions_put_answer`], listing the subscription, its connector key and
/// its agent (`host_door_lists`).
pub(crate) async fn vault_connectors_subscriptions_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionRequest,
) -> Listed<oneiron::connector_key::ChannelMessageSubscription> {
    naming(
        vault_connectors_subscriptions_put_answer(server, auth, input).await,
        |subscribed| {
            hex_rows([
                &subscribed.subscription,
                &subscribed.connector_key,
                &subscribed.agent,
            ])
        },
    )
}

/// `vault.connectors.subscriptions.list`: an agent's connector event
/// subscriptions, standing and revoked, for the owner.
async fn vault_connectors_subscriptions_list_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionsRequest,
) -> MemoryResult<ChannelSubscriptions> {
    let owner = owner_proof(auth, server, "vault.connectors.subscriptions.list")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::channel_subscriptions_as_owner(server.vault(), &owner, &input)
    })
    .await
    .map_err(|_| internal("vault.connectors.subscriptions.list"))?
}

/// [`vault_connectors_subscriptions_list_answer`], listing each subscription it shows and its
/// connector key (`host_door_lists`).
pub(crate) async fn vault_connectors_subscriptions_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionsRequest,
) -> Listed<ChannelSubscriptions> {
    naming(
        vault_connectors_subscriptions_list_answer(server, auth, input).await,
        |listed| {
            listed
                .subscriptions
                .iter()
                .flat_map(|row| hex_rows([&row.subscription, &row.connector_key]))
                .collect()
        },
    )
}

/// `vault.connectors.subscriptions.revoke`: the owner stops a subscription;
/// its key stays.
async fn vault_connectors_subscriptions_revoke_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionRevokeRequest,
) -> MemoryResult<ChannelSubscriptionRevoked> {
    let owner = owner_proof(auth, server, "vault.connectors.subscriptions.revoke")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::revoke_channel_subscription_as_owner(
            server.vault(),
            &owner,
            &input,
        )
    })
    .await
    .map_err(|_| internal("vault.connectors.subscriptions.revoke"))?
}

/// [`vault_connectors_subscriptions_revoke_answer`], listing the subscription it stopped
/// (`host_door_lists`).
pub(crate) async fn vault_connectors_subscriptions_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ChannelSubscriptionRevokeRequest,
) -> Listed<ChannelSubscriptionRevoked> {
    naming(
        vault_connectors_subscriptions_revoke_answer(server, auth, input).await,
        |revoked| hex_rows([&revoked.subscription]),
    )
}

/// `vault.artifacts.review_slides`: reviews an artifact's head through the
/// host's decide() ladder as the bound actor, from the host's starting dial
/// and bands, and holds the proposal for Keep or Discard. A unit with no
/// image is rendered by the host's LibreOffice renderer when it has one. The
/// ladder and the render run on a blocking thread, one call per unit.
/// Beside it, the rows its reads listed, the head it renders from and every
/// stored image a unit names.
pub(crate) async fn vault_artifacts_review_slides(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::blob_artifact::SlideReviewSubmit,
) -> Listed<oneiron::blob_artifact::SlideReviewOutcome> {
    const VERB: &str = "vault.artifacts.review_slides";
    let caller = match slide_reviewer(server, auth) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let beside = read_beside(
        std::iter::once(input.artifact_ref.as_str()).chain(
            input
                .units
                .iter()
                .filter_map(|unit| unit.review_image_ref.as_deref()),
        ),
    );
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |server, _, memory| {
            let host = server.decision_host();
            memory.artifacts_review_slides_through(
                &input,
                &crate::decision_artifact::HostUnitDecider::new(server, caller.1, VERB),
                host.dial(oneiron::llm::decision::DecisionRung::Big),
                &host.bands(),
                crate::slide_render::host_renderer().map(|renderer| {
                    renderer as &dyn oneiron::edit_roundtrip::slides_review::SlideRenderer
                }),
            )
        })
        .await;
    listed.extend(beside);
    (answer, listed)
}

/// The principal a slide review binds its proposal to.
fn slide_reviewer(
    server: &SyncServer,
    auth: &CoreAuth,
) -> MemoryResult<(EntityId, EdgeActorClass)> {
    super::facade_actor(server, auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a slide review binds its proposal to an authenticated principal",
            &["Present a slip paired from a link created with --principal-ref."],
        )
    })
}

/// `vault.artifacts.ask`: asks one typed question over an artifact's units
/// (sheet rows, paragraphs or folder items) through the host's decide()
/// ladder as the bound actor, from the host's starting dial and bands, and
/// holds the answers as one proposal for Keep or Discard. The ladder runs on
/// a blocking thread, one call per unit, as `vault.artifacts.review_slides`.
/// Beside it, the rows its reads listed and the artifact it asks over.
pub(crate) async fn vault_artifacts_ask(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::blob_artifact::ArtifactAskSubmit,
) -> Listed<oneiron::blob_artifact::ArtifactAskOutcome> {
    const VERB: &str = "vault.artifacts.ask";
    let caller = match artifact_asker(server, auth) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let beside = read_beside([input.artifact_ref.as_str()]);
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |server, _, memory| {
            let host = server.decision_host();
            memory.artifacts_ask_through(
                &input,
                &crate::decision_artifact::HostUnitDecider::new(server, caller.1, VERB),
                host.dial(oneiron::llm::decision::DecisionRung::Big),
                &host.bands(),
            )
        })
        .await;
    listed.extend(beside);
    (answer, listed)
}

/// The principal an artifact ask binds its proposal to.
fn artifact_asker(
    server: &SyncServer,
    auth: &CoreAuth,
) -> MemoryResult<(EntityId, EdgeActorClass)> {
    super::facade_actor(server, auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "an artifact ask binds its proposal to an authenticated principal",
            &["Present a slip paired from a link created with --principal-ref."],
        )
    })
}

/// `vault.artifacts.body.deck.preview`: the asked slides of a deck's head,
/// drawn by this host's review renderer on a blocking thread, for a
/// credential that reads the artifact. Beside it, the rows its reads listed
/// and the head it draws from.
pub(crate) async fn vault_artifacts_body_deck_preview(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::office_body::DeckPreviewRequest,
) -> Listed<oneiron::office_body::DeckPreview> {
    const VERB: &str = "vault.artifacts.body.deck.preview";
    let admitted = || -> MemoryResult<(EntityId, EdgeActorClass)> {
        let caller = super::facade_actor(server, auth).map_err(|_| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a deck preview reads as the credential's own principal",
                &["Present a slip paired with a principal ref and an actor class."],
            )
        })?;
        if let Ok(artifact) = EntityId::from_hex(&input.artifact_ref)
            && !auth.can_read_entity(&server.vault, &artifact)?
        {
            return Err(oneiron::Error::EntityNotFound.into());
        }
        Ok(caller)
    };
    let caller = match admitted() {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let beside =
        read_beside(std::iter::once(input.artifact_ref.as_str()).chain(input.fork_ref.as_deref()));
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |_, _, memory| {
            memory.artifacts_body_deck_preview(
                &input,
                crate::slide_render::host_renderer().map(|renderer| {
                    renderer as &dyn oneiron::edit_roundtrip::slides_review::SlideRenderer
                }),
            )
        })
        .await;
    listed.extend(beside);
    (answer, listed)
}

/// `vault.authority.audit`: one page of the dated AUTHORITY_LOG audit, the
/// owner's view under the proof `/v1/owner` takes from the request.
async fn vault_authority_audit_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::receipt::AuthorityAuditQuery,
) -> MemoryResult<oneiron::receipt::AuthorityAuditPage> {
    let owner = owner_proof(auth, server, "vault.authority.audit")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        server
            .vault()
            .authority_audit(&owner, &input)
            .map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal("vault.authority.audit"))?
}

/// [`vault_authority_audit_answer`], listing no row: the authority log holds none
/// (`host_door_lists`).
pub(crate) async fn vault_authority_audit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::receipt::AuthorityAuditQuery,
) -> Listed<oneiron::receipt::AuthorityAuditPage> {
    naming(
        vault_authority_audit_answer(server, auth, input).await,
        |_| Vec::new(),
    )
}

/// `vault.mesh.path_receipts`: the newest path receipts this machine's
/// paired-machine mesh left, newest first and bounded, the owner's view
/// under the proof `/v1/owner` takes from the request.
async fn vault_mesh_path_receipts_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::MeshPathReceiptsRequest,
) -> MemoryResult<Vec<oneiron::sync::mesh_path::MeshPathReceipt>> {
    let _owner = owner_proof(auth, server, "vault.mesh.path_receipts")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        server
            .vault()
            .mesh_path_receipts(input.bound())
            .map_err(MemoryError::from)
    })
    .await
    .map_err(|_| internal("vault.mesh.path_receipts"))?
}

/// [`vault_mesh_path_receipts_answer`], listing no row: path receipts live in a side table
/// (`host_door_lists`).
pub(crate) async fn vault_mesh_path_receipts(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::MeshPathReceiptsRequest,
) -> Listed<Vec<oneiron::sync::mesh_path::MeshPathReceipt>> {
    naming(
        vault_mesh_path_receipts_answer(server, auth, input).await,
        |_| Vec::new(),
    )
}

/// `ai.options`: the rows the credential could call now, where each runs,
/// what it takes, its price, the rates its native counts settle at, and
/// what its meter has left (FIX 2942).
///
/// Its answer is the host runtime's seats, rates and meters, each row
/// filtered by the vault's inference-policy admission and priced from the
/// model registry, none of which is a record, or from the installed model
/// catalog pack when the registry holds no row for the model: that pack's
/// source is the one row it lists. A caller shown no option lists none; a
/// catalog that cannot be read leaves the answer unlisted.
pub(crate) async fn ai_options(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiOptionsRequest,
) -> (MemoryResult<AiOptions>, Option<Vec<EntityId>>) {
    let answer = ai_options_answer(server, auth, &input);
    let listed = match &answer {
        Ok(options) if !options.options.is_empty() => server
            .vault
            .model_catalog_source()
            .ok()
            .map(|source| source.into_iter().collect()),
        _ => Some(Vec::new()),
    };
    (answer, listed)
}

fn ai_options_answer(
    server: &SyncServer,
    auth: &CoreAuth,
    input: &AiOptionsRequest,
) -> MemoryResult<AiOptions> {
    let operation = input
        .operation
        .as_deref()
        .map(|name| {
            AiOperation::parse(name).ok_or_else(|| {
                MemoryError::bad_request(
                    "operation is one of text, image, video, speech, transcribe, embed",
                )
            })
        })
        .transpose()?;
    let mut inputs = BTreeSet::new();
    for name in &input.inputs {
        let modality =
            serde_json::from_value::<Modality>(serde_json::Value::String(name.trim().to_owned()))
                .map_err(|_| {
                MemoryError::bad_request("inputs are text, image, audio, video or embedding")
            })?;
        inputs.insert(modality);
    }
    let listed = caller_options(server, auth.is_owner_grade(), operation, &inputs);
    let options = listed
        .options
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()
        .map_err(|_| internal("ai.options"))?;
    Ok(AiOptions {
        options,
        media_units_left: listed.media_units_left,
    })
}

/// One owner's media call's answer, from its seat's ladder, on the media
/// meter. Only an owner-grade credential reaches it: the facade's, or an
/// MCP `execute_code` run's, whose calls spend under no scope. No room pays
/// for it, so it bills the vault owner (FIX 805).
async fn answered(
    server: &SyncServer,
    auth: &CoreAuth,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    let (request, voices) = admit(server, auth, operation, input)?;
    rendered(server, operation, request, voices, None).await
}

/// `ai.speech` for a pumped agent run (FIX 3194): prepared as the owner's
/// call is, and spent on `run`, the run's own line, as its other model calls
/// are. The run's door admitted it; no owner credential stands behind it.
pub(crate) async fn ai_speech_for_run(
    server: &SyncServer,
    run: &RunAdmission,
    input: AiCallRequest,
) -> MemoryResult<AiAnswer> {
    let (request, voices) = prepare(server, AiOperation::Speech, input)?;
    rendered(server, AiOperation::Speech, request, voices, Some(run)).await
}

/// One media call's answer, from its seat's ladder: on `run` when its caller
/// admitted it on a line of its own, which bills that run's payer, else on
/// the media meter as the owner's call ([`answered`]). A banked voice
/// withdrawn or re-recorded while it rendered, on the rung that answered, is
/// not handed back; nor is a call that found the voice withdrawn everywhere
/// while it waited (FIX 1746).
async fn rendered(
    server: &SyncServer,
    operation: AiOperation,
    request: MediaRequest,
    voices: Option<RungVoices>,
    run: Option<&RunAdmission>,
) -> MemoryResult<AiAnswer> {
    let media = server.ai.model_runtime().media();
    let hint = media.retry_hint(&request, voices.as_ref());
    let answer = match (run, &voices) {
        (Some(run), voices) => media.run_admitted(run, request, voices.as_ref()).await,
        (None, Some(voices)) => media.run_voiced(request, voices, None).await,
        (None, None) => media.run(request, None).await,
    };
    let withdrawn = || {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the voice was withdrawn or its clone replaced while it rendered",
            &["Provision the voice again, then repeat the call."],
        )
    };
    match answer {
        Ok(_)
            if voices
                .as_ref()
                .is_some_and(|voices| !voices.answered_current()) =>
        {
            Err(withdrawn())
        }
        Err(_) if voices.as_ref().is_some_and(RungVoices::withdrawn) => Err(withdrawn()),
        Ok(response) => Ok(response.into()),
        Err(error) if error.is_provider_unavailable() => {
            Err(unavailable(operation, &error, hint.seconds()))
        }
        Err(error @ LlmError::BudgetDenied(_)) if run.is_some() => {
            let mut refusal = failure(operation, &error);
            refusal.suggestions = vec![RUN_LINE_SPENT.to_owned()];
            Err(refusal)
        }
        Err(error) => Err(failure(operation, &error)),
    }
}

/// What a run's media call refused for its spent line suggests: it spends
/// the run's own line, not the media meter.
const RUN_LINE_SPENT: &str = "The run's spend line is spent.";

/// A media call no offer answered (FIX 3194): `MODEL_UNAVAILABLE`, with the
/// seconds until the first offer that could serve it is back as
/// `retry_after` and in its suggestion. Nothing keeps the call; its caller
/// sends it again.
fn unavailable(operation: AiOperation, error: &LlmError, retry_after: u64) -> MemoryError {
    let mut refusal = failure(operation, error);
    refusal.suggestions = vec![format!(
        "Retry in {retry_after} s, or name another row ai.options lists."
    )];
    refusal.retry_after = Some(retry_after);
    refusal
}

/// `ai.image`: one image out; reference images make it an edit. Beside it,
/// no row: its parts come inline and its model from the seat's ladder, and
/// the inference policy only admits it.
pub(crate) async fn ai_image(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> Listed<AiAnswer> {
    record_free(answered(server, auth, AiOperation::Image, input).await)
}

/// `ai.speech`: speech audio out of text, in the voice the call names.
/// Beside it, for a banked voice, the person whose voice it renders: the
/// owner of the voice's identity. The bank's packs, clips, targets and
/// render consent are side tables. A stock voice lists no row, as
/// [`ai_image`] lists none; `None` when the identity cannot be read again.
pub(crate) async fn ai_speech(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> MaybeListed<AiAnswer> {
    let banked = match &input.voice {
        Some(AiVoice::Bank { voice_id, .. }) => Some(voice_id.clone()),
        Some(AiVoice::Stock { .. }) | None => None,
    };
    let answer = answered(server, auth, AiOperation::Speech, input).await;
    let rows = match (&answer, banked) {
        (Ok(_), Some(voice_id)) => voice_owner(server, &voice_id),
        _ => Some(Vec::new()),
    };
    (answer, rows)
}

/// The person a banked voice is: its identity's owner, `None` when the
/// identity cannot be read.
fn voice_owner(server: &SyncServer, voice_id: &str) -> Option<Vec<EntityId>> {
    server
        .vault
        .voice_identity(voice_id)
        .ok()
        .flatten()
        .map(|identity| vec![identity.owner])
}

/// `ai.transcribe`: text out of speech audio. Beside it, no row, as
/// [`ai_image`] lists none.
pub(crate) async fn ai_transcribe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> Listed<AiAnswer> {
    record_free(answered(server, auth, AiOperation::Transcribe, input).await)
}

/// `ai.embed`: one vector per input text. Beside it, no row, as
/// [`ai_image`] lists none.
pub(crate) async fn ai_embed(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> Listed<AiAnswer> {
    record_free(answered(server, auth, AiOperation::Embed, input).await)
}

/// A media door's answer, which no row derives: beside it, an empty list.
fn record_free<T>(answer: MemoryResult<T>) -> Listed<T> {
    (answer, Vec::new())
}

/// `ai.video`: the clip renders as a provider job; the answer is its ticket.
/// It is the owner's call, as [`answered`]'s is, so its job bills the vault
/// owner, and so does each later take-up of it. Beside it, no row: its job
/// lives at its provider and in the media runtime.
pub(crate) async fn ai_video(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> Listed<AiVideoTicket> {
    record_free(ai_video_answer(server, auth, input).await)
}

async fn ai_video_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiCallRequest,
) -> MemoryResult<AiVideoTicket> {
    let (request, _) = admit(server, auth, AiOperation::Video, input)?;
    let ticket = server
        .ai
        .model_runtime()
        .media()
        .submit(request, None)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(AiVideoTicket {
        job: ticket.job,
        model: ticket.model,
        operation: ticket.operation,
    })
}

/// `ai.video.poll`: where a video job stands; a finished one answers with
/// its clip on every poll until `ai.video.cancel` deletes it. Beside it, no
/// row, as [`ai_video`] lists none.
pub(crate) async fn ai_video_poll(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVideoJobRequest,
) -> Listed<AiVideoJob> {
    record_free(ai_video_poll_answer(server, auth, input).await)
}

async fn ai_video_poll_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVideoJobRequest,
) -> MemoryResult<AiVideoJob> {
    owner_grade(auth, VIDEO_JOB_OWNERS)?;
    let state = server
        .ai
        .model_runtime()
        .media()
        .poll(&input.job)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(state.into())
}

/// `ai.video.cancel`: stops a video job at its provider. Beside it, no
/// row, as [`ai_video`] lists none.
pub(crate) async fn ai_video_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVideoJobRequest,
) -> Listed<AiVideoCancelled> {
    record_free(ai_video_cancel_answer(server, auth, input).await)
}

async fn ai_video_cancel_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVideoJobRequest,
) -> MemoryResult<AiVideoCancelled> {
    owner_grade(auth, VIDEO_JOB_OWNERS)?;
    server
        .ai
        .model_runtime()
        .media()
        .cancel(&input.job)
        .await
        .map_err(|error| failure(AiOperation::Video, &error))?;
    Ok(AiVideoCancelled { job: input.job })
}

/// `self.memory.diary.query`: the caller reads an agent's diary, stating a
/// reason the agent sees in its read log (`Memory::read_agent_diary`). The
/// caller's `diary.read` Grants decide what it gets. A person reads with
/// their authentication: the vault owner's own credential carries the proof
/// `/v1/owner` takes from the request, and any other verified human carries
/// their own person proof ([`super::shared_act_doors::person`], OF-490), so
/// their own Grant decides. Any other caller passes none and the engine door
/// decides: an agent or system reads as itself, and a person without a proof
/// is refused. Beside it, the rows its reads listed.
pub(crate) async fn self_memory_diary_query(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::DiaryQueryRequest,
) -> Listed<oneiron::task_verb::sdk::DiaryQueryOutcome> {
    const VERB: &str = "self.memory.diary.query";
    let caller = match diary_reader(server, auth) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |server, auth, memory| {
        let proof = super::shared_act_doors::person(server, auth, VERB).ok();
        oneiron::task_verb::sdk::diary_query_as(&memory, proof.as_ref(), input)
    })
    .await
}

/// The principal a diary query reads as.
fn diary_reader(server: &SyncServer, auth: &CoreAuth) -> MemoryResult<(EntityId, EdgeActorClass)> {
    super::facade_actor(server, auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "self.memory.diary.query reads as the credential's own principal",
            &["Present a slip paired with a principal ref and an actor class."],
        )
    })
}

/// `ai.verdict`: the caller's own typed question through the host's
/// decision ladder, asked for the caller: the slip's principal, or the
/// vault's own owner for an owner-grade credential that names none. Its
/// evidence is read under the caller's own scoped read
/// ([`crate::decision_verdict::run_verdict`]); a screenshot the calling
/// code run's browser holds comes from that browser. Beside it, the rows its
/// evidence reads listed and the asset an image it pulls is read from: the
/// image's lane is a scoped read of its own, which lists nothing itself.
pub(crate) async fn ai_verdict(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVerdictRequest,
) -> Listed<AiVerdict> {
    const VERB: &str = "ai.verdict";
    let caller = match asking(auth, server) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let held = crate::decision_verdict::HeldImage::in_task(input.image.as_deref());
    // A held screenshot is the run's browser's pixels, no row's.
    let beside = match (&input.image, &held) {
        (Some(handle), None) => read_beside([handle.as_str()]),
        _ => Vec::new(),
    };
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |server, auth, reader| {
            // An image is pulled through the caller's own lane before any model
            // reads it, unless it is the run's own held screenshot.
            let lane = match (&input.image, &held) {
                (Some(_), None) => Some(
                    crate::api::scoped_read_for_core_auth(&server.vault, auth).map_err(|_| {
                        MemoryError::new(
                            MEMORY_CODE_FORBIDDEN,
                            "ai.verdict reads an image under the caller's scoped read",
                            &["Present a credential that can read the image."],
                        )
                    })?,
                ),
                _ => None,
            };
            crate::decision_verdict::run_verdict(
                server,
                caller.0,
                caller.1,
                &reader,
                lane.as_ref(),
                held,
                &input,
                // A facade caller's verdict bills the vault owner.
                None,
            )
        })
        .await;
    listed.extend(beside);
    (answer, listed)
}

/// `vault.hooks.replay`: the owner replays a hook over past facts or its
/// saved verb runs, under the proof `/v1/owner` takes from the request, on
/// the hook sandbox serve runs its hooks on. A dry run: nothing lands. A fact
/// no run pinned previews a generative hook's verdicts on serve's own ladder.
/// Beside it, the binding, its body's source, each entry's fact and every
/// row a replayed read served ([`oneiron::Vault::hooks_replay_listing`]);
/// `None` once an entry asked a verdict, whose evidence it does not list.
pub(crate) async fn vault_hooks_replay(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HooksReplayRequest,
) -> MaybeListed<Vec<HookReplayRow>> {
    match vault_hooks_replay_answer(server, auth, input).await {
        Ok((replayed, rows)) => (Ok(replayed), rows),
        Err(refusal) => (Err(refusal), Some(Vec::new())),
    }
}

/// [`vault_hooks_replay`]'s answer, beside its listing.
async fn vault_hooks_replay_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HooksReplayRequest,
) -> MemoryResult<(Vec<HookReplayRow>, Option<Vec<EntityId>>)> {
    let owner = owner_proof(auth, server, "vault.hooks.replay")?;
    let Some(runtime) = server.hook_runtime.get().cloned() else {
        return Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "no hook sandbox runs on this server",
            &["Serve with fact hooks on (no --no-hooks), on a build with the code sandbox."],
        ));
    };
    let verdict = replay_verdict(server);
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        oneiron::task_verb::sdk::replay_hooks_as_owner_listing(
            server.vault(),
            &owner,
            runtime.as_ref(),
            verdict,
            &input,
        )
    })
    .await
    .map_err(|_| internal("vault.hooks.replay"))?
}

/// The verdict host a replay's preview asks: the one the fact-hook runner
/// asks.
#[cfg(feature = "code-sandbox-wasmtime")]
fn replay_verdict(server: &Arc<SyncServer>) -> Option<Arc<dyn HookVerdict>> {
    Some(Arc::new(crate::hook_verdict::ServerHookVerdict::new(
        server,
    )))
}

/// No hook sandbox runs on this build, so no replay reaches a verdict.
#[cfg(not(feature = "code-sandbox-wasmtime"))]
fn replay_verdict(_server: &Arc<SyncServer>) -> Option<Arc<dyn HookVerdict>> {
    None
}

/// Whom a host-door question is asked for: the slip's principal, or the
/// owner a self-hosted root or the dev mode acts as, as a chat turn's writer
/// is; a hosted operator's root asks for no one (FIX 2222).
fn asking(auth: &CoreAuth, server: &SyncServer) -> MemoryResult<(EntityId, EdgeActorClass)> {
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "ai.verdict is asked for an authenticated principal",
            &["Present a slip that names its principal, or the owner's own credential."],
        )
    };
    if let Some(action) = crate::api::host_action::host_action_of(server.vault(), auth) {
        let actor = action.map_err(MemoryError::from)?.actor();
        return Ok((actor.entity_ref(), actor.actor_class()));
    }
    let actor = match auth.principal_ref() {
        Some(reference) => EntityId::from_hex(reference).map_err(|_| refused())?,
        None => return Err(refused()),
    };
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    Ok((actor, class))
}

/// The refusal of an `ai.*` media call from a credential short of the owner's.
const MEDIA_OWNERS: &str = "ai.* media calls are the owner's";
/// The refusal of a video job's poll or cancel from one short of it.
const VIDEO_JOB_OWNERS: &str = "video jobs are the owner's";

fn owner_grade(auth: &CoreAuth, message: &str) -> MemoryResult<()> {
    if auth.is_owner_grade() {
        return Ok(());
    }
    Err(MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        message,
        &["Present a verified, unattenuated owner credential."],
    ))
}

/// The authority check host-door row `verb`'s own door runs first: the
/// owner's proof, a person's proof, a bound principal or an owner-grade
/// credential. The facade runs it before the row's pre chain, so a hook
/// never fires on a call the door refuses; the door runs it again for the
/// proof it acts under. A row whose door has no such check passes.
pub(super) fn door_admits(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
    match verb {
        "vault.booking.constraint_turn"
        | "vault.booking.availability"
        | "vault.booking.book"
        | "vault.booking.reschedule"
        | "vault.booking.cancel" => crate::api::host_action::require_host_owner_act(server, auth)
            .map(drop)
            .map_err(|error| super::FacadeApiError::from(error).into_memory_error()),
        "ai.steps.submit"
        | "ai.steps.receipt"
        | "vault.runs.step"
        | "vault.runs.checkpoint"
        | "vault.runs.review"
        | "vault.runs.settle"
        | "vault.runs.settlement"
        | "vault.revert_run"
        | "ai.reply"
        | "calendar.ics.configure"
        | "calendar.ics.poll"
        | "calendar.ics.status"
        | "calendar.connector.configure"
        | "calendar.connector.get"
        | "calendar.connector.kill"
        | "calendar.connector.pull"
        | "calendar.connector.write"
        | "calendar.imip.configure"
        | "calendar.imip.get"
        | "vault.calendar.ics.import"
        | "vault.calendar.instances.move"
        | "vault.campaign.compliance.install"
        | "vault.campaign.compliance.approve"
        | "vault.campaign.compliance.reject"
        | "vault.campaign.compliance.verify"
        | "vault.companions.access_requests.answer"
        | "vault.personas.preview"
        | "vault.personas.export"
        | "vault.personas.edit"
        | "vault.packs.put"
        | "vault.packs.connector.prepare"
        | "vault.packs.connector.get"
        | "vault.packs.connector.qualify"
        | "vault.packs.connector.accept"
        | "vault.packs.connector.update"
        | "vault.packs.connector.grants.get"
        | "vault.packs.connector.grants.put"
        | "vault.packs.remove"
        | "vault.skill_hubs.put"
        | "vault.skill_hubs.get"
        | "vault.skill_hubs.publishers.admit"
        | "vault.skill_hubs.publishers.revoke"
        | "vault.skill_hubs.refs.get"
        | "vault.skill_hubs.refs.set"
        | "vault.packs.install"
        | "vault.packs.sync"
        | "vault.packs.get"
        | "vault.skills.import"
        | "vault.skills.sync"
        | "vault.skills.receipts"
        | "vault.skills.convert"
        | "vault.skills.get"
        | "vault.skills.list"
        | "vault.skills.archive"
        | "vault.skills.restore"
        | "vault.skills.fork"
        | "vault.skills.rules.set"
        | "vault.skills.code_auto_install.set"
        | "vault.skills.permissions.approve"
        | "vault.skills.optimize.start"
        | "vault.skills.optimize.result"
        | "vault.projects.goal.intake.complete"
        | "vault.projects.goal.get"
        | "vault.skills.optimize.propose"
        | "vault.skills.optimize.measure"
        | "vault.skills.optimize.score"
        | "vault.skills.optimize.admit"
        | "vault.skills.optimize.goal.get"
        | "vault.skills.optimize.goal.bind"
        | "vault.skills.optimize.preferences.get"
        | "vault.skills.optimize.preferences.set"
        | "vault.skills.optimize.tradeoff_asks"
        | "vault.skills.optimize.tradeoff_asks.pick"
        | "vault.skills.governance.get"
        | "vault.skills.governance.set"
        | "vault.skills.pack_receipt"
        | "vault.skills.outcomes.project"
        | "vault.skills.outcomes.get"
        | "vault.packs.hooks.bind"
        | "vault.packs.hooks.list"
        | "vault.packs.hooks.grant.set"
        | "vault.packs.hooks.grant.get"
        | "vault.packs.hooks.qualify"
        | "vault.connectors.subscriptions.put"
        | "vault.connectors.subscriptions.list"
        | "vault.connectors.subscriptions.revoke"
        | "vault.authority.audit"
        | "vault.authority.history.export"
        | "vault.authority.history.import"
        | "vault.mesh.path_receipts"
        | "host.compact"
        | "host.wake"
        | "host.budget.hit"
        | "vault.hooks.replay"
        | "vault.hooks.regen.due"
        | "vault.hooks.regen.get"
        | "vault.hooks.regen.adopt"
        | "vault.lenses.activate"
        | "vault.lenses.deactivate"
        | "vault.packs.setup.prepare"
        | "vault.packs.setup.get"
        | "vault.packs.setup.answer"
        | "vault.packs.setup.verify"
        | "vault.authority.handoff_alarms"
        | "vault.authority.handoff_alarms.acknowledge"
        | "vault.records.erase_sweep"
        | "vault.cleanup.run"
        | "vault.entities.mention"
        | "vault.legal_holds.place"
        | "vault.legal_holds.widen"
        | "vault.legal_holds.list"
        | "vault.legal_holds.log"
        | "vault.legal_holds.lift_and_erase"
        | "vault.residence.mode"
        | "vault.residence.open"
        | "vault.residence.index"
        | "vault.residence.prune"
        | "vault.residence.directives"
        | "vault.courtesy_delete.send"
        | "vault.courtesy_delete.sent"
        | "vault.courtesy_delete.incoming"
        | "vault.courtesy_delete.answer"
        | "vault.decisions.bands.read"
        | "vault.decisions.bands.learn"
        | "vault.decisions.bands.enforce"
        | "vault.retrieval.aging.get"
        | "vault.retrieval.aging.configure"
        | "vault.retrieval.weights.get"
        | "vault.retrieval.weights.configure"
        | "vault.retrieval.hyde.configure"
        | "vault.retrieval.hyde.get"
        | "vault.affect.claims.consolidate"
        | "vault.affect.coping.record"
        | "vault.affect.coping.update"
        | "vault.affect.coping.aggregate"
        | "vault.affect.wellness.policy.get"
        | "vault.affect.wellness.policy.configure"
        | "vault.affect.wellness.derive"
        | "vault.affect.wellness.get"
        | "vault.slim.policy"
        | "vault.slim.state"
        | "vault.slim.resume_step"
        | "vault.slim.drop_heavy"
        | "vault.slim.resume"
        | "vault.retrieval.recall"
        | "vault.retrieval.runs"
        | "vault.retrieval.run"
        | "vault.retrieval.turn"
        | "vault.retrieval.outcomes.put"
        | "vault.retrieval.outcomes.end"
        | "vault.retrieval.trace"
        | "vault.retrieval.export"
        | "vault.retrieval.replay"
        | "vault.learning.read"
        | "vault.learning.projection"
        | "vault.seal.confess"
        | "vault.seal.audit"
        | "vault.seal.receipt"
        | "vault.seal.pending"
        | "vault.seal.run"
        | "vault.seal.complete"
        | "vault.settings.learning"
        | "vault.settings.learning.put"
        | "vault.settings.learning.clear"
        | "vault.widen_proposals"
        | "vault.widen_proposals.approve"
        | "vault.widen_proposals.decline"
        | "vault.craft_candidates"
        | "vault.craft_candidates.answer"
        | "vault.memory.signal_extraction"
        | "vault.memory.signal_extraction.result"
        | "feedback.preview"
        | "feedback.send"
        | "vault.reports.disclosure"
        | "vault.reports.route"
        | "vault.reports.outbound"
        | "vault.claims.review"
        | "vault.claims.settle"
        | "vault.claims.vet"
        | "vault.claims.vetting"
        | "vault.consolidation.promote"
        | "vault.consolidation.evidence"
        | "vault.sieve.evidence"
        | "vault.sieve.evidence.replay"
        | "vault.sieve.cadence"
        | "vault.sieve.settlements"
        | "vault.sieve.settlements.get"
        | "vault.sieve.queue"
        | "vault.sieve.retained"
        | "vault.sieve.receipts"
        | "vault.sieve.policy"
        | "vault.sieve.policy.set"
        | "vault.sieve.recipe_policy"
        | "vault.sieve.recipe_policy.set"
        | "vault.sieve.lease"
        | "vault.sieve.lease.refill"
        | "vault.settings.wake_policy.set"
        | "vault.agents.create"
        | "vault.agents.update"
        | "vault.agents.get"
        | "vault.agents.dreaming.get"
        | "vault.agents.dreaming.set"
        | "vault.standing_blocks.configure"
        | "vault.standing_blocks.reconfigure"
        | "vault.standing_blocks.get"
        | "vault.standing_blocks.list"
        | "vault.workflows.save"
        | "vault.workflows.update"
        | "vault.workflows.get"
        | "vault.workflows.dispatch"
        | "vault.workflows.status"
        | "vault.task_types.pin"
        | "vault.task_types.get"
        | "vault.agents.spawn.get"
        | "vault.agents.spawn"
        | "vault.tasks.cancel_force"
        | "vault.runs.branches.get"
        | "vault.consults.get"
        | "vault.workspace.roster"
        | "vault.booking.page_token"
        | "vault.channel_identities.provision"
        | "vault.channel_identities.bind"
        | "vault.channel_identities.fulfill"
        | "vault.channel_identities.rotate"
        | "vault.channel_identities.release"
        | "vault.channel_identities.route_inbound"
        | "vault.delivery_window.policy.put"
        | "vault.delivery_window.policy.retract"
        | "vault.policy.owner.get"
        | "vault.policy.owner.configure"
        | "vault.policy.owner.row.change"
        | "vault.consent.approve_once"
        | "vault.consent.deny"
        | "vault.consent.create_standing_grant"
        | "vault.consent.registry"
        | "vault.consent.revoke"
        | "vault.consent.graduation.policy"
        | "vault.consent.graduation.policy.set"
        | "vault.consent.graduation.policy.clear"
        | "vault.consent.graduation.stats"
        | "vault.consent.graduation.outcome"
        | "vault.consent.graduation.offers"
        | "vault.consent.graduation.answer"
        | "vault.consent.graduation.trust_table"
        | "vault.consent.graduation.settings.unpin"
        | "vault.consent.graduation.demote"
        | "vault.gate.policy.get"
        | "vault.gate.policy.put"
        | "vault.gate.checker.get"
        | "vault.gate.checker.set"
        | "vault.embedding_spaces.list"
        | "vault.embedding_spaces.declare"
        | "vault.embedding_spaces.bind"
        | "vault.embedding_spaces.one_space"
        | "vault.embedding_spaces.retire"
        | "vault.embedding_spaces.move"
        | "vault.embedding_spaces.move_check"
        | "vault.embedding_spaces.move_approve"
        | "vault.embedding_spaces.move_undo"
        | "vault.embedding_spaces.move_abandon"
        | "vault.embedding_spaces.probes.list"
        | "vault.embedding_spaces.probes.put"
        | "vault.embedding_spaces.probes.delete"
        | "vault.fanout.resume"
        | "vault.fanout.ack"
        | "vault.federation.coreference.link"
        | "vault.federation.coreference.confirm"
        | "vault.federation.coreference.share_consent"
        | "vault.federation.coreference.unlink"
        | "vault.federation.connect.identity"
        | "vault.federation.connect.grants.mint"
        | "vault.federation.connect.offer"
        | "vault.federation.connect.accept"
        | "vault.federation.connect.narrow"
        | "vault.federation.connect.rescope.offer"
        | "vault.federation.connect.rescope.accept"
        | "vault.federation.connect.disconnect"
        | "vault.federation.connect.export"
        | "vault.federation.connect.rejoin"
        | "vault.guests.share"
        | "vault.guests.reshare"
        | "vault.guests.revoke"
        | "vault.guests.mint_slip"
        | "vault.support_grants.mint"
        | "vault.support_grants.list"
        | "vault.support_grants.revoke"
        | "vault.projects.confirm"
        | "vault.weave.owner.link.wrong"
        | "vault.weave.owner.item.wrong"
        | "vault.weave.enqueue"
        | "vault.weave.schedules.list"
        | "vault.weave.schedules.put"
        | "vault.weave.schedules.clear"
        | "vault.weave.owner.digest.render"
        | "vault.inbox.concerns.review"
        | "vault.inbox.lens"
        | "vault.inbox.groups"
        | "vault.budgets.lease.open"
        | "vault.budgets.lease"
        | "vault.budgets.lease.top_up"
        | "vault.budgets.hold"
        | "vault.budgets.hold.resume"
        | "vault.budgets.local"
        | "vault.budgets.settlements"
        | "vault.research.evaluate_split"
        | "vault.research.create_child"
        | "vault.evals.inventory"
        | "vault.evals.cohorts.setup"
        | "vault.evals.author_now"
        | "vault.evals.authoring.result"
        | "vault.evals.families"
        | "vault.evals.families.assign"
        | "vault.evals.cases"
        | "vault.evals.cases.record"
        | "vault.evals.cohorts"
        | "vault.evals.cohorts.open"
        | "vault.evals.exposure"
        | "vault.evals.sufficiency"
        | "vault.evals.labels.blocked"
        | "vault.evals.labels.pick"
        | "vault.coach.training_offers"
        | "vault.coach.training_offers.get"
        | "vault.coach.training_offers.trigger"
        | "vault.coach.training_offers.result"
        | "vault.coach.training_offers.answer"
        | "vault.coach.training_offers.undo"
        | "vault.coach.training_offers.candidates"
        | "vault.coach.training_offers.candidates.prepare"
        | "vault.coach.training_offers.pilots.prepare"
        | "vault.coach.training_offers.pilots.complete"
        | "vault.coach.training_offers.pilots.get"
        | "vault.code.symbols.declare"
        | "vault.code.symbols.renew"
        | "vault.code.symbols.release"
        | "vault.code.proposal_submit"
        | "vault.code.conflict_record"
        | "vault.code.conflict_view"
        | "vault.code.proposal_resolve"
        | "vault.code.proposal_review"
        | "vault.code.proposal_settle"
        | "vault.code.proposal_settlement"
        | "vault.code.oplog"
        | "vault.results.status"
        | "vault.results.recover"
        | "vault.results.read"
        | "vault.results.slice"
        | "vault.code.model_heal_count"
        | "vault.code.waits.resolve"
        | "vault.code.waits.receipt"
        | "vault.code.export"
        | "vault.code.origin.authority.get"
        | "vault.code.origin.authority.set"
        | "vault.code.origin.publications"
        | "vault.code.checkout.bind"
        | "vault.artifacts.publish_approval"
        | "vault.artifacts.publish"
        | "vault.artifacts.repoint"
        | "vault.artifacts.pointer"
        | "vault.artifacts.unpublish"
        | "vault.artifacts.link_token"
        | "vault.artifacts.live_preview.register"
        | "vault.artifacts.live_preview.close"
        | "vault.artifacts.live_preview.invite"
        | "vault.artifacts.live_preview.revoke_invite"
        | "vault.artifacts.live_preview.share"
        | "vault.artifacts.live_preview.revoke_share"
        | "vault.code.snapshots.ingest"
        | "vault.code.snapshots.get"
        | "vault.code.snapshots.read"
        | "vault.code.symbols.definitions"
        | "vault.code.merge_queue.enqueue"
        | "vault.code.merge_queue.stage"
        | "vault.code.merge_queue.observe"
        | "vault.code.merge_queue.requeue_survivors"
        | "vault.code.merge_queue.land_reviewed"
        | "vault.code.merge_queue.settle_slow"
        | "vault.code.merge_queue.recover"
        | "vault.trusted_contacts.name"
        | "vault.trusted_contacts.dial.set"
        | "vault.trusted_contacts.tier.set"
        | "vault.trusted_contacts.concern.asks"
        | "vault.trusted_contacts.concern.authorize"
        | "vault.trusted_contacts.concern.propose"
        | "vault.shared.policy.get"
        | "vault.shared.policy.change"
        | "vault.notes.history_purge"
        | "vault.notes.history_purge_execute"
        | "vault.notes.history_purge_receipts"
        | "vault.voices.packs.put"
        | "vault.voices.render_consent"
        | "vault.voices.targets.provision"
        | "vault.voices.targets.evict"
        | "vault.voices.inspect"
        | "ai.voice.asr.open"
        | "ai.voice.asr.hypothesis"
        | "ai.voice.asr.finalize"
        | "ai.voice.asr.close"
        | "ai.voice.start"
        | "ai.voice.audio"
        | "ai.voice.events"
        | "ai.voice.ack"
        | "ai.voice.usage"
        | "ai.voice.tool"
        | "ai.voice.end"
        | "ai.voice.close" => owner_proof(auth, server, verb).map(drop),
        "vault.shared.propose_delete"
        | "vault.shared.propose_transfer"
        | "vault.shared.propose_remove_owner"
        | "vault.shared.execute"
        | "vault.shared.receipt"
        | "vault.shared.outcomes"
        | "vault.members.add"
        | "vault.members.change"
        | "vault.members.remove"
        | "vault.members.leave"
        | "vault.members.invitations"
        | "vault.members.accept"
        | "vault.members.decline"
        | "vault.members.withdraw_invitation"
        | "vault.members.invitation_slip"
        | "vault.shared.object"
        | "vault.shared.withdraw_objection"
        | "vault.shared.started"
        | "vault.shared.matured"
        | "vault.shared.erase_ask"
        | "vault.shared.erase_asks"
        | "vault.shared.close_erase_ask"
        | "vault.records.erase_preview"
        | "vault.records.erase_confirm"
        | "vault.workspace.establish"
        | "vault.workspace.members.onboard"
        | "vault.trusted_contacts.list"
        | "vault.trusted_contacts.consent"
        | "vault.trusted_contacts.revoke"
        | "vault.shared.policy.propose"
        | "vault.shared.policy.answer" => {
            super::shared_act_doors::person(server, auth, verb).map(drop)
        }
        // The off-record session rows admit their session's manager: the
        // owner, or a person or agent who starts and keeps their own
        // (WILL-PLAN L13 row 03). Each door binds the stretch for them again.
        "vault.off_record.start"
        | "vault.off_record.status"
        | "vault.off_record.witness"
        | "vault.off_record.discard"
        | "vault.off_record.recall"
        | "vault.off_record.notes.create"
        | "vault.off_record.claims.upsert"
        | "self.off_record.execute" => {
            super::off_record_doors::off_record_admits(server, auth, verb)
        }
        "vault.guests.export_envelope" => {
            super::guest_document_doors::guest_document_reader(server, auth).map(drop)
        }
        "execute_code" => super::foreign_code_doors::foreign_code_admits(server, auth),
        "self.credential.attenuate" => super::credential_doors::holder(auth).map(drop),
        "vault.artifacts.review_slides" => slide_reviewer(server, auth).map(drop),
        "vault.artifacts.ask" => artifact_asker(server, auth).map(drop),
        "self.memory.diary.query" => diary_reader(server, auth).map(drop),
        "vault.decisions.asks.answer"
        | "vault.decisions.asks.climb"
        | "self.decisions.asks"
        | "vault.fanout.resume_as" => super::decision_ask_doors::holder(auth, verb).map(drop),
        "vault.retrieval.hyde.pending"
        | "vault.retrieval.hyde.complete"
        | "vault.retrieval.hyde.receipt" => super::hyde_doors::hyde_caller(server, auth).map(drop),
        "fetch" | "crawl" => super::facade_actor(server, auth)
            .map(drop)
            .map_err(super::FacadeApiError::into_memory_error),
        "ai.verdict" => asking(auth, server).map(drop),
        "ai.image" | "ai.speech" | "ai.transcribe" | "ai.embed" | "ai.video" => {
            owner_grade(auth, MEDIA_OWNERS)
        }
        "ai.video.poll" | "ai.video.cancel" => owner_grade(auth, VIDEO_JOB_OWNERS),
        _ => Ok(()),
    }
}

pub(super) fn internal(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        format!("{verb} did not finish on this server"),
        &["Report this SDK host-door failure."],
    )
}

/// A listing host door's answer (`host_door_lists`), beside the rows its
/// reads derived it from, as a plain row's answer lists them (DEC-0005):
/// the rows its caller or its answer names by ref aside. A refusal keeps
/// its typed error, with the rows read before it.
pub(crate) type Listed<T> = (MemoryResult<T>, Vec<EntityId>);

/// [`Listed`] for a door one of whose paths lists none: `None` beside that
/// path's answer ([`ListedRows`]).
pub(crate) type MaybeListed<T> = (MemoryResult<T>, Option<Vec<EntityId>>);

/// The rows a listing door answers beside its result, as every served door
/// releases it by them: a list, or `None` for a call one of whose paths
/// lists none, never an empty list standing in for it.
pub(crate) trait ListedRows {
    /// The rows, `None` when they are unknown.
    fn rows(self) -> Option<Vec<EntityId>>;
}

impl ListedRows for Vec<EntityId> {
    fn rows(self) -> Option<Vec<EntityId>> {
        Some(self)
    }
}

impl ListedRows for Option<Vec<EntityId>> {
    fn rows(self) -> Option<Vec<EntityId>> {
        self
    }
}

/// A refusal before any read: it lists no row.
pub(super) fn refused<T>(refusal: MemoryError) -> Listed<T> {
    (Err(refusal), Vec::new())
}

/// The rows hex ids name; a value that is no id names none.
pub(super) fn hex_rows<S: AsRef<str>>(ids: impl IntoIterator<Item = S>) -> Vec<EntityId> {
    ids.into_iter()
        .filter_map(|hex| EntityId::from_hex(hex.as_ref()).ok())
        .collect()
}

/// The pack source row an install receipt is read from.
fn pack_source(receipt: &oneiron::skill_hub::pack_catalog::PackInstallReceipt) -> Option<EntityId> {
    EntityId::from_hex(&receipt.source_id).ok()
}

/// The lenses a slot decision names: the one it selected or cleared, and
/// the one the slot held before. Its pack slot and decision live in side
/// tables.
fn lens_rows(receipt: &LensActivationReceipt) -> Vec<EntityId> {
    hex_rows(std::iter::once(&receipt.lens_ref).chain(receipt.previous_ref.iter()))
}

/// A pack setup door's act off the runtime as the owner, listing what its
/// view is read from (`host_door_lists`): the pack's source row, each
/// connection's connector key, each standing grant and each stored secret's
/// custody record. The session and its checks live in side tables. `None`
/// when a stored secret's record cannot be read again.
async fn setup_listing(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(
        &Arc<SyncServer>,
        &oneiron::consent::AuthenticatedOwner,
    ) -> MemoryResult<PackSetupReceipt>
    + Send
    + 'static,
) -> MaybeListed<PackSetupReceipt> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        let answer = act(&server, &owner);
        let rows = match &answer {
            Ok(receipt) => setup_rows(server.vault(), &receipt.setup),
            Err(_) => Some(Vec::new()),
        };
        (answer, rows)
    })
    .await
    .unwrap_or_else(|_| (Err(internal(verb)), Some(Vec::new())))
}

/// The rows a pack setup view is read from, as [`setup_listing`] lists them.
fn setup_rows(
    vault: &oneiron::Vault,
    setup: &oneiron::skill_hub::pack_catalog::PackSetupView,
) -> Option<Vec<EntityId>> {
    let mut rows = hex_rows([&setup.source_id]);
    for connection in &setup.connections {
        rows.extend(hex_rows(connection.connector_key.iter()));
        rows.extend(hex_rows(
            connection
                .permissions
                .iter()
                .filter_map(|permission| permission.grant_ref.as_ref()),
        ));
        for secret in connection.secrets.iter().filter(|secret| secret.stored) {
            rows.extend(vault.resolve_secret_ref(&secret.name).ok()?);
        }
    }
    Some(rows)
}

/// `answer` beside the rows `named` reads off it, for a door whose answer
/// derives from no row but those it names (`host_door_lists`). A refusal
/// lists none.
pub(super) fn naming<T>(
    answer: MemoryResult<T>,
    named: impl FnOnce(&T) -> Vec<EntityId>,
) -> Listed<T> {
    let rows = answer.as_ref().map_or_else(|_| Vec::new(), named);
    (answer, rows)
}

/// `act` off the runtime with a fresh collector, which its handles list
/// into, and beside its answer the rows they listed. A worker that does not
/// finish answers [`internal`] and lists none.
pub(super) async fn off_runtime_listing<T: Send + 'static>(
    verb: &'static str,
    act: impl FnOnce(&ProducerRows) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    tokio::task::spawn_blocking(move || {
        let producers = ProducerRows::default();
        let answer = act(&producers);
        (answer, producers.take())
    })
    .await
    .unwrap_or_else(|_| refused(internal(verb)))
}

/// `read` off the runtime on the credential's own handle as `caller`, at
/// its locality ([`crate::api::credential_memory`]), listing every row its
/// reads derive the answer from: the one collector the credential-backed
/// host doors share.
pub(super) async fn credential_listing<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    (actor, class): (EntityId, EdgeActorClass),
    verb: &'static str,
    read: impl FnOnce(&SyncServer, &CoreAuth, Memory<'_>) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let (server, auth) = (Arc::clone(server), auth.clone());
    off_runtime_listing(verb, move |producers| {
        let memory = crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
            .at(auth.locality())
            .listing_producers(producers);
        read(&*server, &auth, memory)
    })
    .await
}

/// The rows a door reads beside its handle's own reads, as its caller names
/// them: a whole id, or an image handle (`<asset>@<hash>`) by its asset.
/// A short ref is the socket's to resolve, as every named ref is.
pub(super) fn read_beside<S: AsRef<str>>(named: impl IntoIterator<Item = S>) -> Vec<EntityId> {
    named
        .into_iter()
        .filter_map(|text| oneiron::memory::ImageHandle::parse(text.as_ref()).ok())
        .map(|handle| handle.asset)
        .collect()
}

/// The owner's call of `operation`, [`prepare`]d.
fn admit(
    server: &SyncServer,
    auth: &CoreAuth,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<(MediaRequest, Option<RungVoices>)> {
    owner_grade(auth, MEDIA_OWNERS)?;
    prepare(server, operation, input)
}

/// A call of `operation`, admitted against the vault's inference policy for
/// the model it names, ready for its seat's ladder, with the banked voice it
/// renders in, if any (bound as `/v1/ai/speech` binds it). Its caller's door
/// admitted the caller.
fn prepare(
    server: &SyncServer,
    operation: AiOperation,
    input: AiCallRequest,
) -> MemoryResult<(MediaRequest, Option<RungVoices>)> {
    let media = server.ai.model_runtime().media();
    let Some((seat, _)) = media.seat(operation) else {
        return Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            format!("no [models.media.{}] seat serves", operation.as_str()),
            &["Configure the operation's media seat on this server."],
        ));
    };
    let mut model = match input.model {
        Some(model) => {
            ModelId::new(model).map_err(|_| MemoryError::bad_request("model is not a model id"))?
        }
        None => seat,
    };
    let unserved = |model: &ModelId| {
        MemoryError::bad_request(format!(
            "{model} serves no {} call here",
            operation.as_str()
        ))
    };
    if media.locality(operation, &model).is_none() {
        return Err(unserved(&model));
    }
    let (voice, voices) =
        bind_voice(server, operation, &mut model, input.voice).map_err(voice_refused)?;
    let Some(locality) = media.locality(operation, &model) else {
        return Err(unserved(&model));
    };
    let mut parts = Vec::new();
    if let Some(prompt) = input.prompt {
        parts.push(MediaPart::Text { text: prompt });
    }
    let decoded = |parts: Vec<oneiron::task_verb::sdk::AiPart>| {
        parts
            .into_iter()
            .map(oneiron::task_verb::sdk::AiPart::into_media)
            .collect::<Option<Vec<_>>>()
    };
    let (Some(sent), Some(references)) = (decoded(input.input), decoded(input.references)) else {
        return Err(MemoryError::bad_request(
            "each part is text, or an image or audio with base64 data",
        ));
    };
    parts.extend(sent);
    let purpose = CallPurpose::Other {
        name: format!("ai.{}", operation.as_str()),
    };
    let mut request = MediaRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(
                &purpose,
                ModelTierRef(format!("media-{}", operation.as_str())),
            ),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality,
            seat_effort: None,
        },
        operation,
        parts,
        references,
        params: input.params,
        voice,
    };
    if let Some(key) = request.admission_request().route_selector_override() {
        return Err(MemoryError::bad_request(format!(
            "{key} would pick the model or the route; name the model instead"
        )));
    }
    let context = oneiron::llm::HostInferenceContext {
        binding: oneiron::llm::HostInferenceBinding::Advertised { model, locality },
        extraction_egress: server.extraction_egress.as_deref(),
    };
    let authorized = server
        .vault
        .authorize_raw_inference(request.admission_request(), &context)
        .map_err(|_| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the vault's inference policy refuses this call",
                &["Name a model the vault's inference policy admits."],
            )
        })?;
    request.envelope = authorized.into_request().envelope;
    // The world a caller names does not vouch for what it sends: a
    // fallback judges the call as naming none, as a raw text call is.
    request.envelope.scope.world = None;
    Ok((request, voices))
}

/// A refused voice, under the facade's codes: a banked voice no rung holds
/// is the bank's state (`INVALID_STATE`), any other refusal `BAD_REQUEST`.
fn voice_refused(refused: VoiceRefusal) -> MemoryError {
    let (code, suggestion) = match refused {
        VoiceRefusal::NotSpeech => (MEMORY_CODE_BAD_REQUEST, "Name a voice on ai.speech alone."),
        VoiceRefusal::Unnamed => (MEMORY_CODE_BAD_REQUEST, "Name the provider's voice."),
        VoiceRefusal::NotProvisioned => (
            MEMORY_CODE_INVALID_STATE,
            "Provision the voice on a target this call's ladder reaches: POST /v1/ai/voices/{voice_id}/targets/{target}.",
        ),
    };
    MemoryError::new(code, refused.message(), &[suggestion])
}

/// A media call's refusal, under the facade's codes: a spent line or window
/// is `BUDGET_SPENT`, a model that did not answer `MODEL_UNAVAILABLE`, and
/// a call its provider refused as written `BAD_REQUEST`.
fn failure(operation: AiOperation, error: &LlmError) -> MemoryError {
    let (code, suggestion) = match error {
        LlmError::BudgetDenied(_) => (MEMORY_CODE_BUDGET_SPENT, "The media meter is spent."),
        LlmError::Retryable(RetryableLlmError::QuotaSpent { .. }) => (
            MEMORY_CODE_BUDGET_SPENT,
            "A usage window or prepaid credit is spent: answer the quota question in GET /v1/ai/status at POST /v1/ai/quota/{question}.",
        ),
        LlmError::Fatal(FatalLlmError::Auth | FatalLlmError::EmptyResponse)
        | LlmError::Retryable(_) => (
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "Retry later, or name another row ai.options lists.",
        ),
        LlmError::Fatal(_) => (
            MEMORY_CODE_BAD_REQUEST,
            "Change the call as its provider asks.",
        ),
    };
    let detail = serde_json::to_string(error).unwrap_or_default();
    MemoryError::new(
        code,
        format!("ai.{}: {error} {detail}", operation.as_str()),
        &[suggestion],
    )
}

/// The vault owner's proof for an owner's host door, from the request, as
/// `/v1/owner` takes it.
pub(super) fn owner_proof(
    auth: &CoreAuth,
    server: &SyncServer,
    verb: &str,
) -> MemoryResult<oneiron::consent::AuthenticatedOwner> {
    crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })
}

/// `vault.lenses.activate`: the owner selects a proposed lens revision for
/// its pack slot, under the proof `/v1/owner` takes from the request. The
/// owner's confirmation is the consent; an agent can only propose.
async fn vault_lenses_activate_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LensActivateRequest,
) -> MemoryResult<LensActivationReceipt> {
    let owner = owner_proof(auth, server, "vault.lenses.activate")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || server.vault().activate_lens(&owner, input))
        .await
        .map_err(|_| internal("vault.lenses.activate"))?
}

/// [`vault_lenses_activate_answer`], listing the lens it selected and the one the slot held before
/// (`host_door_lists`).
pub(crate) async fn vault_lenses_activate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LensActivateRequest,
) -> Listed<LensActivationReceipt> {
    naming(
        vault_lenses_activate_answer(server, auth, input).await,
        lens_rows,
    )
}

/// `vault.lenses.deactivate`: the owner clears a pack slot's selected lens,
/// under the same proof. The pack, its skill and the proposal stay.
async fn vault_lenses_deactivate_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LensDeactivateRequest,
) -> MemoryResult<LensActivationReceipt> {
    let owner = owner_proof(auth, server, "vault.lenses.deactivate")?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || server.vault().deactivate_lens(&owner, input))
        .await
        .map_err(|_| internal("vault.lenses.deactivate"))?
}

/// [`vault_lenses_deactivate_answer`], listing the lens it cleared (`host_door_lists`).
pub(crate) async fn vault_lenses_deactivate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LensDeactivateRequest,
) -> Listed<LensActivationReceipt> {
    naming(
        vault_lenses_deactivate_answer(server, auth, input).await,
        lens_rows,
    )
}

/// `vault.packs.setup.prepare`: the owner opens, or resumes, a pack's guided
/// setup (OF-378), under the proof `/v1/owner` takes from the request.
/// Opening grants nothing.
pub(crate) async fn vault_packs_setup_prepare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupRequest,
) -> MaybeListed<PackSetupReceipt> {
    setup_listing(
        server,
        auth,
        "vault.packs.setup.prepare",
        move |server, owner| {
            oneiron::task_verb::sdk::prepare_pack_setup_as_owner(server.vault(), owner, &input)
        },
    )
    .await
}

/// `vault.packs.setup.get`: a pack's guided setup as it stands, under the
/// same proof.
pub(crate) async fn vault_packs_setup_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupRequest,
) -> MaybeListed<PackSetupReceipt> {
    setup_listing(
        server,
        auth,
        "vault.packs.setup.get",
        move |server, owner| {
            oneiron::task_verb::sdk::pack_setup_as_owner(server.vault(), owner, &input)
        },
    )
    .await
}

/// `vault.packs.setup.answer`: one answer or card action, under the same
/// proof. The verb never answers `allow` (the owner's review stays at
/// `/v1/owner/packs/setup/answer`), and a store action answers with the
/// owner secrets door; a credential value never passes here.
pub(crate) async fn vault_packs_setup_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupAnswerRequest,
) -> MaybeListed<PackSetupReceipt> {
    setup_listing(
        server,
        auth,
        "vault.packs.setup.answer",
        move |server, owner| {
            let checks = HostConnectionChecks::new(&server)?;
            oneiron::task_verb::sdk::answer_pack_setup_as_owner(
                server.vault(),
                owner,
                &input,
                &checks,
            )
        },
    )
    .await
}

/// `vault.packs.setup.verify`: checks one connection with the engine's fixed
/// read-only provider call for its declared check, under the same proof.
pub(crate) async fn vault_packs_setup_verify(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: PackSetupVerifyRequest,
) -> MaybeListed<PackSetupReceipt> {
    setup_listing(
        server,
        auth,
        "vault.packs.setup.verify",
        move |server, owner| {
            let checks = HostConnectionChecks::new(&server)?;
            oneiron::task_verb::sdk::verify_pack_setup_as_owner(
                server.vault(),
                owner,
                &input,
                &checks,
            )
        },
    )
    .await
}
