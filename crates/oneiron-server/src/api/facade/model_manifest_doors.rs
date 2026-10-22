//! Typed owner doors over the existing manifest, route and provider seams.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::embed::EmbedderLocality;
use oneiron::llm::manifest::doors::{
    ModelManifestReplace, ModelRoleInput, ModelRoleInvocation, ModelRoleInvoke, ModelRoleOutput,
    ModelRoleRead, ModelRoleReceipt, ModelRouteRead, ModelRouteReplace, ModelRouteView,
    OneironerBind,
};
use oneiron::llm::manifest::{ModelManifest, ModelRole, ModelSlot};
use oneiron::memory::extraction::{
    EncoderInput, EncoderMessage, EncoderRegister, ExtractionCaller, ExtractionEncoder,
    ExtractionWork, infer_encoder_for,
};
use oneiron::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::{EntityId, ModelId, ModelLocality, ModelTierRef};

use super::host_doors::support::{Listed, internal};
use super::legal_hold_doors::{as_owner, as_owner_naming};
use crate::auth::CoreAuth;
use crate::config::{OneironerConfig, OneironerProvider};
use crate::oneironer::endpoint::ModelCard;
use crate::server::SyncServer;

pub(crate) async fn vault_models_manifest_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Option<ModelManifest>> {
    as_owner_naming(
        server,
        auth,
        "vault.models.manifest.read",
        |server, owner| Ok(server.vault().model_manifest_as_owner(owner)?),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_models_manifest_replace(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelManifestReplace,
) -> Listed<ModelManifest> {
    as_owner_naming(
        server,
        auth,
        "vault.models.manifest.replace",
        move |server, owner| {
            Ok(server
                .vault()
                .replace_model_manifest_as_owner(owner, input)?)
        },
        |_| Vec::new(),
    )
    .await
}

/// Binds the Oneironer this server has loaded into the current manifest. The
/// identity is the loaded slot's, never the caller's: its guards only
/// compare. Side tables list no vault record.
pub(crate) async fn vault_models_oneironer_bind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OneironerBind,
) -> Listed<ModelManifest> {
    as_owner_naming(
        server,
        auth,
        "vault.models.oneironer.bind",
        move |server, owner| {
            let (model, tier) = loaded_oneironer(server, &input)?;
            Ok(server
                .vault()
                .bind_oneironer_as_owner(owner, &model, &tier)?)
        },
        |_| Vec::new(),
    )
    .await
}

/// The Oneironer this server has loaded, as `TaggerSlot::selected_by`
/// compares it: the local tagger's own model, whose revision is the
/// configured checkpoint, and the tier [`oneironer_tier`] names it by, the
/// named tier it serves or else its loaded card's stack. A guard the caller
/// names must match it.
fn loaded_oneironer(
    server: &SyncServer,
    guards: &OneironerBind,
) -> MemoryResult<(ModelId, ModelTierRef)> {
    let slot = server
        .tagger
        .as_ref()
        .ok_or_else(|| unavailable("no oneironer slot is loaded"))?;
    let config = slot.config();
    if !config.is_active() {
        return Err(unavailable("the oneironer slot is disabled"));
    }
    if config.provider != OneironerProvider::Local {
        return Err(unavailable("the oneironer slot is not provider local"));
    }
    let card = slot
        .card()
        .ok_or_else(|| unavailable("the oneironer slot has no loaded model card"))?;
    let model = slot.tagger().model_id();
    let checkpoint = config.checkpoint_sha16.as_deref().unwrap_or_default();
    if model.revision() != checkpoint || card.checkpoint_sha16 != checkpoint {
        return Err(unavailable(
            "the loaded oneironer does not serve the configured checkpoint",
        ));
    }
    if guards
        .expected_checkpoint_sha16
        .as_deref()
        .is_some_and(|expected| expected != checkpoint)
    {
        return Err(MemoryError::bad_request(
            "expected_checkpoint_sha16 does not match the loaded oneironer",
        ));
    }
    let stack = card.stack_sha16.as_deref();
    if guards
        .expected_stack_sha16
        .as_deref()
        .is_some_and(|expected| Some(expected) != stack)
    {
        return Err(MemoryError::bad_request(
            "expected_stack_sha16 does not match the loaded oneironer",
        ));
    }
    let tier = oneironer_tier(config, Some(&card), model);
    Ok((model.clone(), tier))
}

/// The tier an Oneironer bind or host receipt names, and the one place its
/// order lives: the named tier the host is configured to serve; else the
/// stack of the card its probe accepted, the loaded bundle; else the
/// configured stack pin; else the loaded tagger's revision, the configured
/// checkpoint. The last two are configured identity that no loaded card has
/// attested; they name a slot whose probe has not accepted a card yet. Never
/// the manifest's current tier nor the role's key: either may describe
/// another bundle.
fn oneironer_tier(
    config: &OneironerConfig,
    card: Option<&ModelCard>,
    model: &ModelId,
) -> ModelTierRef {
    let attested = card.and_then(|card| card.stack_sha16.as_deref());
    let tier = config
        .tier
        .as_deref()
        .or(attested)
        .or(config.stack_sha16.as_deref())
        .unwrap_or_else(|| model.revision());
    ModelTierRef(tier.to_owned())
}

pub(crate) async fn vault_models_routes_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelRouteRead,
) -> Listed<ModelRouteView> {
    as_owner_naming(
        server,
        auth,
        "vault.models.routes.read",
        move |server, owner| Ok(server.vault().model_route_as_owner(owner, input)?),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_models_routes_replace(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelRouteReplace,
) -> Listed<ModelRouteView> {
    as_owner_naming(
        server,
        auth,
        "vault.models.routes.replace",
        move |server, owner| Ok(server.vault().replace_model_route_as_owner(owner, input)?),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_models_roles_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelRoleRead,
) -> Listed<ModelRoleReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.models.roles.read",
        move |server, owner| role_receipt(server, owner, input.role),
        |_| Vec::new(),
    )
    .await
}

/// Side tables and caller-supplied text list no vault record. An invocation
/// never supplies an endpoint, credential or transport of its own.
pub(crate) async fn vault_models_roles_invoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelRoleInvoke,
) -> Listed<ModelRoleInvocation> {
    let answer = invoke(server, auth, input).await;
    (answer, Vec::new())
}

fn unavailable(message: &str) -> MemoryError {
    MemoryError::new(MEMORY_CODE_MODEL_UNAVAILABLE, message, &[])
}

fn locality(locality: EmbedderLocality) -> ModelLocality {
    match locality {
        EmbedderLocality::OnDevice => ModelLocality::OnDevice,
        EmbedderLocality::OwnerServer => ModelLocality::OwnServer,
        EmbedderLocality::ThirdParty => ModelLocality::ThirdParty,
    }
}

/// Whether `role`, in a vault with no manifest, is served from the host's
/// own section: the selection `TaggerSlot::selected_by` takes for such a
/// vault (FIX 6840). Every other role needs a manifest.
fn host_section_serves(role: ModelRole) -> bool {
    role == ModelRole::ExtractionEncoder
}

/// The receipt of the encoder the host's `[oneironer]` section serves a vault
/// with no manifest: the loaded tagger's own model, whose revision is the
/// configured checkpoint, at its own route, named by [`oneironer_tier`]. A
/// slot whose probe has not accepted a card yet still answers. The host alone
/// attests it.
fn host_section_receipt(server: &SyncServer, role: ModelRole) -> MemoryResult<ModelRoleReceipt> {
    let slot = server
        .tagger
        .as_ref()
        .ok_or_else(|| unavailable("no extraction encoder is configured"))?;
    let config = slot.config();
    let encoder = slot.tagger().as_ref();
    let model = encoder.model_id().clone();
    let tier = oneironer_tier(config, slot.card().as_ref(), &model);
    Ok(ModelRoleReceipt {
        role,
        revision: model.revision().to_owned(),
        provider: config.provider.as_str().to_owned(),
        model,
        slot: ModelSlot::Oneironer,
        tier,
        route: locality(encoder.locality()),
        catalog_revision: None,
    })
}

/// The receipt `role` resolves to, the one rule read and invoke share: a
/// vault with no manifest takes the host's section for a role it serves
/// ([`host_section_serves`]); every other role, and every vault with a
/// manifest, its manifest's binding. Both reads revalidate `owner`.
fn role_receipt(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    role: ModelRole,
) -> MemoryResult<ModelRoleReceipt> {
    let vault = server.vault();
    if host_section_serves(role) && vault.model_manifest_as_owner(owner)?.is_none() {
        return host_section_receipt(server, role);
    }
    Ok(vault.model_role_as_owner(owner, ModelRoleRead { role })?)
}

async fn invoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelRoleInvoke,
) -> MemoryResult<ModelRoleInvocation> {
    const VERB: &str = "vault.models.roles.invoke";
    let role = input.role;
    let mut receipt = as_owner(server, auth, VERB, move |server, owner| {
        role_receipt(server, owner, role)
    })
    .await?;
    let output = match input.input {
        ModelRoleInput::Generate { request } => {
            if receipt.slot != ModelSlot::Llm {
                return Err(MemoryError::bad_request(
                    "generate requires a role in the llm slot",
                ));
            }
            if request.route_selector_override().is_some() {
                return Err(MemoryError::bad_request(
                    "a role call cannot override its model or route",
                ));
            }
            let runtime = server.ai.model_runtime();
            let (call, catalog_revision) = runtime
                .admit_role_receipted(server.vault(), role, *request)
                .map_err(|_| unavailable("the configured role did not admit this request"))?;
            receipt.catalog_revision = catalog_revision;
            let request = call.request;
            if request.model != receipt.model || request.envelope.locality != receipt.route {
                return Err(MemoryError::bad_request(
                    "the role binding changed during admission",
                ));
            }
            let raw = server
                .llm
                .as_ref()
                .ok_or_else(|| unavailable("no model-call meter is configured"))?;
            // Use the raw sibling's meter and run gate, but the role's own
            // prompt-bearing ladder. A pinned manifest call never silently
            // substitutes another model or route.
            let (_, run) = raw
                .call(&request, server.run_receipts())
                .ok_or_else(|| unavailable("the pinned model is not served here"))?;
            let response = call
                .ladder
                .generate_exact(&run, request, None)
                .await
                .map_err(|error| MemoryError::bad_request(error.to_string()))?;
            if let Some(provider) = response.usage.served_provider() {
                receipt.provider = provider.to_owned();
            }
            ModelRoleOutput::Generated { response }
        }
        ModelRoleInput::Embed { text } => {
            if role != ModelRole::RetrievalEmbedder || receipt.slot != ModelSlot::Embedder {
                return Err(MemoryError::bad_request(
                    "embed requires retrieval_embedder in the embedder slot",
                ));
            }
            if text.trim().is_empty() {
                return Err(MemoryError::bad_request("embedding text is empty"));
            }
            let expected = receipt.clone();
            let embedding_server = Arc::clone(server);
            let vector = tokio::task::spawn_blocking(move || {
                let slot = embedding_server
                    .embedder
                    .as_ref()
                    .ok_or_else(|| unavailable("no retrieval embedder is configured"))?;
                let provider = slot
                    .admitted_provider()
                    .ok_or_else(|| unavailable("the retrieval embedder is not ready"))?;
                if provider.model_id() != expected.model.as_str()
                    || locality(provider.locality()) != expected.route
                {
                    return Err(unavailable(
                        "the retrieval embedder does not serve the pinned model and route",
                    ));
                }
                slot.embed_query(&text)
                    .map_err(|_| unavailable("the retrieval embedder could not answer"))
            })
            .await
            .map_err(|_| internal(VERB))??;
            if let Some(slot) = &server.embedder {
                receipt.provider = slot.provider().as_str().to_owned();
            }
            ModelRoleOutput::Embedded { vector }
        }
        ModelRoleInput::Tag { text } => {
            if role != ModelRole::ExtractionEncoder || receipt.slot != ModelSlot::Oneironer {
                return Err(MemoryError::bad_request(
                    "tag requires extraction_encoder in the oneironer slot",
                ));
            }
            if text.trim().is_empty() {
                return Err(MemoryError::bad_request("tagging text is empty"));
            }
            let expected = receipt.clone();
            let server = Arc::clone(server);
            let (output, execution, provider) = tokio::task::spawn_blocking(move || {
                let slot = server
                    .tagger
                    .as_ref()
                    .ok_or_else(|| unavailable("no extraction encoder is configured"))?;
                slot.selected_by(server.vault()).map_err(|_| {
                    unavailable("the configured encoder is not selected by the manifest")
                })?;
                let encoder = slot.tagger().as_ref();
                if locality(encoder.locality()) != expected.route
                    || encoder.model_id().revision() != expected.revision
                {
                    return Err(unavailable(
                        "the encoder does not serve the pinned revision and route",
                    ));
                }
                let input = EncoderInput {
                    turn: EntityId::now().to_hex(),
                    messages: vec![EncoderMessage {
                        id: EntityId::now().to_hex(),
                        text,
                    }],
                    context: Vec::new(),
                    following: Vec::new(),
                    register: EncoderRegister::Live,
                    language: None,
                    speaker: None,
                };
                // The owner waits on this call: a live one, at the owner's
                // own turn (FIX 9519).
                let caller = ExtractionCaller::new("owner");
                let attempt = infer_encoder_for(&input, ExtractionWork::Live, encoder, &caller);
                let output = attempt.result.map_err(MemoryError::bad_request)?;
                let provider = slot.config().provider.as_str().to_owned();
                Ok::<_, MemoryError>((output, attempt.execution, provider))
            })
            .await
            .map_err(|_| internal(VERB))??;
            receipt.provider = provider;
            ModelRoleOutput::Tagged { output, execution }
        }
    };
    Ok(ModelRoleInvocation { receipt, output })
}
