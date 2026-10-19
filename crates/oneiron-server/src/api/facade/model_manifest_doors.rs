//! Typed owner doors over the existing manifest, route and provider seams.
use std::sync::Arc;

use oneiron::embed::EmbedderLocality;
use oneiron::llm::manifest::doors::{
    ModelManifestReplace, ModelRoleInput, ModelRoleInvocation, ModelRoleInvoke, ModelRoleOutput,
    ModelRoleRead, ModelRoleReceipt, ModelRouteRead, ModelRouteReplace, ModelRouteView,
};
use oneiron::llm::manifest::{ModelManifest, ModelRole, ModelSlot};
use oneiron::memory::extraction::{EncoderInput, EncoderMessage, ExtractionEncoder, infer_encoder};
use oneiron::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::{EntityId, ModelLocality};

use super::host_doors::{Listed, internal};
use super::legal_hold_doors::{as_owner, as_owner_naming};
use crate::auth::CoreAuth;
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
        move |server, owner| Ok(server.vault().model_role_as_owner(owner, input)?),
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

async fn invoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ModelRoleInvoke,
) -> MemoryResult<ModelRoleInvocation> {
    const VERB: &str = "vault.models.roles.invoke";
    let role = input.role;
    let mut receipt = as_owner(server, auth, VERB, move |server, owner| {
        Ok(server
            .vault()
            .model_role_as_owner(owner, ModelRoleRead { role })?)
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
            let (output, provider) = tokio::task::spawn_blocking(move || {
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
                    language: None,
                    speaker: None,
                };
                let output = infer_encoder(&input, encoder).map_err(MemoryError::bad_request)?;
                Ok::<_, MemoryError>((output, slot.config().provider.as_str().to_owned()))
            })
            .await
            .map_err(|_| internal(VERB))??;
            receipt.provider = provider;
            ModelRoleOutput::Tagged { output }
        }
    };
    Ok(ModelRoleInvocation { receipt, output })
}
