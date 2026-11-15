//! Doors to an exact replay's admission (FIX-LIST
//! REPLAY-REFUSED-FOR-WIDER-FALLBACK-RUNG): a runtime whose offers' rests and
//! the owner's standing quota fallbacks are kept in a vault, the owner's
//! `use_fallback` choice for each offer of a role's seat, an owner's model
//! manifest pinning every role to one model, and the admission of an exact
//! replay of a call of that role, as the replay callers (the
//! code-fix exact replay, the contribution fork, the audit judge and the
//! shadow arm) ask it.

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::manifest::ModelRole;
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};

use crate::config::models::ModelsConfig;
use crate::models::{ModelRuntime, OfferCooldowns};

/// The runtime `config_toml` (a `[models]` file) builds, its offers' rests
/// and the owner's quota choices kept in `vault`, as a hosted server's are.
///
/// # Errors
///
/// A config that does not parse or resolve.
pub fn runtime_keeping_owner_choices(
    config_toml: &str,
    vault: Arc<Vault>,
) -> anyhow::Result<ModelRuntime> {
    let config = ModelsConfig::from_toml(config_toml, None)?;
    Ok(ModelRuntime::build_hosted(
        Some(&config),
        None,
        OfferCooldowns::in_vault(vault),
        oneiron::HostingPrivacyPosture::SelfHostLocal,
    ))
}

/// The engine model id of each rung of `role`'s seat, in ladder order.
/// Empty when no seat serves the role.
#[must_use]
pub fn seat_models(runtime: &ModelRuntime, role: ModelRole) -> Vec<ModelId> {
    runtime
        .seat(role)
        .map(|seat| {
            seat.rung_models()
                .into_iter()
                .map(|(model, _)| model)
                .collect()
        })
        .unwrap_or_default()
}

/// Keeps `fallback`, an engine model id, as the owner's standing fallback
/// for every offer of `role`'s seat, as the owner's `use_fallback` answer to
/// each offer's quota question keeps it. How many offers.
///
/// # Errors
///
/// No seat serves `role`; the vault's.
pub fn keep_owner_fallback(
    runtime: &ModelRuntime,
    role: ModelRole,
    fallback: &ModelId,
) -> oneiron::Result<usize> {
    let seat = runtime
        .seat(role)
        .ok_or_else(|| oneiron::Error::InvalidConfig(format!("no seat serves {role:?}")))?;
    seat.ladder
        .keep_owner_fallback_for_each_offer(fallback.as_str())
}

/// Pins every role of `vault`'s model manifest to `model` on the LLM slot at
/// `route`, its extraction teacher probe-approved, as an owner pins one. The
/// extraction encoder binds the oneironer slot to `model`'s encoder id.
///
/// # Errors
///
/// A manifest the vault refuses; the vault's.
pub fn pin_every_role(vault: &Vault, model: &ModelId, route: ModelLocality) -> oneiron::Result<()> {
    use oneiron::llm::manifest::{
        MODEL_ROLES, ModelBinding, ModelManifest, ModelSlot, TeacherProbeApproval,
    };
    let encoder = ModelId::new(format!(
        "{}/{}-encoder@{}",
        model.provider(),
        model.name(),
        model.revision()
    ))
    .map_err(|error| oneiron::Error::InvalidConfig(format!("encoder model id: {error:?}")))?;
    let manifest = ModelManifest {
        version: 2,
        roles: MODEL_ROLES
            .into_iter()
            .map(|role| {
                let (model, slot) = if role == ModelRole::ExtractionEncoder {
                    (encoder.clone(), ModelSlot::Oneironer)
                } else {
                    (model.clone(), ModelSlot::Llm)
                };
                (
                    role,
                    ModelBinding {
                        model,
                        slot,
                        tier: ModelTierRef("pinned".into()),
                        route_models: BTreeMap::new(),
                        disposition: None,
                        reads_audio: false,
                    },
                )
            })
            .collect(),
        routes: [
            (ModelSlot::Llm, route),
            (ModelSlot::Embedder, ModelLocality::OnDevice),
            (ModelSlot::Oneironer, ModelLocality::OnDevice),
        ]
        .into_iter()
        .collect(),
        verdict: None,
        seat_policy: None,
    };
    let approval = TeacherProbeApproval::for_scored_checkpoint(
        &manifest,
        &vault.teacher_probe_policy(None)?,
        1_000_000,
    )?;
    vault.set_model_manifest_with_teacher_approval(&manifest, &approval)
}

/// Admits an exact replay of a call of `role` that `model` answered at
/// `locality`, as the replay callers send it: the captured model and route
/// on the request, never the role's pick. `Ok` when admitted, else the
/// refusal's text.
///
/// # Errors
///
/// The refusal's text.
pub fn admit_replay(
    runtime: &ModelRuntime,
    vault: &Vault,
    role: ModelRole,
    model: &ModelId,
    locality: ModelLocality,
) -> Result<(), String> {
    runtime
        .admit_replay(vault, role, replay_request(model, locality))
        .map(|_| ())
        .map_err(|refusal| refusal.to_string())
}

/// A chat call on `model` at `locality`, as a replay caller rebuilds the
/// captured one.
fn replay_request(model: &ModelId, locality: ModelLocality) -> LlmRequest {
    LlmRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("answer".into()),
            ),
            response_format: ResponseFormat::Text,
            locality,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "the captured question".into(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}
