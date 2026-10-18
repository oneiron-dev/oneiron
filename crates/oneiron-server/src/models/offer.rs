//! What a run admission binds a model call to: one model at one provider, the
//! route it goes out on, who pays for it and where its key sits.
use std::sync::Arc;

use oneiron::ModelId;
use oneiron::llm::SingleRouteBackend;
use oneiron::llm::media::AiOperation;
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferBinding, OfferRoute, PaidConnector};

use crate::config::models::{ProviderConfig, ProviderKind};

/// One model at one provider, as this server serves it: the offer a run
/// admits the call under, and the single-route backend that offer's gate
/// wraps.
#[derive(Clone)]
pub struct ServedOffer {
    pub binding: OfferBinding,
    pub backend: Arc<dyn SingleRouteBackend>,
}

/// The offer `[models]` binds for `model` on `provider`. Unless the host
/// explicitly names another payer, a `key_env` key is the owner's own. It
/// sits in this process, not behind the credential
/// broker, so it is held at T1: a declared run refuses it unless the owner
/// allows that offer. A `key_secret` key stays in the vault's custody and
/// only the credential broker sends it, so it is at T0. A provider with no
/// key defaults to the vault's own server. A reranker's offer names the rerank
/// protocol as its adapter, so a chat permit never starts a rerank call at
/// the same origin, nor the reverse.
pub(super) fn provider_offer(
    provider: &ProviderConfig,
    model: ModelId,
    rerank: bool,
) -> anyhow::Result<OfferBinding> {
    let origin = reqwest::Url::parse(&provider.base_url)?
        .origin()
        .ascii_serialization();
    let adapter = if rerank {
        format!("{}-rerank", adapter(provider.kind))
    } else {
        adapter(provider.kind).to_owned()
    };
    let route = OfferRoute::new(adapter, origin)
        .map_err(|error| anyhow::anyhow!("model route: {error}"))?;
    let (custody, credential_binding) = match (&provider.key_secret, &provider.key_env) {
        (Some(secret), _) => (KeyCustody::T0, Some(format!("secret:{secret}"))),
        (None, Some(env)) => (KeyCustody::T1, Some(format!("env:{env}"))),
        (None, None) => (KeyCustody::Keyless, None),
    };
    Ok(OfferBinding {
        offer: model.as_str().to_owned(),
        model,
        route,
        locality: provider.locality,
        payer: provider.payer,
        credential_binding,
        catalog_revision: Some(provider.revision.clone()),
        custody,
        rates: provider.rates.clone(),
        // A configured offer is the owner's; a funded run binds its payer.
        payer_person: None,
    })
}

/// The offer `[models.media]` binds for `model` on `provider` for one media
/// operation: the provider's offer, at a route that names the operation's
/// protocol, so a chat permit never starts an image call at the same
/// origin, nor the reverse.
pub(super) fn media_offer(
    provider: &ProviderConfig,
    model: ModelId,
    operation: AiOperation,
) -> anyhow::Result<OfferBinding> {
    let mut binding = provider_offer(provider, model, false)?;
    binding.route = OfferRoute::new(
        format!("{}-{}", binding.route.adapter(), operation.as_str()),
        binding.route.origin().to_owned(),
    )
    .map_err(|error| anyhow::anyhow!("media route: {error}"))?;
    Ok(binding)
}

/// The paid connector hosted provider `name`'s voice-clone calls are
/// admitted as (FIX 3009): its clone protocol at its origin, so a speech
/// permit never starts a clone call nor the reverse, paid and keyed as the
/// provider's offers are. A clone reports no usage, so each call is one unit.
pub(super) fn clone_connector(
    provider: &ProviderConfig,
    name: &str,
) -> anyhow::Result<PaidConnector> {
    let origin = reqwest::Url::parse(&provider.base_url)?
        .origin()
        .ascii_serialization();
    let route = OfferRoute::new(format!("{}-voice-clone", adapter(provider.kind)), origin)
        .map_err(|error| anyhow::anyhow!("voice clone route: {error}"))?;
    let (custody, credential_binding) = match (&provider.key_secret, &provider.key_env) {
        (Some(secret), _) => (KeyCustody::T0, Some(format!("secret:{secret}"))),
        (None, Some(env)) => (KeyCustody::T1, Some(format!("env:{env}"))),
        (None, None) => (KeyCustody::Keyless, None),
    };
    Ok(PaidConnector {
        connector: format!("voice-clone:{name}"),
        route,
        locality: provider.locality,
        payer: provider.payer,
        credential_binding,
        catalog_revision: Some(provider.revision.clone()),
        custody,
        unit_cost: 1,
        cost_unit: LeaseUnit::tokens(),
        rates: provider.rates.clone(),
    })
}

/// The wire adapter a provider kind speaks, as its route names it.
fn adapter(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::OpenaiCompat => "openai-compat",
        ProviderKind::AnthropicCompat => "anthropic-compat",
        ProviderKind::LocalOpenaiCompat => "local-openai-compat",
        ProviderKind::Oneironer => "oneironer",
        ProviderKind::Cartesia => "cartesia",
        ProviderKind::Elevenlabs => "elevenlabs",
        ProviderKind::Voxcpm2 => "voxcpm2",
        ProviderKind::Gemini => "gemini",
        ProviderKind::Soniox => "soniox",
    }
}
