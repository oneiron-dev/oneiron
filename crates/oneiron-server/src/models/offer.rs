//! What a run admission binds a model call to: one model at one provider, the
//! route it goes out on, who pays for it and where its key sits.
use std::sync::Arc;

use oneiron::ModelId;
use oneiron::llm::SingleRouteBackend;
use oneiron::llm::run_admission::{KeyCustody, OfferBinding, OfferRoute, Payer};

use crate::config::models::{ProviderConfig, ProviderKind};

/// One model at one provider, as this server serves it: the offer a run
/// admits the call under, and the single-route backend that offer's gate
/// wraps.
#[derive(Clone)]
pub struct ServedOffer {
    pub binding: OfferBinding,
    pub backend: Arc<dyn SingleRouteBackend>,
}

/// The offer `[models]` binds for `model` on `provider`. A `key_env` key is
/// the owner's own and sits in this process, not behind the credential
/// broker, so it is held at T1: a declared run refuses it unless the owner
/// allows that offer. A provider with no key is the vault's own server.
pub(super) fn provider_offer(
    provider: &ProviderConfig,
    model: ModelId,
) -> anyhow::Result<OfferBinding> {
    let origin = reqwest::Url::parse(&provider.base_url)?
        .origin()
        .ascii_serialization();
    let route = OfferRoute::new(adapter(provider.kind), origin)
        .map_err(|error| anyhow::anyhow!("model route: {error}"))?;
    let keyed = provider.key_env.is_some();
    Ok(OfferBinding {
        offer: model.as_str().to_owned(),
        model,
        route,
        locality: provider.locality,
        payer: if keyed {
            Payer::CustomerKey
        } else {
            Payer::Local
        },
        credential_binding: provider.key_env.as_ref().map(|env| format!("env:{env}")),
        catalog_revision: Some(provider.revision.clone()),
        custody: if keyed {
            KeyCustody::T1
        } else {
            KeyCustody::Keyless
        },
        rates: Vec::new(),
    })
}

/// The wire adapter a provider kind speaks, as its route names it.
fn adapter(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::OpenaiCompat => "openai-compat",
        ProviderKind::AnthropicCompat => "anthropic-compat",
        ProviderKind::LocalOpenaiCompat => "local-openai-compat",
        ProviderKind::Oneironer => "oneironer",
    }
}
