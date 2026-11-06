use std::collections::{BTreeMap, BTreeSet};

use oneiron::llm::manifest::ModelRole;

use super::{ModelRef, ProviderConfig, ProviderKind, Rung, role_key};

pub(super) fn validate_ladders(
    providers: &BTreeMap<String, ProviderConfig>,
    roles: &BTreeMap<ModelRole, Vec<Rung>>,
) -> anyhow::Result<()> {
    // Two provider spellings that map to one engine id would share one
    // catalog row: one of them would silently run as the other.
    let mut engine_ids: BTreeMap<oneiron::ModelId, &ModelRef> = BTreeMap::new();
    for rung in roles.values().flatten() {
        let Some(provider) = providers.get(&rung.model.provider) else {
            continue;
        };
        let id = rung.model.engine_id(&provider.revision)?;
        if let Some(other) = engine_ids.insert(id.clone(), &rung.model)
            && other != &rung.model
        {
            anyhow::bail!(
                "models {other} and {} both become engine id {id}; rename one",
                rung.model
            );
        }
    }
    for (role, ladder) in roles {
        let key = role_key(*role);
        if *role == ModelRole::RetrievalEmbedder {
            anyhow::bail!(
                "models.roles.{key}: the retrieval embedder is configured in [embedder] (provider = \"endpoint\" takes any OpenAI-compatible /v1/embeddings server)"
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for rung in ladder {
            let provider = providers.get(&rung.model.provider).ok_or_else(|| {
                anyhow::anyhow!(
                    "models.roles.{key}: {} names provider {:?}, which [models.providers] does not define",
                    rung.model,
                    rung.model.provider
                )
            })?;
            if provider.kind.media_only() {
                anyhow::bail!(
                    "models.roles.{key}: {} is on a media provider, which serves [models.media] seats only",
                    rung.model
                );
            }
            let tagger_role = *role == ModelRole::ExtractionEncoder;
            if tagger_role != (provider.kind == ProviderKind::Oneironer) {
                anyhow::bail!(
                    "models.roles.{key}: {} is a {} provider; extraction_encoder takes a tagger (kind = \"oneironer\") and every other role takes a generating provider",
                    rung.model,
                    if provider.kind.generates() {
                        "generating"
                    } else {
                        "tagger"
                    }
                );
            }
            if *role == ModelRole::Reranker && !provider.kind.reranks() {
                anyhow::bail!(
                    "models.roles.{key}: {} is not on an OpenAI-compatible provider; the reranker is called over /v1/rerank",
                    rung.model
                );
            }
            if !seen.insert(&rung.model) {
                anyhow::bail!(
                    "models.roles.{key}: {} appears twice in one ladder",
                    rung.model
                );
            }
        }
    }
    Ok(())
}

/// `[models.aliases]`: each target is the engine id
/// (`provider/name@revision`) of a model a ladder names.
pub(super) fn resolve_aliases(
    aliases: BTreeMap<String, String>,
    providers: &BTreeMap<String, ProviderConfig>,
    roles: &BTreeMap<ModelRole, Vec<Rung>>,
) -> anyhow::Result<BTreeMap<String, oneiron::ModelId>> {
    let configured = roles
        .values()
        .flatten()
        .filter_map(|rung| {
            let provider = providers.get(&rung.model.provider)?;
            rung.model.engine_id(&provider.revision).ok()
        })
        .collect::<BTreeSet<_>>();
    aliases
        .into_iter()
        .map(|(alias, target)| {
            let id = target.parse::<oneiron::ModelId>().map_err(|error| {
                anyhow::anyhow!(
                    "models.aliases.{alias}: {target:?} is not a provider/name@revision model id: {error}"
                )
            })?;
            anyhow::ensure!(
                configured.contains(&id),
                "models.aliases.{alias}: {id} is not a model [models] configures"
            );
            // An alias spelled as a configured id would silently reroute it.
            anyhow::ensure!(
                !configured.iter().any(|model| model.as_str() == alias),
                "models.aliases.{alias}: the alias is a configured model's own id"
            );
            Ok((alias, id))
        })
        .collect()
}
