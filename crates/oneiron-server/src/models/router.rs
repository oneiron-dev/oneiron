//! Every configured model and seat by id: the raw `/v1/llm` routes call
//! whichever model they name, through its ladder and a run.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, PoisonError, RwLock};

use oneiron::llm::model_pack::AccessSnapshot;
use oneiron::llm::run_admission::OfferBinding;
use oneiron::{LlmCatalogEntry, ModelId, ModelLocality, Vault};

use super::catalog::engine_model_id;
use super::ladder::OfferLadder;
use super::offer::provider_offer;
use super::{referenced_models, reranker_models};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::config::models::WorkerConfig;
use crate::config::models::{ModelsConfig, ProviderConfig};

/// Each model by id: where it runs and the ladder that serves it.
pub(super) type Routes = BTreeMap<ModelId, (ModelLocality, Arc<OfferLadder>)>;

/// How a discovered model's offer names its route: the owner's node that
/// offers it, by machine id (FIX 3229).
pub(super) const MESH_ORIGIN: &str = "mesh:";

#[derive(Default)]
pub struct ModelRouter {
    routes: Routes,
    /// The models the owner's other nodes offer (FIX 3229), as the last mesh
    /// catalog refresh left them, each served alone at its node. A configured
    /// route of the same id wins. Readers clone the map and let go at once.
    discovered: RwLock<Arc<Routes>>,
    /// Each configured chat model served alone by its own id, and the family
    /// its provider's config names for it.
    chat: BTreeMap<ModelId, Option<String>>,
    /// The owner's aliases (`[models.aliases]`), each for a configured
    /// model's id.
    aliases: BTreeMap<String, ModelId>,
    /// Each chat model's catalog entry, as the owner's other nodes see it.
    entries: BTreeMap<ModelId, LlmCatalogEntry>,
    /// The on-device view of each configured model or seat a managed worker
    /// this server supervises serves over its native channel (I2-LOCAL): the
    /// ladder a call routed on device takes, which never sends anywhere
    /// else. Its default route, in `routes`, keeps every other transport.
    on_device: BTreeMap<ModelId, Arc<OfferLadder>>,
}

impl ModelRouter {
    pub(super) fn insert(
        &mut self,
        model: ModelId,
        locality: ModelLocality,
        ladder: Arc<OfferLadder>,
    ) {
        self.routes.insert(model, (locality, ladder));
    }

    /// Records `ladder` as `model`'s on-device view: a ladder that sends
    /// only over supervised native channels ([`OfferLadder::native_local`]).
    /// Any other ladder is left out, so this view never names a transport
    /// that can leave the device.
    pub(super) fn insert_on_device(&mut self, model: ModelId, ladder: Arc<OfferLadder>) {
        if ladder.native_local() {
            self.on_device.insert(model, ladder);
        }
    }

    /// Where `model` runs and the ladder that serves it for a call routed at
    /// `route` (I2-LOCAL): on device, its on-device view when it has one;
    /// at any other route, or with no such view, [`Self::served`]. The
    /// caller still compares the locality with the route it asked for.
    pub(crate) fn served_at(
        &self,
        model: &ModelId,
        route: ModelLocality,
    ) -> Option<(ModelLocality, Arc<OfferLadder>)> {
        if route == ModelLocality::OnDevice
            && let Some(ladder) = self.on_device.get(model)
        {
            return Some((ModelLocality::OnDevice, Arc::clone(ladder)));
        }
        self.served(model)
    }

    /// Records `model`, served alone by its own id, as a chat model of
    /// `family`.
    pub(super) fn chat_model(&mut self, model: ModelId, family: Option<String>) {
        self.chat.insert(model, family);
    }

    /// Records the catalog entry of a chat model served by its own id.
    pub(super) fn chat_entry(&mut self, entry: LlmCatalogEntry) {
        self.entries.insert(entry.model.clone(), entry);
    }

    /// The catalog entry of every chat model served by its own id, in id
    /// order.
    pub fn chat_catalog(&self) -> impl Iterator<Item = &LlmCatalogEntry> {
        self.entries.values()
    }

    /// Names the owner's aliases, each for the configured model it calls.
    pub(super) fn name_aliases(&mut self, aliases: &BTreeMap<String, ModelId>) {
        self.aliases.clone_from(aliases);
    }

    /// The configured model an owner alias names, when `[models.aliases]`
    /// has it.
    pub fn aliased(&self, alias: &str) -> Option<&ModelId> {
        self.aliases.get(alias)
    }

    /// Every chat model this router serves alone by its own id (no seat, no
    /// reranker), in id order.
    pub fn chat_models(&self) -> impl Iterator<Item = &ModelId> {
        self.chat.keys()
    }

    /// The family the config names for a chat model served by its own id.
    pub fn family(&self, model: &ModelId) -> Option<&str> {
        self.chat.get(model)?.as_deref()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Where `model` runs, when this router's config serves it. This is the
    /// host's attestation for the engine's inference admission. A model the
    /// mesh discovered has none: its own-server row vouches for it, and this
    /// node never serves it on to another node.
    pub fn locality(&self, model: &ModelId) -> Option<ModelLocality> {
        self.routes.get(model).map(|(locality, _)| *locality)
    }

    /// Where `model` runs and the ladder that serves it: its configured
    /// route, or else the route a mesh catalog refresh found for it.
    pub fn served(&self, model: &ModelId) -> Option<(ModelLocality, Arc<OfferLadder>)> {
        let route = |routes: &Routes| {
            routes
                .get(model)
                .map(|(locality, ladder)| (*locality, Arc::clone(ladder)))
        };
        route(&self.routes).or_else(|| route(&self.discovered()))
    }

    /// Every model this router serves now, configured or mesh-discovered,
    /// with where each runs, in id order (FIX 2745): the birth-time snapshot
    /// a seat birth admits its pick from. A configured route wins over a
    /// discovered one, as `served` reads them.
    pub fn served_models(&self) -> BTreeMap<ModelId, ModelLocality> {
        let mut served: BTreeMap<ModelId, ModelLocality> = self
            .discovered()
            .iter()
            .map(|(model, (locality, _))| (model.clone(), *locality))
            .collect();
        served.extend(
            self.routes
                .iter()
                .map(|(model, (locality, _))| (model.clone(), *locality)),
        );
        served
    }

    /// The access this router's offers hold now, each with the models it
    /// serves by their own id, configured or mesh-discovered, as
    /// [`Self::served`] finds them, and on device, as [`Self::served_at`]
    /// finds them there (FIX 5366): what a vault's model pack picks a role's
    /// variant from. A local GPU is held only by an on-device view's offers
    /// ([`oneiron::llm::model_pack::model_pack_access_for`]). Read from the
    /// host-bound offers alone; nothing is probed. A seat's rungs, reached
    /// only through the seat, are left out.
    pub fn access_snapshot(&self) -> AccessSnapshot {
        let mut snapshot = AccessSnapshot::new();
        let discovered = self.discovered();
        let ladders = self
            .routes
            .iter()
            .chain(discovered.iter())
            .map(|(model, (_, ladder))| (model, ladder))
            .chain(self.on_device.iter());
        for (model, ladder) in ladders {
            for offer in ladder.offer_bindings() {
                if offer.model == *model {
                    snapshot.insert_offer(offer);
                }
            }
        }
        snapshot
    }

    /// The access the router a `serve` of `vault` builds from `config` would
    /// hold, as [`Self::access_snapshot`] reads it (FIX 22059, 22189): what
    /// `oneiron maintain` lends a stopped vault's model pack retirement
    /// sweep. It holds each model a role's ladder names on a provider that
    /// generates, and each the reranker's ladder names on one that reranks,
    /// with the offer its route binds; the on-device view of each such chat
    /// model a managed EXL3 worker row serves, which plain `serve` binds
    /// beside the workers it launches; and, with or without `config`, each
    /// model the vault's mesh discovery rows hold that no configured route
    /// serves, which `serve` routes to the owner's node that offers it from
    /// its start, before its first mesh refresh. A `serve` with the mesh off
    /// marks those rows stale at its start (FIX 22227), so after it none
    /// counts. Read from `config` and the
    /// vault's rows alone: no backend is built, no worker is launched, no
    /// key is read and nothing is sent, so a provider that would not start
    /// (its key variable unset, say) still counts.
    pub(crate) fn stopped_vault_access_snapshot(
        config: Option<&ModelsConfig>,
        vault: &Vault,
    ) -> AccessSnapshot {
        let mut snapshot = AccessSnapshot::new();
        // The ids a configured route serves, which keep that route.
        let mut configured = BTreeSet::new();
        let providers = config
            .into_iter()
            .flat_map(|config| config.providers.iter().map(move |entry| (config, entry)));
        for (config, (name, provider)) in providers {
            let chat_routes = provider
                .kind
                .generates()
                .then(|| (referenced_models(config, name), false));
            let rerank_routes = provider
                .kind
                .reranks()
                .then(|| (reranker_models(config, name), true));
            for (models, rerank) in chat_routes.into_iter().chain(rerank_routes) {
                for model in &models {
                    let Ok(id) = engine_model_id(model, provider) else {
                        continue;
                    };
                    if let Ok(offer) = provider_offer(provider, id.clone(), rerank) {
                        snapshot.insert_offer(&offer);
                    }
                    configured.insert(id);
                }
            }
            for offer in configured_on_device_offers(name, provider, config) {
                snapshot.insert_offer(&offer);
            }
        }
        #[cfg(feature = "mesh")]
        match super::discovered::discovered_offers(vault) {
            Ok(offers) => {
                for offer in offers
                    .iter()
                    .filter(|offer| !configured.contains(&offer.model))
                {
                    snapshot.insert_offer(offer);
                }
            }
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "mesh model offers left out: the vault's discovery rows did not read");
            }
        }
        #[cfg(not(feature = "mesh"))]
        let _ = (vault, configured);
        snapshot
    }

    /// Each model the last mesh catalog refresh found, with the machine id
    /// of the owner's node that offers it and the ladder that serves it, in
    /// id order.
    pub(super) fn discovered_routes(&self) -> Vec<(ModelId, String, Arc<OfferLadder>)> {
        self.discovered()
            .iter()
            .filter_map(|(model, (_, ladder))| {
                let peer = ladder.first_provider()?.strip_prefix(MESH_ORIGIN)?;
                Some((model.clone(), peer.to_owned(), Arc::clone(ladder)))
            })
            .collect()
    }

    /// The routes the last mesh catalog refresh found.
    fn discovered(&self) -> Arc<Routes> {
        Arc::clone(
            &self
                .discovered
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// Serves `routes`, the models the owner's other nodes offer now, in
    /// place of the ones the last refresh found. An id a configured route
    /// serves keeps that route.
    #[cfg_attr(not(feature = "mesh"), allow(dead_code))]
    pub(super) fn discover(&self, mut routes: Routes) {
        routes.retain(|model, _| !self.routes.contains_key(model));
        *self
            .discovered
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(routes);
    }
}

/// The on-device offers of `provider`'s models a plain `serve` built from
/// `config` binds (I2-LOCAL), read from `config` alone: each model a chat
/// ladder names on `provider` that a row whose supervisor holds a native
/// launch slot serves (`WorkerConfig::has_native_launch`, the worker host's
/// own rule), as `build_native_local` and `native_rung` bind it; and each
/// model the reranker's ladder names on it that a `listen = "unix"` row
/// serves (`WorkerConfig::listens_on_socket`, L9-15), as `build_reranker`
/// binds it. No supervisor is made and nothing is launched.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn configured_on_device_offers(
    name: &str,
    provider: &ProviderConfig,
    config: &ModelsConfig,
) -> Vec<OfferBinding> {
    use super::catalog::catalog_entry;
    use super::offer::native_local_binding;

    let chat_rows = serving_rows(config, name, WorkerConfig::has_native_launch);
    let chat = super::speaks_native_local(provider)
        .then(|| referenced_models(config, name))
        .unwrap_or_default()
        .into_iter()
        .filter(|model| catalog_entry(model, provider).is_ok())
        .filter_map(|model| {
            let worker = chat_rows.get(model.model.as_str())?;
            let id = engine_model_id(&model, provider).ok()?;
            native_local_binding(provider, id, worker, false).ok()
        });
    let rerank_rows = serving_rows(config, name, WorkerConfig::listens_on_socket);
    let rerank = reranker_models(config, name)
        .into_iter()
        .filter_map(|model| {
            let worker = rerank_rows.get(model.model.as_str())?;
            let id = engine_model_id(&model, provider).ok()?;
            native_local_binding(provider, id, worker, true).ok()
        });
    chat.chain(rerank).collect()
}

/// The worker id that serves each wire model of provider `name`, among the
/// rows `serves` picks.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn serving_rows<'a>(
    config: &'a ModelsConfig,
    name: &str,
    serves: fn(&WorkerConfig) -> bool,
) -> BTreeMap<&'a str, &'a str> {
    config
        .workers
        .iter()
        .filter(|row| row.binding.provider == name && serves(row))
        .map(|row| (row.binding.model.as_str(), row.id.as_str()))
        .collect()
}

/// No native channel or socket here checks its peer against the supervised
/// child, so no model has an on-device view.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn configured_on_device_offers(
    _name: &str,
    _provider: &ProviderConfig,
    _config: &ModelsConfig,
) -> Vec<OfferBinding> {
    Vec::new()
}
