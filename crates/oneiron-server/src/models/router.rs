//! Every configured model and seat by id: the raw `/v1/llm` routes call
//! whichever model they name, through its ladder and a run.
use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError, RwLock};

use oneiron::{LlmCatalogEntry, ModelId, ModelLocality};

use super::ladder::OfferLadder;

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
