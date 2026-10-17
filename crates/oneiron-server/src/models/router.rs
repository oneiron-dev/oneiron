//! Every configured model and seat by id: the raw `/v1/llm` routes call
//! whichever model they name, through its ladder and a run.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::{ModelId, ModelLocality};

use super::ladder::OfferLadder;

#[derive(Default)]
pub struct ModelRouter {
    routes: BTreeMap<ModelId, (ModelLocality, Arc<OfferLadder>)>,
    /// Each configured chat model served alone by its own id, and the family
    /// its provider's config names for it.
    chat: BTreeMap<ModelId, Option<String>>,
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

    /// Where `model` runs, when this router serves it. This is the host's
    /// attestation for the engine's inference admission.
    pub fn locality(&self, model: &ModelId) -> Option<ModelLocality> {
        self.routes.get(model).map(|(locality, _)| *locality)
    }

    /// Where `model` runs and the ladder that serves it.
    pub fn served(&self, model: &ModelId) -> Option<(ModelLocality, Arc<OfferLadder>)> {
        self.routes
            .get(model)
            .map(|(locality, ladder)| (*locality, Arc::clone(ladder)))
    }
}
