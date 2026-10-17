//! Model families (OF-184): the line of models one developer trains, as a
//! provider's config (`family`, `model_families`) or a registry row's
//! catalog names it, so a caller comparing two models can ask a third from
//! another family. A family nothing names is unknown, never guessed from a
//! provider, a proxy or a model id.
use std::collections::BTreeSet;

use oneiron::{ModelId, Vault};

use super::ModelRuntime;

impl ModelRuntime {
    /// The family `model` belongs to: its provider config's, else its
    /// registry row's. A seat is the one family every rung it serves
    /// shares; a seat mixing families, or with a rung of unknown family, has
    /// none.
    pub fn model_family(&self, vault: &Vault, model: &ModelId) -> oneiron::Result<Option<String>> {
        if let Some(seat) = self.seats.values().find(|seat| &seat.model == model) {
            let mut shared: Option<String> = None;
            for rung in seat.rungs.keys() {
                let Some(family) = self.model_family(vault, rung)? else {
                    return Ok(None);
                };
                match &shared {
                    Some(seen) if *seen != family => return Ok(None),
                    Some(_) => {}
                    None => shared = Some(family),
                }
            }
            return Ok(shared);
        }
        if let Some(family) = self
            .router
            .as_deref()
            .and_then(|router| router.family(model))
        {
            return Ok(Some(family.to_owned()));
        }
        Ok(vault
            .model_registry_row(model)?
            .and_then(|row| row.catalog.family().map(str::to_owned)))
    }

    /// Every chat model this server serves alone by its own id whose family
    /// is known and is none of `models`' families, in id order: the models
    /// a third opinion may come from. Empty when any of `models` has no
    /// known family, since then no pick is shown to be of another family.
    pub fn models_outside_families(
        &self,
        vault: &Vault,
        models: &[&ModelId],
    ) -> oneiron::Result<Vec<ModelId>> {
        let mut families = BTreeSet::new();
        for model in models {
            let Some(family) = self.model_family(vault, model)? else {
                return Ok(Vec::new());
            };
            families.insert(family);
        }
        let Some(router) = self.router.as_deref() else {
            return Ok(Vec::new());
        };
        let mut outside = Vec::new();
        for model in router.chat_models() {
            if self
                .model_family(vault, model)?
                .is_some_and(|family| !families.contains(&family))
            {
                outside.push(model.clone());
            }
        }
        Ok(outside)
    }
}
