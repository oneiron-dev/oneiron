//! A call-local view of the models its reader inherited from the agent.

use oneiron::agent_def::ensure_inherited_model_list;

use super::*;

impl OfferLadder {
    /// Keeps every allowed rung, in order and at its original position.
    /// An empty inherited list leaves the model choice unconstrained.
    pub(crate) fn for_model_list(&self, listed: &[AgentModel]) -> oneiron::Result<Self> {
        let mut refused = None;
        let rungs: Vec<_> = self
            .rungs
            .iter()
            .filter_map(
                |rung| match ensure_inherited_model_list(listed, &rung.model) {
                    Ok(()) => Some(rung.clone()),
                    Err(error) => {
                        refused = Some(error);
                        None
                    }
                },
            )
            .collect();
        if rungs.is_empty()
            && let Some(error) = refused
        {
            return Err(error);
        }
        Ok(Self {
            name: self.name.clone(),
            rungs,
            picked: self.picked,
            rests: Arc::clone(&self.rests),
            scope: self.scope,
            prefix: self.prefix.clone(),
            listed: (!listed.is_empty()).then(|| Arc::from(listed)),
        })
    }

    pub(super) fn admits_listed_model(&self, model: &ModelId) -> bool {
        self.listed
            .as_deref()
            .is_none_or(|listed| ensure_inherited_model_list(listed, model).is_ok())
    }

    /// Eligibility reads the filtered view; the actual fallback clone still
    /// enumerates the original target so receipt positions never compact.
    pub(super) fn listed_fallback(&self, original: Arc<Self>) -> Option<(Arc<Self>, Arc<Self>)> {
        let view = match &self.listed {
            Some(listed) => Arc::new(original.for_model_list(listed).ok()?),
            None => Arc::clone(&original),
        };
        Some((original, view))
    }
}
