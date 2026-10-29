//! Each Dreamer model call's own source rows (FIX 6998). A call whose
//! input fixed code assembled from a complete, known set of rows sends on
//! its route bound to exactly those rows, so its permit and its metered
//! settlement carry them; any other call sends on its route as it is, its
//! sources unknown. Capture only: no call is refused, held or narrowed here.
use crate::entity_id::EntityId;
use crate::llm::LlmBackend;

/// A host route that can send one call under the rows its input was read
/// from: the host binds its run to them for that call alone, on the same
/// run, line and permits as the route's own backend.
pub trait SourcedBackend: Send + Sync {
    /// This route for one call whose input fixed code assembled from exactly
    /// `rows`, sorted and deduplicated.
    fn sourced(&self, rows: Vec<EntityId>) -> Box<dyn LlmBackend + '_>;
}

/// One call's backend: the route's own, or, when the host lends a sourced
/// route and the call knows its complete source rows, that route bound to
/// them. An unknown set keeps the route's own backend: unsourced, as before.
pub(in crate::dreamer_consolidation) struct CallBackend<'r> {
    base: &'r dyn LlmBackend,
    sourced: Option<Box<dyn LlmBackend + 'r>>,
}

impl<'r> CallBackend<'r> {
    /// `base`, bound through `route` to `rows` when both are known.
    pub(in crate::dreamer_consolidation) fn new(
        base: &'r dyn LlmBackend,
        route: Option<&'r dyn SourcedBackend>,
        rows: Option<Vec<EntityId>>,
    ) -> Self {
        let sourced = route.zip(rows).map(|(route, mut rows)| {
            rows.sort_unstable();
            rows.dedup();
            route.sourced(rows)
        });
        Self { base, sourced }
    }

    /// The backend this call sends on.
    pub(in crate::dreamer_consolidation) fn get(&self) -> &dyn LlmBackend {
        match &self.sourced {
            Some(sourced) => &**sourced,
            None => self.base,
        }
    }
}
