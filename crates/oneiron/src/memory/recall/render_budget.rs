//! The token budget a rendered pack is cut to (FIX 9962): one resolver for
//! every door that renders a recall or a chat's documents.

use super::*;

/// The rendering budget, in the one order every door takes: the caller's
/// own `token_budget`; else the window budget of the reader whose memory
/// profile the caller opted into; else [`RECALL_TOKEN_BUDGET`].
pub(crate) fn render_token_budget(explicit: Option<u64>, reader: Option<u64>) -> usize {
    explicit
        .or(reader)
        .map_or(RECALL_TOKEN_BUDGET, |budget| {
            usize::try_from(budget).unwrap_or(usize::MAX)
        })
}

/// The budget an execution renders under: the one its door resolved, else
/// [`RECALL_TOKEN_BUDGET`].
pub(crate) fn execution_render_budget(
    execution: &crate::retrieval_depth::RecallExecution<'_>,
) -> usize {
    execution.render_budget.unwrap_or(RECALL_TOKEN_BUDGET)
}

impl Memory<'_> {
    /// The rendering budget a request asks for, by [`render_token_budget`].
    /// A `token_budget` of 0 renders the pack uncut, as the serializer reads
    /// 0. `reader_agent_ref` names an agent definition whose memory profile
    /// sizes the pack when the caller gives no budget of its own. It is read
    /// through the caller's own lane, so it grants nothing; a ref that names
    /// no definition this caller reads, or one with no memory profile, adds
    /// no budget, and the order goes on to the default. A rendering hint
    /// never refuses the recall.
    pub(crate) fn recall_render_budget(
        &self,
        token_budget: Option<u64>,
        reader_agent_ref: Option<&str>,
    ) -> usize {
        let reader = match (token_budget, reader_agent_ref) {
            (None, Some(reference)) => self.reader_window_budget(reference),
            _ => None,
        };
        render_token_budget(token_budget, reader)
    }

    /// The window budget of the memory profile the agent definition at
    /// `reference` carries, read as this caller reads; `None` when the caller
    /// reads no such definition or it carries no profile.
    fn reader_window_budget(&self, reference: &str) -> Option<u64> {
        let id = self.resolve_ref(reference).ok()?;
        let lane = self.read_lane(ClaimReadStatus::Recorded).ok()?;
        let row = lane
            .read(&[PointRead::id(id)], None)
            .ok()?
            .value
            .into_iter()
            .next()
            .flatten()
            .filter(|row| row.entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF)?;
        let definition = crate::agent_def::decode_agent_definition(&row.body?).ok()?;
        definition
            .memory_profile
            .map(|profile| profile.window_token_budget)
    }
}
