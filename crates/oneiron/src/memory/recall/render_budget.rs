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
    /// The rendering budget a recall request asks for, by
    /// [`render_token_budget`]. `reader_agent_ref` names an agent definition
    /// whose memory profile sizes the pack when the caller gives no budget of
    /// its own; it is read through the caller's own lane, so it grants
    /// nothing: a definition the caller cannot read is refused as one that
    /// names nothing, and one with no memory profile adds no budget.
    ///
    /// # Errors
    /// A zero `token_budget`, or a `reader_agent_ref` that names no agent
    /// definition this caller reads.
    pub(crate) fn recall_render_budget(
        &self,
        token_budget: Option<u64>,
        reader_agent_ref: Option<&str>,
    ) -> MemoryResult<usize> {
        if token_budget == Some(0) {
            return Err(MemoryError::bad_request(
                "token_budget must be at least 1",
            ));
        }
        let reader = match (token_budget, reader_agent_ref) {
            (None, Some(reference)) => self.reader_window_budget(reference)?,
            _ => None,
        };
        Ok(render_token_budget(token_budget, reader))
    }

    /// The window budget of the memory profile the agent definition at
    /// `reference` carries, read as this caller reads.
    fn reader_window_budget(&self, reference: &str) -> MemoryResult<Option<u64>> {
        let unread = || MemoryError::not_found("reader_agent_ref names no agent definition");
        let id = self.resolve_ref(reference).map_err(|_| unread())?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let row = lane
            .read(&[PointRead::id(id)], None)?
            .value
            .into_iter()
            .next()
            .flatten()
            .filter(|row| row.entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF)
            .ok_or_else(unread)?;
        let body = row.body.ok_or_else(unread)?;
        let definition = crate::agent_def::decode_agent_definition(&body)?;
        Ok(definition
            .memory_profile
            .map(|profile| profile.window_token_budget))
    }
}
