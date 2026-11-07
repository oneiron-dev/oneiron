use super::*;

impl<'a, E> ScopeSummaryExecutor<'a, E> {
    #[must_use]
    pub fn new(
        inner: E,
        backend: &'a dyn LlmBackend,
        guard: &'a BudgetGuard,
        actor: WriteActor,
        model: ModelId,
        inference: HostInferenceContext<'a>,
        instruction: Option<&'a str>,
    ) -> Self {
        Self {
            inner,
            backend,
            guard,
            actor,
            model,
            inference,
            instruction,
            window_tokens: None,
            arc_decisions: None,
        }
    }

    /// Lends Arc opening the host's typed ladder and its verdict role.
    /// Whole inputs on routes with no staffed stronger rung can pre-open a
    /// TURN. Larger inputs, review cells and stronger ladders keep the
    /// narrative reader until their typed read has its own paging and pace.
    #[must_use]
    pub fn with_arc_decisions(
        mut self,
        decisions: super::super::executor::ConsolidationDecisions,
        roles: super::super::RoleBackends,
    ) -> Self {
        self.arc_decisions = Some((decisions, roles));
        self
    }

    /// The tokens one call's input may fill on the model, lent by the host
    /// (FIX 7509 P7b): a sitting too big for one call pages its TURNs to it.
    #[must_use]
    pub fn with_window_tokens(mut self, window_tokens: Option<u64>) -> Self {
        self.window_tokens = window_tokens;
        self
    }
}
