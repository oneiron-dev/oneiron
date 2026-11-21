//! Budget configuration for the context pack builder: token budgets, model
//! windows, tokenizers and retrieval budgets.

use super::*;

impl ContextPackBuilder<'_> {
    /// Selects the pack tokenizer for every serialization budget gate
    /// (opt-in reader measurement). The default is the engine-normalized
    /// `o200k` counter; selection never changes authority, ranking, or row
    /// order.
    pub fn pack_tokenizer(mut self, tokenizer: PackTokenizer) -> Self {
        self.tokenizer = tokenizer;
        self
    }

    /// Declares the share of the active model's context window the default
    /// budget resolves from (ARCH-0004 #budget-unit, `{ contextFraction }`).
    /// Consulted only when neither an explicit [`Self::token_budget`] nor a
    /// memory profile set the budget, and only with a known model window
    /// ([`Self::model_window_tokens`] / [`Self::model_window`]). A fraction
    /// outside `(0, 1]` disables the derivation; above `1` counts as `1`.
    pub fn context_fraction(mut self, fraction: f32) -> Self {
        self.context_fraction = fraction;
        self
    }

    /// Names the active model's context window in tokens, for the
    /// window-relative default (see [`Self::context_fraction`]). `0` means
    /// unknown, like never calling this.
    pub fn model_window_tokens(mut self, window_tokens: u64) -> Self {
        self.model_window_tokens = (window_tokens > 0).then_some(window_tokens);
        self
    }

    /// Names the active model and resolves its context window from the
    /// vault's model registry, for the window-relative default (see
    /// [`Self::context_fraction`]). Best-effort: a model id that does not
    /// parse, has no registry row, or whose row does not read leaves the
    /// window unknown, and the budget falls back exactly as it did before
    /// this call existed. The catalog window is taken whole; the fraction
    /// is what leaves room for the prompt and the answer.
    pub fn model_window(mut self, model: &str) -> Self {
        self.model_window_tokens = None;
        let Ok(model) = model.parse::<ModelId>() else {
            return self;
        };
        match self.vault.model_registry_row(&model) {
            Ok(Some(row)) => {
                let window = row.catalog.context_window_tokens;
                self.model_window_tokens = (window > 0).then_some(window);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    %model,
                    %error,
                    "a context pack's model row did not read; its window is unknown"
                );
            }
        }
        self
    }

    /// Applies an agent's RT-05 memory profile as construction-time defaults
    /// (ONE-1687): the window budget and, when present, the per-class split.
    ///
    /// `None` is a NO-OP — today's defaults hold and the assembled pack is
    /// byte-for-byte what it was before the profile existed. An explicit
    /// [`Self::token_budget`] always wins over the profile's window budget,
    /// in either call order, so a per-request override always wins over the
    /// stored profile; [`Self::token_allocation`] still applies in call
    /// order.
    pub fn memory_profile(mut self, profile: Option<&MemoryProfile>) -> Self {
        let Some(profile) = profile else {
            return self;
        };
        self.profile_token_budget = Some(
            usize::try_from(profile.window_token_budget).unwrap_or(DEFAULT_WINDOW_TOKEN_BUDGET),
        );
        if let Some(split) = profile.budget_split {
            self.token_allocation = TokenAllocation {
                claims: split.claims,
                turns: split.turns,
                summaries: split.summaries,
                other: split.other,
            };
        }
        self
    }

    /// Takes no optional recall, for a reader whose profile picked
    /// [`OptionalMemory::None`] for this task (ARCH-0004 #reader-budget): the
    /// terminal returns an empty pack marked
    /// [`EmptyReason::SkippedByProfile`] before any retrieval or L2 work.
    /// Pinned rows and mandatory instructions never ride this pack; the host
    /// adds them as before.
    ///
    /// [`OptionalMemory::None`]: crate::agent_def::OptionalMemory::None
    /// [`EmptyReason::SkippedByProfile`]: crate::context_pack::EmptyReason::SkippedByProfile
    pub fn skip_optional_recall(mut self) -> Self {
        self.skip_optional_recall = true;
        self
    }

    /// The effective window budget after defaults and profile application.
    ///
    /// The ONE public read of the assembled budget, resolved at call time
    /// (ARCH-0004 #budget-unit): an explicit [`Self::token_budget`] wins,
    /// then a memory profile's window budget, then the declared
    /// [`Self::context_fraction`] of the active model's known window, and
    /// only when no window is known the fixed engine fallback — so a pack
    /// whose call site names no model assembles exactly as it did before
    /// the window-relative default existed. An explicit budget of `0`
    /// keeps its "no limit" meaning; a derived budget never resolves
    /// to `0`.
    #[must_use]
    pub fn effective_token_budget(&self) -> usize {
        if let Some(budget) = self.token_budget {
            return budget;
        }
        if let Some(budget) = self.profile_token_budget {
            return budget;
        }
        if let Some(window) = self.model_window_tokens
            && self.context_fraction.is_finite()
            && self.context_fraction > 0.0
        {
            let fraction = f64::from(self.context_fraction.min(1.0));
            #[allow(clippy::cast_precision_loss)]
            let derived = (window as f64 * fraction) as usize;
            return derived.max(1);
        }
        DEFAULT_WINDOW_TOKEN_BUDGET
    }

    pub fn token_allocation(mut self, allocation: TokenAllocation) -> Self {
        self.token_allocation = allocation;
        self
    }

    pub fn retrieval_budget(mut self, budget: ContextPackRetrievalBudget) -> Self {
        let selected_edges = budget.selected_edges;
        self.selected_edge_budget = selected_edges;
        self.retrieval_budget = Some(ContextPackRetrievalBudget {
            selected_edges,
            ..budget
        });
        self
    }

    pub fn max_field_chars(mut self, max: usize) -> Self {
        self.max_field_chars = max;
        self
    }

    pub fn max_item_tokens(mut self, max: usize) -> Self {
        self.max_item_tokens = max;
        self
    }
}
