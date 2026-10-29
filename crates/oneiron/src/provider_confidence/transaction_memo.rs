//! Successful prior resolutions reused only within one scoring transaction.

use std::collections::HashMap;

use super::indexes::ProviderPrior;
use crate::error::Result;

/// One transaction's provider priors, including resolved neutral absence and
/// a resolved unresolved-by-split status (FIX 10530).
///
/// Create this inside the write transaction and discard it before that
/// transaction ends. The scoring pass may repair disposable indexes, but it
/// must not change provider actors or prior CLAIM truth while using this memo.
/// Nothing here is persisted or shared with another evaluation.
#[derive(Default)]
pub(crate) struct ProviderPriorMemo {
    resolved: HashMap<String, ProviderPrior>,
}

impl ProviderPriorMemo {
    /// Resolve an exact provider key once. Every [`ProviderPrior`] is a
    /// successful resolution; an error is propagated and leaves no entry,
    /// never a neutral fallback.
    pub(super) fn resolve(
        &mut self,
        provider: &str,
        resolve: impl FnOnce() -> Result<ProviderPrior>,
    ) -> Result<ProviderPrior> {
        if let Some(&prior) = self.resolved.get(provider) {
            return Ok(prior);
        }
        let prior = resolve()?;
        self.resolved.insert(provider.to_owned(), prior);
        Ok(prior)
    }
}
