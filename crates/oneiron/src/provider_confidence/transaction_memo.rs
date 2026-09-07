//! Successful prior resolutions reused only within one scoring transaction.

use std::collections::HashMap;

use crate::error::Result;

/// One transaction's provider priors, including resolved neutral absence.
///
/// Create this inside the write transaction and discard it before that
/// transaction ends. The scoring pass may repair disposable indexes, but it
/// must not change provider actors or prior CLAIM truth while using this memo.
/// Nothing here is persisted or shared with another evaluation.
#[derive(Default)]
pub(crate) struct ProviderPriorMemo {
    resolved: HashMap<String, Option<f32>>,
}

impl ProviderPriorMemo {
    /// Resolve an exact provider key once. `None` is a successful resolution;
    /// an error is propagated and leaves no entry, never a neutral fallback.
    pub(super) fn resolve(
        &mut self,
        provider: &str,
        resolve: impl FnOnce() -> Result<Option<f32>>,
    ) -> Result<Option<f32>> {
        if let Some(&prior) = self.resolved.get(provider) {
            return Ok(prior);
        }
        let prior = resolve()?;
        self.resolved.insert(provider.to_owned(), prior);
        Ok(prior)
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderPriorMemo;
    use crate::error::Error;
    use std::collections::HashMap;

    #[test]
    fn resolves_each_exact_provider_once_including_neutral_and_zero() {
        let mut memo = ProviderPriorMemo::default();
        let mut resolutions = HashMap::new();
        let providers = [
            ("provider_neutral", None),
            ("provider_prior", Some(0.25)),
            ("provider_zero", Some(0.0)),
            ("PROVIDER_NEUTRAL", Some(1.0)),
        ];

        // Interleave providers so reuse must be keyed, not just the last result.
        for _ in 0..3 {
            for (provider, expected) in providers {
                let actual = memo
                    .resolve(provider, || {
                        *resolutions.entry(provider).or_insert(0) += 1;
                        Ok(expected)
                    })
                    .expect("successful prior resolution");
                assert_eq!(actual, expected);
            }
        }
        assert_eq!(resolutions.len(), providers.len());
        for (provider, _) in providers {
            assert_eq!(
                resolutions[provider], 1,
                "{provider} resolved more than once"
            );
        }
    }

    #[test]
    fn resolution_errors_remain_typed_and_are_not_memoized_as_absence() {
        let mut memo = ProviderPriorMemo::default();
        let mut resolutions = 0;
        for _ in 0..2 {
            let error = memo
                .resolve("provider_broken", || {
                    resolutions += 1;
                    Err(Error::InvalidClaimBody("unreadable prior"))
                })
                .expect_err("an unreadable prior must not read neutral");
            assert!(matches!(error, Error::InvalidClaimBody("unreadable prior")));
        }
        assert_eq!(resolutions, 2);
        assert!(memo.resolved.is_empty());
    }

    #[test]
    fn a_fresh_memo_resolves_again_after_neutral_or_positive_prior() {
        for previous in [None, Some(0.50)] {
            let mut first = ProviderPriorMemo::default();
            assert_eq!(
                first
                    .resolve("provider", || Ok(previous))
                    .expect("first resolution"),
                previous
            );

            let mut next = ProviderPriorMemo::default();
            let mut resolutions = 0;
            let current = next
                .resolve("provider", || {
                    resolutions += 1;
                    Ok(Some(0.25))
                })
                .expect("next transaction resolves independently");
            assert_eq!(current, Some(0.25));
            assert_eq!(resolutions, 1);
        }
    }
}
