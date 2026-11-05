//! Values paired with the scope receipt of the read that produced them.
use oneiron_contracts::claim::ScopedReadReceipt;
use serde::{Deserialize, Serialize};

/// Values and the narrowing receipt from one scoped read.
///
/// Borrowing the value leaves the receipt available. Consuming the wrapper as
/// bare rows is not supported: projections must explicitly preserve the receipt.
///
/// ```compile_fail
/// use oneiron::claim::ScopedReadResult;
/// fn bare_rows(result: ScopedReadResult<Vec<u8>>) {
///     for row in result {
///         let _ = row;
///     }
/// }
/// ```
///
/// ```compile_fail
/// use oneiron::claim::ScopedReadResult;
/// fn bare_rows(result: ScopedReadResult<Vec<u8>>) -> Vec<u8> {
///     result.into_iter().collect()
/// }
/// ```
///
/// On the wire the pair is `{"value": .., "narrowing": ..}`: `narrowing` is the
/// one name every read result gives its receipt.
#[must_use = "scoped results include a mandatory narrowing receipt"]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScopedReadResult<T> {
    pub value: T,
    #[serde(rename = "narrowing")]
    pub receipt: ScopedReadReceipt,
}

impl<T> ScopedReadResult<T> {
    /// Project the value; the receipt travels with the projection.
    pub fn map<U>(self, project: impl FnOnce(T) -> U) -> ScopedReadResult<U> {
        ScopedReadResult {
            value: project(self.value),
            receipt: self.receipt,
        }
    }
}

impl<T> ScopedReadResult<Vec<Option<T>>> {
    /// The first slot of a one-read slice, under the slice's receipt.
    pub fn single(self) -> ScopedReadResult<Option<T>> {
        self.map(|slots| slots.into_iter().next().flatten())
    }
}
impl<T> std::ops::Deref for ScopedReadResult<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
