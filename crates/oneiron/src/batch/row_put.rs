//! What a put is to the row it writes, as the record-scope stamp reads it.
//! `federation::record_scope` re-exports [`RowPut`] at its old path.

/// What a put is to the row it writes: `federation::record_scope::stamp_put`
/// mints a first position for a row stored with none only at its local birth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowPut {
    /// A local put of a row not stored before it, or a sweep that settles a
    /// stored row's first position.
    Birth,
    /// A local put of a row stored before it: a row stored with no position,
    /// as a replicated row is, keeps none (FIX 11925).
    LocalReput,
    /// A peer's replicated row.
    Replicated,
}
