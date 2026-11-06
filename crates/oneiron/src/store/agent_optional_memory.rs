//! How much optional recall a reader takes, per task family (ZERO-RETRIEVAL
//! = A, ARCH-0004 #reader-budget): the setting for one family, and a
//! reader's default with the families that differ.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use crate::store::context_field_profile::FieldProfile;

/// One reader's optional recall for one task family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionalMemory {
    /// No optional recall. Not a budget of 0, which means no limit.
    None,
    /// At most `tokens` of optional recall, at `view` detail or less.
    Budget {
        tokens: NonZeroU64,
        view: FieldProfile,
    },
}

/// A reader's optional recall: a default, and the task families that differ.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OptionalMemoryProfile {
    pub default: OptionalMemory,
    pub families: BTreeMap<String, OptionalMemory>,
}
