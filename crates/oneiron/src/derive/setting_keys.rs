//! The setting keys `derive` declares (restriction wave 8): the crate's build script lists each row
//! in the setting catalogue.

use super::batch::{DerivationBatchCap, MAX_BATCH_ITEMS};
use crate::setting::{Kind, lower_is_tighter};

fn default_batch_cap() -> DerivationBatchCap {
    DerivationBatchCap(u32::try_from(MAX_BATCH_ITEMS).unwrap_or(u32::MAX))
}

crate::setting::setting_keys! {
    /// The most items one derivation batch holds: a larger batch is malformed and its commit aborts
    /// whole; each item is still judged alone in its own savepoint. At least 256, the size the
    /// engine's own jobs fill.
    pub(crate) BATCH_MAX_ITEMS: DerivationBatchCap = "derive.batch.max_items" {
        kind: Kind::new(default_batch_cap).tighter(lower_is_tighter::<DerivationBatchCap>),
    };
}
