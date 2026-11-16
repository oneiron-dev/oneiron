//! The setting keys `maintain` declares (restriction wave 17): the crate's build script lists
//! each row in the setting catalogue.

use crate::setting::{Kind, lower_is_tighter};

/// How many held facet-stamp receipts a maintenance report names unless the owner sets it.
const DEFAULT_FACET_RECEIPTS_SHOWN: u32 = 100;

const fn default_facet_receipts_shown() -> u32 {
    DEFAULT_FACET_RECEIPTS_SHOWN
}

crate::setting::setting_keys! {
    /// How many held facet-stamp receipts a maintenance report names: 100 unless the owner sets
    /// it; 0 names none. The total beside them is always counted whole.
    pub(crate) REPORT_FACET_RECEIPTS_SHOWN: u32 = "maintain.report.facet_receipts_shown" {
        kind: Kind::new(default_facet_receipts_shown).tighter(lower_is_tighter),
    };
}

/// The owner's `maintain.report.facet_receipts_shown` on `vault`.
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "sync")]
pub(super) fn facet_receipts_shown(vault: &crate::Vault) -> crate::error::Result<usize> {
    let txn = vault.store.env.read_txn()?;
    let shown = REPORT_FACET_RECEIPTS_SHOWN
        .read_in_txn(vault, &txn, &[], None)?
        .value;
    Ok(usize::try_from(shown).unwrap_or(usize::MAX))
}
