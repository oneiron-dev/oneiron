//! The anchored-annotation Setting key (restriction wave 13, census C100; the owner's principle of
//! 16 Nov: an optional freedom with a good default): how many places one reattach offer lists.
//! The default is the count the sweep has always offered. The owner changes it; an agent's
//! change waits on the owner's approval.
//!
//! Direction: a lower count is tighter, since a search withholds every place past it. A row that
//! does not decode reads as one place. Whatever the count, nothing reattaches without a person's
//! click on one offered place (OF-368 = A).

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// The places one reattach offer has always listed.
const DEFAULT_MAX_OFFERS: u32 = 16;

/// How many places one reattach offer lists: at least 1.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct ReattachOfferLimit(pub(crate) u32);

impl SettingValue for ReattachOfferLimit {
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "a reattach offer lists at least 1 place".to_owned(),
            ))
        }
    }
}

fn default_max_offers() -> ReattachOfferLimit {
    ReattachOfferLimit(DEFAULT_MAX_OFFERS)
}

fn fewest_offers() -> ReattachOfferLimit {
    ReattachOfferLimit(1)
}

crate::setting::setting_keys! {
    /// Places one reattach offer lists for a detached comment whose words return (default 16).
    /// Lower is tighter: each search (a sheet, a Word document, a deck, HTML, plain text or a
    /// code tree) withholds every place past this count. A person still picks the place, and
    /// nothing reattaches without that click.
    pub(crate) ANCHORED_ANNOTATION_REATTACH_MAX_OFFERS: ReattachOfferLimit =
        "anchored_annotation.reattach.max_offers" {
        kind: Kind::new(default_max_offers)
            .strictest(fewest_offers)
            .tighter(lower_is_tighter::<ReattachOfferLimit>),
    };
}

/// The places one reattach offer lists in `txn`, at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub(super) fn reattach_max_offers_in_txn(vault: &Vault, txn: &RoTxn<'_>) -> Result<usize> {
    let limit = ANCHORED_ANNOTATION_REATTACH_MAX_OFFERS
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0;
    Ok(usize::try_from(limit).unwrap_or(usize::MAX))
}
