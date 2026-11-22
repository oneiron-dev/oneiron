//! The value of a list's page-maximum key: the most rows one page of that list serves
//! (restriction wave 19, owner 16 Nov 00:44: "we apply the optional freedom with good defaults
//! everywhere"). Each key's default is the list's maximum before it became a key, so no page
//! changes until the owner moves it.

use oneiron_contracts::error::{Error, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{Setting, SettingValue};
use crate::Vault;

/// The most rows one page of a list serves. Zero is refused: a list whose maximum is zero would
/// serve no row to any ask. A larger value is the looser one ([`super::lower_is_tighter`]).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct PageMax(pub u32);

impl PageMax {
    /// The maximum as a row count.
    #[must_use]
    pub fn rows(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

impl SettingValue for PageMax {
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            Err(Error::InvalidConfig(
                "a page maximum is at least one row".into(),
            ))
        } else {
            Ok(self)
        }
    }
}

impl Vault {
    /// The page maximum in force for `key`, read in its own read transaction: the owner's row,
    /// a key holder's tighter row within it, or the key's default (the list's maximum before it
    /// became a key) when no row stands.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn page_max_in_force(&self, key: &Setting<PageMax>) -> crate::Result<PageMax> {
        let txn = self.store.env.read_txn()?;
        Ok(key.read_in_txn(self, &txn, &[], None)?.value)
    }
}
