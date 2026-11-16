//! The setting keys `code_run` declares (restriction wave 17): the crate's build script lists
//! each row in the setting catalogue.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// The most a result search may show on each side of a match unless the owner sets it.
pub(crate) const DEFAULT_SEARCH_CONTEXT_BYTES: u64 = 1024;

/// The largest bound the key takes. One match's entry, its text and both contexts, must fit
/// one reply even when every byte is escaped six-fold in JSON; past this a search could stop at
/// a match without moving, and ask for the same match again.
pub(crate) const MAX_SEARCH_CONTEXT_BYTES: u64 = 32 * 1024;

/// Bytes of context a result search shows at most on each side of a match.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct SearchContextBytes(pub(crate) u64);

impl SettingValue for SearchContextBytes {
    fn check(self) -> Result<Self> {
        if self.0 <= MAX_SEARCH_CONTEXT_BYTES {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(format!(
                "a result search shows at most {MAX_SEARCH_CONTEXT_BYTES} bytes of context, so \
                 one match always fits a reply"
            )))
        }
    }
}

const fn default_search_context() -> SearchContextBytes {
    SearchContextBytes(DEFAULT_SEARCH_CONTEXT_BYTES)
}

crate::setting::setting_keys! {
    /// Bytes of context a result search shows at most on each side of a match, whatever the
    /// search asks: 1024 unless the owner sets it, and never past 32768. A search that names no
    /// context gets 80, inside this bound.
    pub(crate) RESULT_SEARCH_MAX_CONTEXT: SearchContextBytes = "code_run.result_search.max_context" {
        kind: Kind::new(default_search_context).tighter(lower_is_tighter),
    };
}

/// The owner's `code_run.result_search.max_context` for a read on `vault`.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn result_search_max_context(vault: &Vault) -> Result<usize> {
    let txn = vault.store.env.read_txn()?;
    let bytes = RESULT_SEARCH_MAX_CONTEXT
        .read_in_txn(vault, &txn, &[], None)?
        .value
        .0;
    Ok(usize::try_from(bytes).unwrap_or(usize::MAX))
}
