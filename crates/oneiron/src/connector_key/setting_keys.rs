//! The setting keys `connector_key` declares (restriction wave 17): the crate's build script
//! lists each row in the setting catalogue.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// How many memory rows one turn through the OpenAI-compatible proxy recalls unless the owner
/// sets it.
const DEFAULT_OPENAI_PROXY_RECALL_LIMIT: u32 = 8;

/// The most memory rows one proxied turn recalls: at least 1, because recall refuses a limit of
/// 0 and every proxied turn would then fail.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct ProxyRecallRows(pub(crate) u32);

impl SettingValue for ProxyRecallRows {
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "a proxied turn recalls at least one row: recall refuses a limit of 0".into(),
            ))
        }
    }
}

const fn default_openai_proxy_recall_limit() -> ProxyRecallRows {
    ProxyRecallRows(DEFAULT_OPENAI_PROXY_RECALL_LIMIT)
}

crate::setting::setting_keys! {
    /// How many memory rows each turn through the OpenAI-compatible proxy recalls at most: 8
    /// unless the owner sets it, at least 1. The rows reach the proxied model as data, under the
    /// same read destination checks as before; only how many may come changes.
    pub(crate) OPENAI_PROXY_RECALL_LIMIT: ProxyRecallRows = "proxy.openai.recall_limit" {
        kind: Kind::new(default_openai_proxy_recall_limit).tighter(lower_is_tighter),
    };
}

/// The owner's `proxy.openai.recall_limit` on `vault`: the most memory rows one proxied turn
/// recalls.
///
/// # Errors
///
/// Storage errors.
pub fn openai_proxy_recall_limit(vault: &Vault) -> Result<usize> {
    let txn = vault.store.env.read_txn()?;
    let rows = OPENAI_PROXY_RECALL_LIMIT
        .read_in_txn(vault, &txn, &[], None)?
        .value
        .0;
    Ok(usize::try_from(rows).unwrap_or(usize::MAX))
}
