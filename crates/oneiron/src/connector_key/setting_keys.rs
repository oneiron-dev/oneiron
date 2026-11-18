//! The setting keys `connector_key` declares: the crate's build script lists each row in the
//! setting catalogue. The connector slate drafter's owner key (DESIGN 15-setting-primitive;
//! restriction census C46, Engine RULING RESTRICTION-WAVE-6-CANON-ROWS 16 Nov 03:35, C46 = A)
//! and the OpenAI-compatible proxy's recall limit (restriction wave 17).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};

/// Off: drafts pre-fill `always ask` or `never allow` only, as ARCH-0072 says.
fn drafts_never_offer() -> bool {
    false
}

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
    /// Whether a connector's admission and drift drafts may pre-fill `always allow` (off by
    /// default). On, the drafter pre-fills it on a tool row only where the owner's past rulings
    /// show he chose `always allow` for every kind of call the tool makes, on at least two
    /// connectors and on more than half of those he ruled; tighter evidence still wins, and the
    /// elicitation row still starts at `auto`. A draft grants nothing: the slate is shown before
    /// anything is granted, and only the owner's stamp accepts the row (ARCH-0072). Turning the
    /// key off stops new such drafts; it does not change a slate already drafted. On is the
    /// looser value: only the owner sets it, and an agent's change waits on the owner's answer.
    pub(crate) DRAFTS_OFFER_ALWAYS_ALLOW: bool = "connectors.slate.drafts_offer_always_allow" {
        kind: Kind::new(drafts_never_offer)
            .strictest(drafts_never_offer)
            .tighter(lower_is_tighter::<bool>),
    };

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
