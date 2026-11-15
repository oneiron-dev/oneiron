//! The owner Setting keys of the owner's support grant list and hook replay pages (DESIGN
//! 15-setting-primitive): rows the setting catalogue reads from this file. Each default is the
//! fixed bound these verbs had before; a larger value loosens, so an agent holding a key's set
//! line asks the owner before it raises one.

use std::num::NonZeroU32;

use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{Kind, Setting, lower_is_tighter};

/// `vault.support_grants.list`'s default page: 500 grants.
fn support_grants_list_page_max() -> NonZeroU32 {
    NonZeroU32::new(500).unwrap_or(NonZeroU32::MIN)
}

/// `vault.hooks.replay`'s default page: 256 entries.
fn hooks_replay_page_max() -> NonZeroU32 {
    NonZeroU32::new(256).unwrap_or(NonZeroU32::MIN)
}

crate::setting::setting_keys! {
    /// The most support grants one `vault.support_grants.list` call answers, newest first. The
    /// list has no cursor, so a grant past it is not listed. 500 by default.
    pub(crate) SUPPORT_GRANTS_LIST_PAGE_MAX: NonZeroU32 = "support_grants.list.page_max" {
        kind: Kind::new(support_grants_list_page_max)
            .strictest(support_grants_list_page_max)
            .tighter(lower_is_tighter::<NonZeroU32>),
    };
    /// The most entries one `vault.hooks.replay` page holds, each a dry run of the hook's body in
    /// the host's sandbox; a larger `limit` is served a page at a time through `next_cursor`. 256
    /// by default.
    pub(crate) HOOKS_REPLAY_PAGE_MAX: NonZeroU32 = "hooks.replay.page_max" {
        kind: Kind::new(hooks_replay_page_max)
            .strictest(hooks_replay_page_max)
            .tighter(lower_is_tighter::<NonZeroU32>),
    };
}

/// The rows a page of `key`'s list serves at most: the vault's value, in a read of its own.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn page_max(vault: &Vault, key: &Setting<NonZeroU32>) -> Result<usize> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let rows = key.read_in_txn(vault, &txn, &[], None)?.value;
    Ok(usize::try_from(rows.get()).unwrap_or(usize::MAX))
}
