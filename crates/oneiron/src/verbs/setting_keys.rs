//! The verbs' owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue reads
//! from this file.

use super::files::MAX_FILES_PAGE_LIMIT;
use super::host::HOOKS_REPLAY_PAGE_MAX;
use super::support_grant::SUPPORT_GRANT_LIST_MAX;
use crate::setting::{Kind, PageMax, lower_is_tighter};

/// 1,000 files: a Files listing's maximum page before it became a key (FIX 10247).
fn files_page_max_default() -> PageMax {
    PageMax(u32::try_from(MAX_FILES_PAGE_LIMIT).unwrap_or(u32::MAX))
}

/// 500 grants: a support grant listing's maximum before it became a key.
fn support_grant_list_max_default() -> PageMax {
    PageMax(u32::try_from(SUPPORT_GRANT_LIST_MAX).unwrap_or(u32::MAX))
}

/// 256 entries: a hook replay page's maximum before it became a key (FIX 8629).
fn hooks_replay_page_max_default() -> PageMax {
    PageMax(u32::try_from(HOOKS_REPLAY_PAGE_MAX).unwrap_or(u32::MAX))
}

crate::setting::setting_keys! {
    /// The most files one `vault.files.sources.files` page holds (default 1,000). An ask for more
    /// is served this many, with a cursor to the rest; an ask that names no limit is still served
    /// 200, and an ask of zero is served one file. A maximum of zero is refused. A larger value
    /// is looser, so only the owner raises it; an agent's raise waits on the owner's answer.
    pub(crate) FILES_PAGE_MAX: PageMax = "verbs.files.max_page_limit" {
        kind: Kind::new(files_page_max_default)
            .strictest(files_page_max_default)
            .tighter(lower_is_tighter::<PageMax>),
    };

    /// The most support grants one `vault.support_grants.list` answers (default 500). An ask for
    /// more is served this many; an ask that names no limit is still served at most 500. A
    /// maximum of zero is refused. A larger value is looser, so only the owner raises it; an
    /// agent's raise waits on the owner's answer.
    pub(crate) SUPPORT_GRANT_LIST_MAX_KEY: PageMax = "verbs.support_grant.list_max" {
        kind: Kind::new(support_grant_list_max_default)
            .strictest(support_grant_list_max_default)
            .tighter(lower_is_tighter::<PageMax>),
    };

    /// The most entries one `vault.hooks.replay` page holds (default 256); a larger limit is
    /// still served a page at a time through `next_cursor`. A maximum of zero is refused. A
    /// larger value is looser, so only the owner raises it; an agent's raise waits on the
    /// owner's answer.
    pub(crate) HOOKS_REPLAY_PAGE_MAX_KEY: PageMax = "verbs.hooks_replay.page_max" {
        kind: Kind::new(hooks_replay_page_max_default)
            .strictest(hooks_replay_page_max_default)
            .tighter(lower_is_tighter::<PageMax>),
    };
}
