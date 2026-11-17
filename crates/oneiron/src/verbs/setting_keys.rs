//! The verbs' owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue reads
//! from this file.

use super::files::MAX_FILES_PAGE_LIMIT;
use crate::setting::{Kind, PageMax, lower_is_tighter};

/// 1,000 files: a Files listing's maximum page before it became a key (FIX 10247).
fn files_page_max_default() -> PageMax {
    PageMax(u32::try_from(MAX_FILES_PAGE_LIMIT).unwrap_or(u32::MAX))
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
}
