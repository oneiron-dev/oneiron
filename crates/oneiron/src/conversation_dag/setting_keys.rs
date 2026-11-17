//! The conversation DAG's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use super::quote_strips::PAGE_LIMIT;
use crate::setting::{Kind, PageMax, lower_is_tighter};

/// 256 strips: a reply-strip page's maximum before it became a key.
fn reply_strips_page_max_default() -> PageMax {
    PageMax(u32::try_from(PAGE_LIMIT).unwrap_or(u32::MAX))
}

crate::setting::setting_keys! {
    /// The most reply strips one `vault.rooms.reply_strips` page holds (default 256). An ask
    /// for more is served this many, with `next_after` to the rest; an ask that names no limit
    /// is still served 256. Zero is refused. A larger value is looser, so only the owner raises
    /// it; an agent's raise waits on the owner's answer.
    pub(crate) REPLY_STRIPS_PAGE_MAX: PageMax = "conversation_dag.reply_strips.max_page" {
        kind: Kind::new(reply_strips_page_max_default)
            .strictest(reply_strips_page_max_default)
            .tighter(lower_is_tighter::<PageMax>),
    };
}
