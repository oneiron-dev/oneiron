//! The feeds' owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue reads
//! from this file.

use super::FEED_READ_MAX_LIMIT;
use crate::setting::{Kind, PageMax, lower_is_tighter};

/// 256 entries: a feed read's maximum from each source before it became a key.
fn feed_read_max_default() -> PageMax {
    PageMax(u32::try_from(FEED_READ_MAX_LIMIT).unwrap_or(u32::MAX))
}

crate::setting::setting_keys! {
    /// The most entries one `vault.feeds.read` returns from each source (default 256). An ask
    /// for more is served this many, and the page says more remain; an ask that names no limit
    /// is still served 64. Zero is refused. A larger value is looser, so only the owner raises
    /// it; an agent's raise waits on the owner's answer.
    pub(crate) FEED_READ_MAX: PageMax = "feeds.read.max_per_source" {
        kind: Kind::new(feed_read_max_default)
            .strictest(feed_read_max_default)
            .tighter(lower_is_tighter::<PageMax>),
    };
}
