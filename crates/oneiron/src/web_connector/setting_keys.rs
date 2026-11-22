//! The web connector's owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use super::MAX_RESULTS_CAP;
use crate::setting::{Kind, PageMax, lower_is_tighter};

/// 10 results: a search's maximum before it became a key.
fn search_max_results_default() -> PageMax {
    PageMax(MAX_RESULTS_CAP)
}

crate::setting::setting_keys! {
    /// The most results one `connector.web.search` returns when the owner's own provider key
    /// pays for it (default 10; restriction wave 19, C73 = B). Each call is also cut to its
    /// provider's documented maximum (Tavily and Brave 20; Exa, context.dev and Octen 100;
    /// Tinyfish takes no count, so only this maximum bounds it). An ask that names no count is
    /// still served 5, and an ask of zero is served one. Calls on the deploy's backend key, our
    /// cash, keep 10. A hub connector's call is forwarded as asked before any of this, so this
    /// key never changes it. A maximum of zero is refused. A larger value is looser, so only the
    /// owner raises it; an agent's raise waits on the owner's answer.
    pub(crate) SEARCH_MAX_RESULTS: PageMax = "connectors.web.search_max_results" {
        kind: Kind::new(search_max_results_default)
            .strictest(search_max_results_default)
            .tighter(lower_is_tighter::<PageMax>),
    };
}
