//! Door for `tests/web_search_owner_max.rs` (restriction wave 19, C73 = B): the
//! result count one web search sends its provider, as `call_listing` resolves
//! it before the call goes out.

use oneiron::web_connector::{WebKeySource, WebProvider, WebSearchInput};
use oneiron::{Result, Vault};

/// The count a search on `provider`, paid by `key_source`, asks its provider
/// for (`crate::web_connector::search_count`).
///
/// # Errors
///
/// Storage errors reading the owner's key.
pub fn search_count(
    vault: &Vault,
    key_source: WebKeySource,
    provider: WebProvider,
    input: &WebSearchInput,
) -> Result<u32> {
    crate::web_connector::search_count(vault, key_source, provider, input)
}
