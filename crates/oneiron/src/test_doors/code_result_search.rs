//! The code-run result search over caller-held text (restriction wave 17,
//! `code_run.result_search.max_context`): the door the key's tests read
//! through.

/// Searches `text` as a text result under the vault's own search context
/// bound, and answers the search's output value.
///
/// # Errors
///
/// Storage errors, and the search's own refusal as an invariant: the door
/// asks nothing a search denies or spills.
#[cfg(feature = "test-support")]
pub fn search_text(
    vault: &crate::Vault,
    text: &str,
    input: serde_json::Value,
) -> crate::Result<serde_json::Value> {
    crate::code_run::search_text_for_test(vault, text, input)
}
