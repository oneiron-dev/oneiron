//! The result search over one caller-held text, under the vault's own search
//! context bound (restriction wave 17, `code_run.result_search.max_context`):
//! the door `test_doors::code_result_search` opens for the key's tests.

use super::search::search;
use super::{ReadBounds, Reply, ResultBody};
use crate::Result;
use crate::code_run::CodeRunOutputKind;

/// One caller-held text as a result body: the whole text, borrowed only for
/// the current read. Shaped as the query facet's selection body is.
struct TestTextBody<'b>(&'b [u8]);

impl ResultBody for TestTextBody<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn kind(&self) -> CodeRunOutputKind {
        CodeRunOutputKind::Text
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let start = usize::try_from(offset)
            .unwrap_or(self.0.len())
            .min(self.0.len());
        let end = start.saturating_add(len).min(self.0.len());
        Ok(self.0[start..end].to_vec())
    }

    fn line_index(&self) -> Option<Vec<u64>> {
        None
    }

    fn base(&self) -> u64 {
        0
    }
}

/// Searches `text` as a text result under the vault's own search context
/// bound. The reply's own bound is the executor's, as a run's read takes it;
/// the context each match shows is the owner's
/// `code_run.result_search.max_context`.
pub(crate) fn search_text_for_test(
    vault: &crate::Vault,
    text: &str,
    input: serde_json::Value,
) -> Result<serde_json::Value> {
    let body = TestTextBody(text.as_bytes());
    let bounds = ReadBounds {
        reply_bytes: crate::engine_executor::RESULT_REPLY_INLINE_BYTES,
        watch: vault.limit_watch(),
        search_max_context: crate::code_run::setting_keys::result_search_max_context(vault)?,
    };
    match search(&body, "test-result", input, &bounds)? {
        Reply::Output(value) => Ok(value),
        Reply::Denied(_) => Err(crate::error::Error::InvariantViolation(
            "the wave-17 search door asks nothing a search denies",
        )),
        Reply::Spilled { .. } => Err(crate::error::Error::InvariantViolation(
            "the wave-17 search door asks nothing a search spills",
        )),
    }
}
