//! The `error` member that ends an `embedder serve` answer a later batch
//! could not complete (FIX 10702), which this client asks for.

use super::EMBEDDER_TOOL;

/// The `error` member an unfinished answer ends with. Only its code is
/// read: a remote picks its own message, which could hold text it has read.
#[derive(serde::Deserialize)]
pub(super) struct AnswerError {
    #[serde(default)]
    code: Option<String>,
}

impl AnswerError {
    /// The failure the vault reports for an answer that ended after `rows`
    /// of its `expected` rows, naming the code `embedder serve` sends and
    /// nothing else the remote wrote.
    pub(super) fn failure(&self, rows: usize, expected: usize) -> oneiron::Error {
        let reason = match self.code.as_deref() {
            Some("embedding_failed") => "the model could not embed a later batch",
            Some("encoding_failed") => "a later batch could not be encoded",
            _ => "a later batch failed",
        };
        oneiron::Error::UpstreamToolFailure {
            tool: EMBEDDER_TOOL,
            code: format!(
                "embedder endpoint ended its answer after {rows} of {expected} rows: {reason}"
            ),
        }
    }
}
