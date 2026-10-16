//! The single exported error type for the UniFFI head-contract surface.
//!
//! One variant with one shape means every foreign catch site sees the same
//! shape: a stable code string, a human message, and ordered remediation
//! hints. `suggestions` is never dropped, reordered, or folded into `message`,
//! and the failure is never encoded as JSON, a sentinel null, or an integer.

/// Every failure that crosses the generated foreign boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OneironError {
    /// A typed facade failure.
    #[error("{code}: {message}")]
    Failure {
        /// One of the core `MEMORY_CODE_*` strings; unknown future codes pass
        /// through losslessly rather than collapsing to a closed enum.
        code: String,
        /// Human-readable description of the failure.
        message: String,
        /// Ordered remediation hints, preserved verbatim.
        suggestions: Vec<String>,
        /// On a `WRONG_ROOT` refusal: the verb name the caller wrote.
        attempted: Option<String>,
        /// On a `WRONG_ROOT` refusal: the canonical verb to call instead.
        replacement: Option<String>,
        /// On a `WRONG_ROOT` refusal: where the replacement's schema lives.
        schema_ref: Option<String>,
    },
}

impl From<oneiron::MemoryError> for OneironError {
    fn from(error: oneiron::MemoryError) -> Self {
        let wrong_root = error.wrong_root.map(|correction| *correction);
        let (attempted, replacement, schema_ref) = match wrong_root {
            Some(correction) => (
                Some(correction.attempted),
                Some(correction.replacement),
                Some(correction.schema_ref),
            ),
            None => (None, None, None),
        };
        Self::Failure {
            code: error.code,
            message: error.message,
            suggestions: error.suggestions,
            attempted,
            replacement,
            schema_ref,
        }
    }
}
