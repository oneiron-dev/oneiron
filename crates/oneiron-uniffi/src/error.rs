//! The single exported error type for the UniFFI head-contract surface.
//!
//! One variant with three fields means every foreign catch site sees the same
//! shape: a stable code string, a human message, and ordered remediation
//! hints. `suggestions` is never dropped, reordered, or folded into `message`,
//! and the failure is never encoded as JSON, a sentinel null, or an integer.

/// Every failure that crosses the generated foreign boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OneironError {
    /// A typed facade failure.
    #[error("{code}: {message}")]
    Failure {
        /// One of the core `FACADE_CODE_*` strings; unknown future codes pass
        /// through losslessly rather than collapsing to a closed enum.
        code: String,
        /// Human-readable description of the failure.
        message: String,
        /// Ordered remediation hints, preserved verbatim.
        suggestions: Vec<String>,
    },
}

impl From<oneiron::FacadeError> for OneironError {
    fn from(error: oneiron::FacadeError) -> Self {
        Self::Failure {
            code: error.code,
            message: error.message,
            suggestions: error.suggestions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OneironError;

    #[test]
    fn facade_error_round_trip_preserves_all_fields() {
        let source = oneiron::FacadeError {
            code: oneiron::FACADE_CODE_BAD_REQUEST.to_owned(),
            message: "subject_ref is not a known entity".to_owned(),
            suggestions: vec!["first".to_owned(), "second".to_owned(), "third".to_owned()],
            successor_short_id: None,
        };
        let expected = source.clone();

        let OneironError::Failure {
            code,
            message,
            suggestions,
        } = OneironError::from(source);

        assert_eq!(code, expected.code);
        assert_eq!(message, expected.message);
        assert_eq!(suggestions, expected.suggestions);
    }

    #[test]
    fn facade_error_round_trip_keeps_empty_suggestions_empty() {
        let OneironError::Failure { suggestions, .. } = OneironError::from(oneiron::FacadeError {
            code: oneiron::FACADE_CODE_INTERNAL.to_owned(),
            message: "no hints".to_owned(),
            suggestions: Vec::new(),
            successor_short_id: None,
        });

        assert!(suggestions.is_empty());
    }

    #[test]
    fn exported_error_display_carries_code_and_message() {
        let error = OneironError::Failure {
            code: oneiron::FACADE_CODE_INVALID_STATE.to_owned(),
            message: "not wired".to_owned(),
            suggestions: Vec::new(),
        };

        assert_eq!(error.to_string(), "INVALID_STATE: not wired");
    }
}
