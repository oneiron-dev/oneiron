//! A call-local question target that keeps no crossings or traces.

impl super::LimitQuestions {
    pub(crate) fn unrecorded() -> Self {
        Self {
            discard: true,
            ..Self::default()
        }
    }
}
