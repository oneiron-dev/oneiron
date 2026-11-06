//! The same resource lines with a call-local unrecorded question target.

use super::*;

impl ModelHostBudgets {
    pub(in crate::models) fn unrecorded_view(&self) -> Self {
        let questions = Arc::new(LimitQuestions::unrecorded());
        let line = |source: &Arc<ReplyLine>| {
            Arc::new(ReplyLine {
                line: Arc::clone(&source.line),
                questions: Arc::clone(&questions),
            })
        };
        Self {
            media: line(&self.media),
            chat: line(&self.chat),
            #[cfg(feature = "mesh")]
            staging: self.staging.clone(),
        }
    }
}
