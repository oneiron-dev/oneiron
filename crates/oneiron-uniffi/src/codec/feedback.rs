//! Owned feedback-bundle output for the preview binding.

use oneiron::task_verb::sdk::FeedbackSubjectPreview;

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<FeedbackSubjectPreview> for crate::FeedbackSubjectPreview {
    fn lift(mut value: FeedbackSubjectPreview) -> Result<Self, OneironError> {
        let bundle = WireJson::lift(std::mem::take(&mut value.bundle))?;
        let mut output: Self = lift_record("feedback.preview", &value)?;
        output.bundle = bundle;
        Ok(output)
    }
}
