//! Owned opaque leaves for the browser batch's complete answer (FIX 12936).

use oneiron::task_verb::sdk::BrowserBatchOutput;

use super::browser_answers::{lift_decisions, lift_image_release};
use super::{Lift, OneironError, lift_record};

impl Lift<BrowserBatchOutput> for crate::BrowserAnswerBatchOutput {
    fn lift(mut value: BrowserBatchOutput) -> Result<Self, OneironError> {
        // Finish every opaque leaf before a finite conversion can return early.
        let decisions = lift_decisions(std::mem::take(&mut value.answer.decisions));
        let image_release = lift_image_release(
            value
                .session_manifest
                .as_mut()
                .and_then(|manifest| manifest.image_release.take()),
        );
        let decisions = decisions?;
        let image_release = image_release?;

        // Both opaque fields are now empty; retain the shared finite wire shape.
        let mut output: Self = lift_record("self.browser.batch", &value)?;
        output.flattened.decisions = decisions;
        if let Some(manifest) = &mut output.session_manifest {
            manifest.image_release = image_release;
        }
        Ok(output)
    }
}
