//! Owned opaque leaves for the browser batch's complete answer (FIX 12936).

use oneiron::task_verb::sdk::BrowserBatchOutput;
use serde_json::Value;

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<BrowserBatchOutput> for crate::BrowserAnswerBatchOutput {
    fn lift(mut value: BrowserBatchOutput) -> Result<Self, OneironError> {
        // Finish every opaque leaf before a finite conversion can return early.
        let decisions = std::mem::take(&mut value.answer.decisions)
            .into_iter()
            .map(WireJson::lift)
            .collect::<Vec<_>>();
        let image_release = value
            .session_manifest
            .as_mut()
            .and_then(|manifest| manifest.image_release.take());
        let image_release = match image_release {
            None | Some(Value::Null) => Ok(None),
            Some(release) => WireJson::lift(release).map(Some),
        };
        let decisions = decisions.into_iter().collect::<Result<Vec<_>, _>>()?;
        let image_release = image_release?;

        // Both opaque fields are now empty; retain the shared finite wire shape.
        let mut output: Self = lift_record("self.browser.batch", &value)?;
        output.flattened.decisions = if decisions.is_empty() {
            None
        } else {
            Some(decisions)
        };
        if let Some(manifest) = &mut output.session_manifest {
            manifest.image_release = image_release;
        }
        Ok(output)
    }
}
