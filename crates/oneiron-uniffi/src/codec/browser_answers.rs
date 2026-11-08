//! Owned JSON in browser-answer manifests and nested library batches.

use oneiron::task_verb::sdk;
use serde_json::Value;

use super::{Lift, OneironError, WireJson, lift_record};

pub(super) fn lift_image_release(value: Option<Value>) -> Result<Option<WireJson>, OneironError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => WireJson::lift(value).map(Some),
    }
}

pub(super) fn lift_decisions(values: Vec<Value>) -> Result<Option<Vec<WireJson>>, OneironError> {
    let converted = values.into_iter().map(WireJson::lift).collect::<Vec<_>>();
    let converted = converted.into_iter().collect::<Result<Vec<_>, _>>()?;
    Ok(if converted.is_empty() {
        None
    } else {
        Some(converted)
    })
}

// These payloads are finite; only their shared manifest contains opaque JSON.
macro_rules! finite_browser_answers {
    ($($source:ident => $target:ident),+ $(,)?) => {
        $(
            impl Lift<sdk::$source> for crate::$target {
                fn lift(mut value: sdk::$source) -> Result<Self, OneironError> {
                    let image_release = lift_image_release(value.session_manifest.as_mut()
                        .and_then(|manifest| manifest.image_release.take()))?;
                    let mut output: Self = lift_record(stringify!($source), &value)?;
                    if let Some(manifest) = &mut output.session_manifest {
                        manifest.image_release = image_release;
                    }
                    Ok(output)
                }
            }
        )+
    };
}

finite_browser_answers! {
    BrowserObservationPage => BrowserAnswerObservationPage,
    BrowserImageOutput => BrowserAnswerImageOutput,
    BrowserFindOutput => BrowserAnswerFindOutput,
    BrowserWaitForOutput => BrowserAnswerWaitForOutput,
    BrowserExpectOutput => BrowserAnswerExpectOutput,
    BrowserScreenshotOutput => BrowserAnswerScreenshotOutput,
    BrowserLibraryFindOutput => BrowserAnswerLibraryFindOutput,
    BrowserLibraryDraftOutput => BrowserAnswerDraftOutput,
    BrowserDemonstrationStartOutput => BrowserAnswerDemonstrationStarted,
    BrowserDemonstrationStopOutput => BrowserAnswerDemonstrationOutput,
    BrowserLibraryRetireOutput => BrowserAnswerLibraryRetireOutput,
    BrowserLibraryRetiredOutput => BrowserAnswerLibraryRetiredOutput,
    BrowserHandoverOutput => BrowserAnswerHandoverOutput,
    BrowserSwitchEngineOutput => BrowserAnswerSwitchEngineOutput,
}

impl Lift<sdk::BrowserLibraryProposeOutput> for crate::BrowserAnswerProposeOutput {
    fn lift(mut value: sdk::BrowserLibraryProposeOutput) -> Result<Self, OneironError> {
        let decisions = lift_decisions(
            value
                .answer
                .replay
                .as_mut()
                .map_or_else(Vec::new, |replay| std::mem::take(&mut replay.decisions)),
        );
        let image_release = lift_image_release(
            value
                .session_manifest
                .as_mut()
                .and_then(|manifest| manifest.image_release.take()),
        );
        let decisions = decisions?;
        let image_release = image_release?;
        let mut output: Self = lift_record("self.browser.library.propose", &value)?;
        if let Some(replay) = &mut output.flattened.replay {
            replay.decisions = decisions;
        }
        if let Some(manifest) = &mut output.session_manifest {
            manifest.image_release = image_release;
        }
        Ok(output)
    }
}

impl Lift<sdk::BrowserLibraryRunOutput> for crate::BrowserAnswerLibraryRunOutput {
    fn lift(mut value: sdk::BrowserLibraryRunOutput) -> Result<Self, OneironError> {
        let decisions = lift_decisions(std::mem::take(&mut value.answer.batch.decisions));
        let image_release = lift_image_release(
            value
                .session_manifest
                .as_mut()
                .and_then(|manifest| manifest.image_release.take()),
        );
        let decisions = decisions?;
        let image_release = image_release?;
        let mut output: Self = lift_record("self.browser.library.run", &value)?;
        output.flattened.batch.decisions = decisions;
        if let Some(manifest) = &mut output.session_manifest {
            manifest.image_release = image_release;
        }
        Ok(output)
    }
}
