//! The step's streamed result in a shadow arm (PR-S1): each frame the
//! program writes goes into the arm's store, as a run's host writes it.

use super::super::store::ShadowBodyStore;
use crate::engine_executor::{JsCodeModeStepOutcome, JsCodeModeStream};
use crate::store::BodySink;
use crate::{Error, Result};

/// The step's streamed result, written into the arm's store frame by frame.
#[derive(Default)]
pub(crate) struct ArmStreams {
    console: Option<BodySink>,
    finish: Option<BodySink>,
    /// The value the program is passing to `store`, until the host takes it.
    pub(super) store: Option<BodySink>,
    files: Vec<(String, BodySink)>,
}

impl ArmStreams {
    /// Appends one frame to its target's body, as a run's host does: a
    /// finish frame that starts an answer drops the answer before it, and a
    /// store frame that starts a value drops any value no `store` took.
    pub(super) fn write(
        &mut self,
        store: &ShadowBodyStore,
        stream: JsCodeModeStream<'_>,
        frame: &[u8],
    ) -> Result<()> {
        let sink = match stream {
            JsCodeModeStream::Console => &mut self.console,
            JsCodeModeStream::Finish { start } => {
                if start {
                    self.finish = None;
                }
                &mut self.finish
            }
            JsCodeModeStream::Store { start } => {
                if start {
                    self.store = None;
                }
                &mut self.store
            }
            JsCodeModeStream::File(path) => {
                let at = match self.files.iter().position(|(held, _)| held == path) {
                    Some(at) => at,
                    None => {
                        self.files.push((path.to_owned(), store.sink()?));
                        self.files.len() - 1
                    }
                };
                return self.files[at].1.write(frame);
            }
        };
        if sink.is_none() {
            *sink = Some(store.sink()?);
        }
        match sink {
            Some(sink) => sink.write(frame),
            None => Err(Error::InvariantViolation("shadow arm stream sink missing")),
        }
    }

    /// The step's bodies once it ran: the answer of a finished step, else
    /// its console lines, a finished step's console lines beside it, and
    /// its files, with whatever the runtime returned in its outcome
    /// instead of streaming it.
    pub(crate) fn into_bodies(
        self,
        store: &ShadowBodyStore,
        outcome: &JsCodeModeStepOutcome,
    ) -> Result<(BodySink, Option<BodySink>, Vec<(String, BodySink)>)> {
        let (observation, mut console) = if outcome.done {
            (self.finish, self.console)
        } else {
            (self.console, None)
        };
        let mut observation = match observation {
            Some(sink) => sink,
            None => store.sink()?,
        };
        observation.write(outcome.observation.as_bytes())?;
        if console.is_none() && !outcome.console.is_empty() {
            let mut sink = store.sink()?;
            sink.write(outcome.console.as_bytes())?;
            console = Some(sink);
        }
        let mut files = self.files;
        for output in &outcome.outputs {
            let mut sink = store.sink()?;
            sink.write(&output.bytes)?;
            files.push((output.path.clone(), sink));
        }
        Ok((observation, console, files))
    }

    /// What a step that failed streamed before it failed: its console
    /// lines, else its answer so far, and its files, each kept partial.
    pub(crate) fn into_partial(self) -> (Option<BodySink>, Vec<(String, BodySink)>) {
        (self.console.or(self.finish), self.files)
    }
}
