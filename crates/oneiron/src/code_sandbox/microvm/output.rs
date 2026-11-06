//! Caller-owned destinations for an isolated step's streamed output.

use std::sync::Arc;

use crate::Result;
use crate::code_sandbox::{ProposalSpoolFloor, SandboxProposalBody, SandboxProposalBodyWriter};
use crate::engine_executor::JsCodeModeStream;

/// Accepts the complete frame before the guest receives its stored-byte receipt.
/// The exchange calls this on its caller's thread; the sink may borrow its host.
pub trait MicroVmOutputSink {
    fn write_output_frame(&mut self, stream: JsCodeModeStream<'_>, frame: Vec<u8>) -> Result<()>;
}

impl<F> MicroVmOutputSink for F
where
    F: FnMut(JsCodeModeStream<'_>, Vec<u8>) -> Result<()>,
{
    fn write_output_frame(&mut self, stream: JsCodeModeStream<'_>, frame: Vec<u8>) -> Result<()> {
        self(stream, frame)
    }
}

/// Output for a caller with no executor body store, on its actual shared disk floor.
pub struct MicroVmOutputSpool {
    floor: Arc<dyn ProposalSpoolFloor>,
    console: Option<SandboxProposalBodyWriter>,
    finish: Option<SandboxProposalBodyWriter>,
    store: Option<SandboxProposalBodyWriter>,
    files: Vec<(String, SandboxProposalBodyWriter)>,
}

/// The selected observation and output files, retaining their admitted spools.
pub struct MicroVmOutputBodies {
    pub observation: Option<SandboxProposalBody>,
    pub files: Vec<(String, SandboxProposalBody)>,
}

/// Every stream role, retained without choosing a step observation.
#[derive(Debug)]
pub struct MicroVmOutputStreamBodies {
    pub console: Option<SandboxProposalBody>,
    pub finish: Option<SandboxProposalBody>,
    pub store: Option<SandboxProposalBody>,
    pub files: Vec<(String, SandboxProposalBody)>,
}

impl MicroVmOutputSpool {
    pub fn new(floor: Arc<dyn ProposalSpoolFloor>) -> Self {
        Self {
            floor,
            console: None,
            finish: None,
            store: None,
            files: Vec::new(),
        }
    }

    /// Retains each role as received when the caller's result is not a selected observation.
    pub fn into_stream_bodies(self) -> Result<MicroVmOutputStreamBodies> {
        Ok(MicroVmOutputStreamBodies {
            console: self
                .console
                .map(SandboxProposalBodyWriter::finish)
                .transpose()?,
            finish: self
                .finish
                .map(SandboxProposalBodyWriter::finish)
                .transpose()?,
            store: self
                .store
                .map(SandboxProposalBodyWriter::finish)
                .transpose()?,
            files: self
                .files
                .into_iter()
                .map(|(path, writer)| Ok((path, writer.finish()?)))
                .collect::<Result<_>>()?,
        })
    }

    /// Selects finish for a completed step, otherwise console, as the executor does.
    /// Untaken store frames and the unselected text are dropped without a second read.
    pub fn into_step_bodies(self, done: bool) -> Result<MicroVmOutputBodies> {
        let text = if done { self.finish } else { self.console };
        let observation = text.map(SandboxProposalBodyWriter::finish).transpose()?;
        let mut files = Vec::with_capacity(self.files.len());
        for (path, writer) in self.files {
            files.push((path, writer.finish()?));
        }
        Ok(MicroVmOutputBodies { observation, files })
    }
}

impl MicroVmOutputSink for MicroVmOutputSpool {
    fn write_output_frame(&mut self, stream: JsCodeModeStream<'_>, frame: Vec<u8>) -> Result<()> {
        let slot = match stream {
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
                let index = match self.files.iter().position(|(name, _)| name == path) {
                    Some(index) => index,
                    None => {
                        let body = SandboxProposalBody::spool_floored(self.floor.as_ref())?;
                        self.files.push((path.to_owned(), body));
                        self.files.len() - 1
                    }
                };
                return self.files[index].1.append(&frame);
            }
        };
        if slot.is_none() {
            *slot = Some(SandboxProposalBody::spool_floored(self.floor.as_ref())?);
        }
        slot.as_mut()
            .expect("output spool opened above")
            .append(&frame)
    }
}
