//! Lifted half of `oneiron::code_sandbox::microvm::output` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::microvm::output::*;
#[allow(unused_imports)]
use crate::ext::*;
use std::sync::Arc;
use crate::Result;
use crate::code_sandbox::ProposalSpoolFloor;
use crate::code_sandbox::SandboxProposalBody;
use crate::code_sandbox::SandboxProposalBodyWriter;

/// The selected observation and output files, retaining their admitted spools.
pub struct MicroVmOutputBodies {
    pub observation: Option<SandboxProposalBody>,
    pub files: Vec<(String, SandboxProposalBody)>,
}

/// Methods of [`MicroVmOutputSpool`] that moved out of `oneiron` with `code_sandbox::microvm::output` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxMicrovmOutputMicroVmOutputSpoolExt {
    fn new(floor: Arc<dyn ProposalSpoolFloor>) -> Self;
    /// Selects finish for a completed step, otherwise console, as the executor does.
    /// Untaken store frames and the unselected text are dropped without a second read.
    fn into_step_bodies(self, done: bool) -> Result<MicroVmOutputBodies>;
}

impl CodeSandboxMicrovmOutputMicroVmOutputSpoolExt for MicroVmOutputSpool {
    fn new(floor: Arc<dyn ProposalSpoolFloor>) -> Self {
            Self {
                floor,
                console: None,
                finish: None,
                store: None,
                files: Vec::new(),
            }
        }

    /// Selects finish for a completed step, otherwise console, as the executor does.
    /// Untaken store frames and the unselected text are dropped without a second read.
    fn into_step_bodies(self, done: bool) -> Result<MicroVmOutputBodies> {
            let text = if done { self.finish } else { self.console };
            let observation = text.map(SandboxProposalBodyWriter::finish).transpose()?;
            let mut files = Vec::with_capacity(self.files.len());
            for (path, writer) in self.files {
                files.push((path, writer.finish()?));
            }
            Ok(MicroVmOutputBodies { observation, files })
        }
}
