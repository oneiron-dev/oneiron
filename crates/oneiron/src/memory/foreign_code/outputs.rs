//! Materialization at the existing public foreign-code owned-return boundary.

use super::{ForeignCodeOutput, StepOutput};
use crate::code_sandbox::SandboxProposalBody;
use crate::code_sandbox::microvm::MicroVmOutputSpool;
use crate::{Error, Result};

pub(super) fn merge(streamed: MicroVmOutputSpool, output: &mut StepOutput) -> Result<()> {
    let bodies = streamed.into_step_bodies(output.done)?;
    if output.observation.is_empty() {
        if let Some(body) = bodies.observation {
            output.observation = String::from_utf8(bytes(body)?)
                .map_err(|_| Error::InvalidConfig("streamed observation is not UTF-8".into()))?;
        }
    }
    for (path, body) in bodies.files {
        output.outputs.push(ForeignCodeOutput {
            path,
            bytes: bytes(body)?,
        });
    }
    Ok(())
}

fn bytes(body: SandboxProposalBody) -> Result<Vec<u8>> {
    let len = usize::try_from(body.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            "foreign output exceeds host address space",
        )
    })?;
    body.read_range(0, len)
}
