use crate::error::{ArtifactError, Error};

pub(crate) fn invalid(message: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(message))
}
