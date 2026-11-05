//! Core half of `git_wire::failure`: its store-layer items live in `oneiron_store::git_wire::failure` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::git_wire::failure::*;

use super::record::hex_lower;
use super::{GitWireOperation, GitWireProcessOutput};
use crate::error::{CodeError, Error, Result};

pub(super) fn classify_failure(output: &GitWireProcessOutput) -> GitWireFailure {
    let class = if output.timed_out {
        GitWireFailureClass::Timeout
    } else if output.truncated {
        GitWireFailureClass::OutputOverflow
    } else if output.exit_code.is_none() {
        GitWireFailureClass::Signalled
    } else {
        classify_diagnostics(&output.stderr)
    };
    GitWireFailure {
        class,
        exit_code: output.exit_code,
        diagnostics_digest: *blake3::hash(&output.stderr).as_bytes(),
        diagnostics_len: output.stderr.len(),
    }
}
