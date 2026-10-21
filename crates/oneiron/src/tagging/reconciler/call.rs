//! The call (FIX 6755): a prepared marker's one tagger call, made on the
//! caller's thread by the synchronous drain, and the checks every answer
//! passes before its marker settles, whichever path brought it.

use super::claim::PreparedCall;
use super::coordinator::{PreparedTagging, TaggingReconciler};
use crate::error::{Error, Result};
use crate::memory::extraction::EncoderOutput;
use crate::tagging::output::check_output;
use crate::tagging::trace::TaggingFailure;

/// What a call came back with: its answer, or the panic that ended it.
pub(super) type Called = std::thread::Result<Result<EncoderOutput>>;

impl TaggingReconciler {
    /// Makes `prepared`'s one call on this thread, at its class, through the
    /// encoder's own `infer`, outside any write transaction, recording its
    /// wall time and the facts of the worker that ran it on its trace. A
    /// panic is caught and returned.
    pub(super) fn call(&self, prepared: &mut PreparedTagging) -> Called {
        let PreparedTagging { trace, call, .. } = prepared;
        trace.record_call(|| self.encoder.infer(&call.input, call.work))
    }

    /// What `called` gave, checked against `call`'s input and the stack its
    /// marker is owed to: the output that passed every check, or the failure
    /// its marker is retried on. A call that failed or panicked is a failed
    /// call; a refused answer is not.
    pub(super) fn checked(
        &self,
        call: &PreparedCall,
        called: Called,
    ) -> std::result::Result<EncoderOutput, TaggingFailure> {
        let output = match called {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                return Err(TaggingFailure::Call {
                    code: failure_code(&error),
                });
            }
            Err(_) => return Err(TaggingFailure::Panicked),
        };
        check_output(&call.input, &output, self.config.stack.as_deref())
            .map_err(|refusal| TaggingFailure::Refused { refusal })?;
        Ok(output)
    }
}

/// A host failure code is caller-safe by contract (the host builds it with no
/// vault text); every other error reports only its stable kind.
fn failure_code(error: &Error) -> String {
    match error {
        Error::UpstreamToolFailure { code, .. } => code.clone(),
        other => format!("{:?}", other.kind()),
    }
}
