//! The typed unavailable a read of erased reply content answers with. The
//! code run layer (`code_run`) raises it on replay and wait delivery; the
//! store's opaque-response reader raises it on an erased marker.
use oneiron_base::error::{CodeError, Error};

/// The typed unavailable a run's read of reply content an erase of its actor
/// took answers with (FIX 5718; `ErrorKind::ResponseErased`): a replayed
/// call's, a wait's delivered or settled reply, a consent wait's resume.
/// `what` names the read. Nothing is sent again.
pub fn response_erased_error(what: &'static str) -> Error {
    Error::Code(CodeError::ResponseErased(what))
}
