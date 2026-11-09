//! Lifted half of `oneiron::code_sandbox::guest_error` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::guest_error::*;
#[allow(unused_imports)]
use crate::ext::*;
use super::source::PreparedSource;
use super::source::split_guest_error;
use crate::Error;
use crate::Result;

/// Characters of a guest's error text a failed step keeps. A program can
/// throw text of any size; its head says why.
const GUEST_ERROR_CHARS: usize = 2048;

/// The guest's own error text for a failed step, so the model learns why its
/// program stopped. The guest's position header never reaches it; a
/// TypeScript program's error ends with where it threw in the TypeScript
/// source, past the text's cut, and a JavaScript program's is as it was.
#[cfg(feature = "code-sandbox-wasmtime")]
pub(crate) fn guest_failure(message: &str, prepared: &PreparedSource<'_>) -> Error {
    let (message, at) = split_guest_error(message);
    step_failure(message, prepared.failure_position(at))
}

/// The step's failure: the text's head, its size when cut, then `position`.
fn step_failure(message: &str, position: Option<String>) -> Error {
    let mut text: String = message.chars().take(GUEST_ERROR_CHARS).collect();
    if text.len() < message.len() {
        text.push_str(&format!(" … ({} bytes in all)", message.len()));
    }
    if let Some(position) = position {
        text.push_str(&position);
    }
    Error::InvalidConfig(format!("guest reported step failure: {text}"))
}

/// Methods of [`GuestProgramError`] that moved out of `oneiron` with `code_sandbox::guest_error` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxGuestErrorGuestProgramErrorExt {
    fn new(message: String) -> Self;
    /// The step's failure for the model. The header is split first, and its
    /// position is moved past the `prefix_lines` lines the host put before
    /// `prepared`'s program. Then the whole body is masked: `mask` replaces
    /// each known value, and the release shape sanitizer redacts a
    /// credential-shaped body. The existing cut and the TypeScript position
    /// come last. A mask that fails returns its own error, never the text.
    fn into_error(
        self,
        prepared: &PreparedSource<'_>,
        prefix_lines: u32,
        mask: impl FnOnce(&str) -> Result<String>,
    ) -> Error;
}

impl CodeSandboxGuestErrorGuestProgramErrorExt for GuestProgramError {
    fn new(message: String) -> Self {
            Self(message)
        }

    /// The step's failure for the model. The header is split first, and its
    /// position is moved past the `prefix_lines` lines the host put before
    /// `prepared`'s program. Then the whole body is masked: `mask` replaces
    /// each known value, and the release shape sanitizer redacts a
    /// credential-shaped body. The existing cut and the TypeScript position
    /// come last. A mask that fails returns its own error, never the text.
    fn into_error(
            self,
            prepared: &PreparedSource<'_>,
            prefix_lines: u32,
            mask: impl FnOnce(&str) -> Result<String>,
        ) -> Error {
            let (body, at) = split_guest_error(&self.0);
            let at = at.and_then(|at| at.after_prefix(prefix_lines));
            let masked = match mask(body) {
                Ok(masked) => masked,
                Err(error) => return error,
            };
            let mut body = serde_json::Value::String(masked);
            crate::batch::secret_scan::sanitize_credentials(&mut body, false);
            step_failure(
                body.as_str().unwrap_or_default(),
                prepared.failure_position(at),
            )
        }
}
