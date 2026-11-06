//! A guest program's own error text, as the model reads it. An isolated
//! guest's text is masked on the host before it leaves the host (FIX 9209).

use super::source::{PreparedSource, split_guest_error};
use crate::store::known_value_index::{KnownSweep, RunKnownSource};
use crate::{Error, Result, Vault};

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

/// Replaces each value a host knows in a guest program's error text with its
/// existing stand-in, before the text leaves the host (FIX 9209).
pub trait GuestErrorMask {
    /// `body` with each known value replaced by its stand-in.
    ///
    /// # Errors
    ///
    /// The host cannot read the values it knows.
    fn mask_known_values(&self, body: &str) -> Result<String>;
}

/// The vault's custody values, as its stream sweeps read them.
impl GuestErrorMask for Vault {
    fn mask_known_values(&self, body: &str) -> Result<String> {
        match self.known_source()? {
            Some(source) => swept(KnownSweep::new(source), body),
            None => Ok(body.to_owned()),
        }
    }
}

/// `body` with each custody and PERSON value of the run `source` reads
/// replaced, as the run's output sweep replaces them (FIX 9209).
pub(crate) fn mask_run_known_values(source: RunKnownSource, body: &str) -> Result<String> {
    swept(KnownSweep::for_run(source), body)
}

/// One whole pass of `sweep` over `body`: its frame, then its held tail.
fn swept(mut sweep: KnownSweep, body: &str) -> Result<String> {
    let mut masked = sweep.feed(body.as_bytes())?;
    masked.extend(sweep.tail()?);
    Ok(String::from_utf8_lossy(&masked).into_owned())
}

/// A failed isolated program's own error text, as its guest sent it, header
/// included (FIX 9209). It is not masked: it has no `Debug` and leaves only
/// through [`Self::into_error`].
pub(crate) struct GuestProgramError(String);

impl GuestProgramError {
    pub(crate) fn new(message: String) -> Self {
        Self(message)
    }

    /// The step's failure for the model. The header is split first, and its
    /// position is moved past the `prefix_lines` lines the host put before
    /// `prepared`'s program. Then the whole body is masked: `mask` replaces
    /// each known value, and the release shape sanitizer redacts a
    /// credential-shaped body. The existing cut and the TypeScript position
    /// come last. A mask that fails returns its own error, never the text.
    pub(crate) fn into_error(
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
