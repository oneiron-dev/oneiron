//! A guest program's own error text, as the model reads it. An isolated
//! guest's text is masked on the host before it leaves the host (FIX 9209).

use super::source::{PreparedSource, split_guest_error};
use crate::store::known_value_index::{KnownSweep, RunKnownSource};
use crate::{Error, Result, Vault};

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
pub struct GuestProgramError(String);

