//! The taint of the values a shadow arm stores, and how its own results
//! leave the arm (FIX 3607): a result that reads tainted inside the arm
//! leaves withheld, whether the secret scan marked its bytes or it inherits
//! a custody taint from the results it was made from. No export, adoption
//! or scoring reads it as clean.

use super::Taint;
use crate::secret_rotation::ArtifactTaintState;

/// The mark a result the arm stored leaves with when it reads tainted but
/// the secret scan named no reason: its taint came from the custody of a
/// result it was made from.
const INHERITED_TAINT: &str = "tainted";

/// The taint a value the arm stored reads under: the secret scan's mark on
/// its own bytes, else the first taint among the results it was made from.
pub(super) fn stored_taint(secret: Option<&'static str>, inherit: &[Taint]) -> Taint {
    if let Some(reason) = secret {
        return (ArtifactTaintState::TaintedLive, Some(reason.to_owned()));
    }
    inherit
        .iter()
        .find(|(state, _)| state.is_tainted())
        .cloned()
        .unwrap_or((ArtifactTaintState::Clean, None))
}

/// The withholding mark one of the arm's own results leaves with: the
/// secret scan's reason when it named one, else [`INHERITED_TAINT`] for a
/// result that reads tainted, else none. A marked body is never read whole,
/// adopted or scored.
pub(super) fn exported_mark(state: ArtifactTaintState, secret: Option<&str>) -> Option<&str> {
    secret.or_else(|| state.is_tainted().then_some(INHERITED_TAINT))
}
