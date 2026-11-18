//! The tail guard of an adopted image, for the integration tests of row
//! CARRIER-PROOF-OLD-PARENTS (Astra review OP-01, 16 Nov): an image's build
//! needs a vault, and the guard reads only what an image carries.

use crate::HostingPrivacyPosture;
use crate::authority::AuthorityLogEntry;
use crate::error::Result;

/// Whether a fold past an image of the hand-signed `covered` rows, folded
/// under the hosted posture, leaves the `tail` rows to the whole log.
///
/// # Errors
///
/// A row that does not encode, or covered rows that leave no image.
pub fn tail_goes_to_the_whole_log(
    covered: &[AuthorityLogEntry],
    tail: &[AuthorityLogEntry],
) -> Result<bool> {
    crate::authority::tail_reaches_old_parents_past_rows_for_test(
        covered,
        tail,
        HostingPrivacyPosture::Hosted,
    )
}
