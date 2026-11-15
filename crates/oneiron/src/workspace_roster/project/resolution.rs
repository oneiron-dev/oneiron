//! Signed envelopes over a project's history (decision 6, ruling F2): a board
//! resolution settles a fork among board-rank children, and the owner's seal
//! re-roots the fold at a fresh host-signed revision. Both are stored as
//! revisions and ride transport with the rows they name.
use super::revision::ProjectRevisionHash;
use super::*;

#[doc(hidden)]
pub use oneiron_records::workspace_roster::project::resolution::{ProjectResolution, ProjectSeal};
#[doc(hidden)]
use oneiron_records::workspace_roster::project::resolution::{
    RESOLUTION_DOMAIN, SEAL_DOMAIN, challenge,
};
