//! A critique's checkable flaw identity (LEARN-CRITIC Q1 = B): what kind of
//! flaw it names and where in the reviewed target that flaw sits. Critiques
//! of one target that name one identity are one finding; nothing else merges
//! them.

/// The most bytes of a flaw kind.
pub const MAX_FLAW_KIND_BYTES: usize = 64;

#[doc(hidden)]
pub use oneiron_records::critic::flaw::{FlawIdentity, FlawLocation};
