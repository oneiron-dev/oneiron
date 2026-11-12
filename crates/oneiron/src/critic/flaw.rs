//! A critique's checkable flaw identity (LEARN-CRITIC Q1 = B): what kind of
//! flaw it names and where in the reviewed target that flaw sits. Critiques
//! of one target that name one identity are one finding; nothing else merges
//! them.
use serde::{Deserialize, Serialize};

/// The most bytes of a flaw kind.
pub const MAX_FLAW_KIND_BYTES: usize = 64;

/// What the flaw is and where it sits in the target its review read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlawIdentity {
    /// The kind of flaw, a token of ASCII lowercase letters, digits and
    /// underscores that starts with a letter, at most [`MAX_FLAW_KIND_BYTES`]:
    /// never its severity, lens or model.
    pub kind: String,
    pub location: FlawLocation,
}

/// Where the flaw sits in the target as its review read it. A byte range
/// counts in the body text of the review's state: the body's JSON text when
/// the state holds it whole, the cut text when the state holds a cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FlawLocation {
    /// The whole target.
    WholeTarget,
    /// The bytes `start..end` of the body text, on character boundaries.
    BodyBytes { start: u64, end: u64 },
}
