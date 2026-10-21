//! Which licences let a model download start (the owner's standing grant:
//! any licence that does not hurt us, never non-commercial weights).
//!
//! A manifest names its licence by the id its model card declares and pins
//! the licence file itself, so the exact text and notices sit beside the
//! weights at each revision (DESIGN-V2 R0), not only the card's badge. The
//! class comes from [`LICENCE_CLASSES`] alone, never from the manifest: an
//! operator's manifest cannot call its own licence permissive. A licence
//! entry is a design input, not legal advice.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::ArtifactError;
use super::manifest::ArtifactManifest;

/// How a licence id is treated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LicenceClass {
    /// Commercial use and redistribution with notices: admitted.
    Permissive,
    /// Usable on terms that need an individual decision: admitted only with
    /// the manifest naming that decision.
    Conditional,
    /// Never shipped.
    NonCommercial,
    /// Not in [`LICENCE_CLASSES`]: never shipped until a ruling classifies
    /// it.
    Unknown,
}

impl LicenceClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Permissive => "permissive",
            Self::Conditional => "conditional",
            Self::NonCommercial => "non-commercial",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for LicenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every licence id this build classifies, as Hugging Face model cards
/// declare them (`license:`), compared without ASCII case. An id not here is
/// [`LicenceClass::Unknown`], so the card's catch-all `other` is too. A
/// later ruling changes one row.
const LICENCE_CLASSES: &[(&str, LicenceClass)] = &[
    ("apache-2.0", LicenceClass::Permissive),
    ("mit", LicenceClass::Permissive),
    ("bsd-2-clause", LicenceClass::Permissive),
    ("bsd-3-clause", LicenceClass::Permissive),
    ("isc", LicenceClass::Permissive),
    ("cc0-1.0", LicenceClass::Permissive),
    ("cc-by-4.0", LicenceClass::Permissive),
    ("unlicense", LicenceClass::Permissive),
    ("openrail", LicenceClass::Conditional),
    ("openrail++", LicenceClass::Conditional),
    ("creativeml-openrail-m", LicenceClass::Conditional),
    ("bigscience-openrail-m", LicenceClass::Conditional),
    ("llama2", LicenceClass::Conditional),
    ("llama3", LicenceClass::Conditional),
    ("llama3.1", LicenceClass::Conditional),
    ("llama3.2", LicenceClass::Conditional),
    ("llama3.3", LicenceClass::Conditional),
    ("llama4", LicenceClass::Conditional),
    ("gemma", LicenceClass::Conditional),
    ("cc-by-sa-4.0", LicenceClass::Conditional),
    ("mpl-2.0", LicenceClass::Conditional),
    ("lgpl-3.0", LicenceClass::Conditional),
    ("gpl-3.0", LicenceClass::Conditional),
    ("agpl-3.0", LicenceClass::Conditional),
    ("cc-by-nc-2.0", LicenceClass::NonCommercial),
    ("cc-by-nc-3.0", LicenceClass::NonCommercial),
    ("cc-by-nc-4.0", LicenceClass::NonCommercial),
    ("cc-by-nc-nd-3.0", LicenceClass::NonCommercial),
    ("cc-by-nc-nd-4.0", LicenceClass::NonCommercial),
    ("cc-by-nc-sa-2.0", LicenceClass::NonCommercial),
    ("cc-by-nc-sa-3.0", LicenceClass::NonCommercial),
    ("cc-by-nc-sa-4.0", LicenceClass::NonCommercial),
];

/// The class of a licence id; [`LicenceClass::Unknown`] when the table does
/// not name it.
pub(crate) fn classify(id: &str) -> LicenceClass {
    let id = id.trim();
    LICENCE_CLASSES
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(id))
        .map_or(LicenceClass::Unknown, |(_, class)| *class)
}

/// A manifest's licence: what the card declares, the pinned file that
/// carries it, and the decision that admits a conditional one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LicenceTerms {
    /// The licence id as the model card declares it, e.g. `apache-2.0`.
    pub(crate) id: Cow<'static, str>,
    /// The pinned file holding the licence text, or the card that declares
    /// it when the repository has no licence file. One of the manifest's
    /// files, so its exact bytes are installed with the weights.
    pub(crate) file: Cow<'static, str>,
    /// For a conditional licence, the owner decision that admits this model
    /// (a ruling or FIX reference). Read for no other class.
    #[serde(default)]
    pub(crate) decision: Option<Cow<'static, str>>,
}

impl LicenceTerms {
    pub(crate) fn class(&self) -> LicenceClass {
        classify(&self.id)
    }
}

/// Whether a manifest's licence lets its download start: the one policy.
///
/// Permissive is admitted. Conditional is admitted only when the manifest
/// names the decision that admits it. Non-commercial and unknown are refused
/// before any byte is fetched, naming the model and the licence; no decision
/// admits them. Returns the class admitted.
pub(crate) fn admit_download(manifest: &ArtifactManifest) -> Result<LicenceClass, ArtifactError> {
    let terms = &manifest.licence;
    let class = terms.class();
    let decided = terms
        .decision
        .as_deref()
        .is_some_and(|decision| !decision.trim().is_empty());
    match class {
        LicenceClass::Permissive => Ok(class),
        LicenceClass::Conditional if decided => Ok(class),
        LicenceClass::Conditional => Err(ArtifactError::LicenceUndecided {
            model: manifest.id.to_string(),
            licence: terms.id.to_string(),
        }),
        LicenceClass::NonCommercial | LicenceClass::Unknown => Err(ArtifactError::LicenceRefused {
            model: manifest.id.to_string(),
            licence: terms.id.to_string(),
            class,
        }),
    }
}
