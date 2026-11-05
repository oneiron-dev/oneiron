//! Whole-vault export manifest artifact types and stanza impls.
use std::fs;
use std::path::{Path, PathBuf};

use oneiron_base::error::Error;
use oneiron_base::error::Result;

pub const EXPORT_MANIFEST_ARTIFACT_NAME: &str = "manifest.json";

pub const EXPORT_MANIFEST_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ExportSecretsNulledManifest {
    pub payloads: bool,
    pub structural_placeholders: bool,
}

impl ExportSecretsNulledManifest {
    #[must_use]
    pub const fn from_redacted(redacted: bool) -> Self {
        Self {
            payloads: redacted,
            structural_placeholders: redacted,
        }
    }

    /// Declares STRUCTURAL placeholders without forcing payload nulling.
    ///
    /// [`Self::from_redacted`] couples the two flags because a redacted
    /// export means both. SECRET-04 (ONE-1922) needs exactly one of them:
    /// an export carrying secret-tainted build exhaust serializes that
    /// exhaust nulled with the structural placeholder, while the rest of
    /// the bundle's payloads are as clear as the caller asked for. Coupling
    /// them here would have quietly redacted a whole export because one
    /// artifact touched one secret.
    #[must_use]
    pub const fn with_structural_placeholders(self) -> Self {
        Self {
            payloads: self.payloads,
            structural_placeholders: true,
        }
    }

    #[must_use]
    pub const fn payloads(&self) -> bool {
        self.payloads
    }

    #[must_use]
    pub const fn structural_placeholders(&self) -> bool {
        self.structural_placeholders
    }
}
