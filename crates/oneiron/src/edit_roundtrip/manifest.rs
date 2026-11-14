//! Edit manifest and warnings.

use super::{AnchorEffect, EditOp, OfficeFormat};
use crate::error::{ArtifactError, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[doc(hidden)]
pub use oneiron_records::edit_roundtrip::manifest::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditWarning, MutationMode, WarningCode,
};
