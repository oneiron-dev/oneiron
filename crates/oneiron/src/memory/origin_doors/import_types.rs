//! `vault.code.import` wire types (FIX 6869, G4 PR1): the owner names a
//! served repo, its PROJECT, the admitted ref, the exact chosen commit and
//! the push publication that admitted it, and optionally accepts one exact
//! manifest over its checked Baseline. No host path, actor, argv, caller
//! tree or file list, pass Boolean or implicit HEAD is taken.
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::memory::codebase_doors::CodeSnapshotFile;
pub use crate::{
    code_revision::CodeImportAcceptance, store::code_import_manifest::CodeImportAnchor,
};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::origin_doors::import_types::{
    CodeImportManifestFile, CodeImportManifestView, CodeRepoImportRequest, CodeRepoImportState,
    CodeRepoImportView,
};
