//! The owner workbench reads' wire types (FIX 6869, G4 PR2): a served code
//! repository with its stored links, one durable revision fork, and one
//! received ref with its candidate. Requests name stored ids only; answers
//! carry ids, Git commits and digests, never a host path, credential or
//! command exhaust.
use serde::{Deserialize, Serialize};

use super::super::merge_queue_doors::MergeQueuePointersView;
use crate::EntityId;
use crate::code_document::{CodeDocumentFrontier, CodeFileMetadataEdit};
use crate::origin::{CodePushCandidateView, ReceivedFileOperation};
use crate::store::code_import_manifest::CodeImportAnchor;
use crate::store::code_tree_blob::CodeTreeBlob;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::origin_doors::workbench_types::{
    CodeForkGetRequest, CodePushIngressGetRequest, CodeRepoGetRequest,
};

#[doc(hidden)]
pub use oneiron_records::memory::origin_doors::workbench_types::{
    CodeForkDocumentView, CodeForkView, CodeIngressRef, CodePushIngressView, CodeRepoImportLink,
    CodeRepoView, CodeRunWorkFile, CodeRunWorkLink,
};
