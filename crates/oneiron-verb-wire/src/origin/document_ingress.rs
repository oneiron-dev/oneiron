//! Moved from `crates/oneiron/src/origin/document_ingress.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::origin::document_candidate_types::ReceivedRefSource;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;
use oneiron_store::code_document_values::CodeFileEdit;
use oneiron_store::code_snapshot::ids::entity_id_from_hash_material;
use oneiron_store::git_wire::repo::GitWireRepo;
use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
use oneiron_store::scan_kind::EngineScan;
use oneiron_store::side_table::key::SideKey;
use oneiron_store::write_envelope::WriteActor;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;

/// One push operation, including non-text blobs and mode-only changes.
/// Git objects remain pinned by the hash-keyed origin change claim.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ReceivedFileOperation {
    pub operation_id: String,
    /// The pusher's hex id, or [`ERASED_CALL_IDENTITY`] once that actor was
    /// erased (FIX 4475).
    pub actor_id: String,
    pub session_id: String,
    pub ref_name: String,
    pub path: String,
    pub before_hash: [u8; 32],
    pub after_hash: [u8; 32],
    pub old_mode: Option<u32>,
    pub new_mode: Option<u32>,
    pub document_edit: bool,
}
