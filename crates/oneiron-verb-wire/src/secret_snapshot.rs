//! Moved from `crates/oneiron/src/secret_snapshot.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::batch::secret_scan;
use heed::RoTxn;
use oneiron_base::error::CodeError;
use oneiron_base::error::Error;
use oneiron_base::error::GateError;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_SECRET_CUSTODY;
use oneiron_store::code_snapshot::repo_ref::RepoRef;
use oneiron_store::code_snapshot::snapshot::CodebaseFileEntry;
use oneiron_store::code_snapshot::snapshot::CodebaseSnapshot;
use oneiron_store::side_table::codec::CodecError;
use oneiron_store::side_table::codec::RawValue;
use oneiron_store::side_table::key::HexId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// A value-free proposal to move a detected file secret into the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotSecretLiftProposal {
    pub path: String,
    pub detector_reason: String,
    pub suggested_secret_name: String,
    pub project_id: String,
}
