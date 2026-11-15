//! Moved from `crates/oneiron/src/repo_mutation/oplog.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(super) use oneiron_store::git_wire::mutation_commands::repo_mutation_repo_key;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;

pub const REPO_MUTATION_OPLOG_SCHEMA_VERSION: u8 = 1;
