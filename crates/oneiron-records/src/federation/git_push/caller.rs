//! Moved from `crates/oneiron/src/federation/git_push/caller.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(crate) use oneiron_store::origin::git_ref_change::GitPushRefChange;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

/// Which arm admitted a push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitPushArm {
    Owner,
    Grant,
    Checkout,
}

impl GitPushArm {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Grant => "grant",
            Self::Checkout => "checkout",
        }
    }
}
