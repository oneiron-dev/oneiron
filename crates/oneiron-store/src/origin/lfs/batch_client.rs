//! The outbound Git-LFS batch client: one https remote's batch API
//! (`<remote>.git/info/lfs/objects/batch`) and its basic transfer. A
//! mirror's objects go up, an upload and its verify call per object the
//! remote does not hold yet (FIX 919); an outside import's come down, each
//! installed through the vault-LFS upload door, its scan, SHA-256 and size
//! checks included (FIX 7596).
//!
//! https only, no redirects, no proxy. The one credential is the
//! `Authorization` value the caller hands it inside the custody door; it
//! rides the batch call to the remote's own host alone, and each action's
//! own headers ride that action's request alone. An object is streamed,
//! never held whole in memory. A batch carries at most
//! [`LFS_BATCH_OBJECTS`] objects, more go in further batches, so no count
//! is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::origin::lfs::oid::LfsOid;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::temporal::TimeRange;

/// Objects one batch call names: the size Git-LFS servers commonly take.
pub const LFS_BATCH_OBJECTS: usize = 100;

/// The bound of one batch answer read into memory.
pub const LFS_BATCH_ANSWER_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// How long one batch or verify call may take.
pub const LFS_BATCH_TIMEOUT: Duration = Duration::from_secs(60);

/// How long one object's transfer may take.
pub const LFS_TRANSFER_TIMEOUT: Duration = Duration::from_secs(60 * 60);

pub fn invalid(why: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidLfsObject(why))
}

#[derive(Serialize)]
pub struct BatchRequest<'a> {
    pub operation: &'a str,
    pub transfers: [&'a str; 1],
    pub objects: Vec<BatchObjectRef>,
    pub hash_algo: &'a str,
}

#[derive(Serialize)]
pub struct BatchObjectRef {
    pub oid: String,
    pub size: u64,
}

#[derive(Deserialize)]
pub struct BatchAnswer {
    pub objects: Vec<BatchObject>,
}

#[derive(Deserialize)]
struct BatchObject {
    pub oid: String,
    #[serde(default)]
    pub actions: Option<BatchActions>,
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct BatchActions {
    #[serde(default)]
    pub upload: Option<BatchAction>,
    #[serde(default)]
    pub verify: Option<BatchAction>,
    #[serde(default)]
    pub download: Option<BatchAction>,
}

#[derive(Deserialize)]
pub struct BatchAction {
    pub href: String,
    #[serde(default)]
    pub header: BTreeMap<String, String>,
}

